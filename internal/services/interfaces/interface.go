package interfaces

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfos"
)

var (
	interfaceTypes  = []string{"vlan", "bridge", "lag"}
	lagModes        = []string{"activeBackup", "lacp8023ad"}
	lagLoadBalances = []string{"layer2", "layer2And3", "layer3And4"}
)

type interfaceModel struct {
	ID           types.String `tfsdk:"id"`
	Name         types.String `tfsdk:"name"`
	HardwareName types.String `tfsdk:"hardware_name"`
	Type         types.String `tfsdk:"type"`
	Description  types.String `tfsdk:"description"`
	Zone         types.String `tfsdk:"zone"`
	VLAN         *vlanModel   `tfsdk:"vlan"`
	Bridge       *bridgeModel `tfsdk:"bridge"`
	LAG          *lagModel    `tfsdk:"lag"`
	IPv4         *ipModel     `tfsdk:"ipv4"`
	IPv6         *ipModel     `tfsdk:"ipv6"`
	MTU          types.Int64  `tfsdk:"mtu"`
	MSS          types.Int64  `tfsdk:"mss"`
}

type vlanModel struct {
	ParentInterface types.String `tfsdk:"parent_interface"`
	VLANID          types.Int64  `tfsdk:"vlan_id"`
}

type bridgeMemberModel struct {
	Interface types.String `tfsdk:"interface"`
	Zone      types.String `tfsdk:"zone"`
}

type bridgeModel struct {
	Members              []bridgeMemberModel `tfsdk:"members"`
	Routing              types.Bool          `tfsdk:"routing"`
	FilterVLANs          types.Bool          `tfsdk:"filter_vlans"`
	PermitARPBroadcast   types.Bool          `tfsdk:"permit_arp_broadcast"`
	STP                  types.Bool          `tfsdk:"stp"`
	STPMaxAge            types.Int64         `tfsdk:"stp_max_age"`
	MACAging             types.Int64         `tfsdk:"mac_aging"`
	FilterEthernetFrames types.Bool          `tfsdk:"filter_ethernet_frames"`
}

type lagModel struct {
	Members           types.Set    `tfsdk:"members"`
	Mode              types.String `tfsdk:"mode"`
	LoadBalanceMethod types.String `tfsdk:"load_balance_method"`
	PrimaryInterface  types.String `tfsdk:"primary_interface"`
}

// Interface manages VLAN, bridge and LAG interfaces.
var Interface = &framework.Resource[interfaceModel, networkInterface]{
	Name:       "interface",
	Title:      "network interface",
	Path:       interfacesPath,
	Schema:     interfaceSchema(),
	CreateOnly: []string{"type", "hardwareName", "vlanDetails"},
	Validate:   validateInterface,
	Expand: func(ctx context.Context, m *interfaceModel, diags *diag.Diagnostics) *networkInterface {
		ni := &networkInterface{
			Name:         m.Name.ValueString(),
			HardwareName: m.HardwareName.ValueString(),
			Type:         m.Type.ValueString(),
			Description:  framework.StringPtr(m.Description),
			Zone:         framework.Ref(m.Zone),
			IPv4:         expandIP(4, m.IPv4, diags),
			IPv6:         expandIP(6, m.IPv6, diags),
			MTU:          framework.Int64Ptr(m.MTU),
			MSS:          framework.Int64Ptr(m.MSS),
		}
		if m.HardwareName.IsUnknown() {
			ni.HardwareName = ""
		}
		if v := m.VLAN; v != nil {
			ni.VLANDetails = &vlanDetails{VLANID: v.VLANID.ValueInt64(), ParentInterface: sfos.NameRef{Name: v.ParentInterface.ValueString()}}
		}
		if b := m.Bridge; b != nil {
			members := make([]bridgeMember, 0, len(b.Members))
			for _, mem := range b.Members {
				members = append(members, bridgeMember{Interface: sfos.NameRef{Name: mem.Interface.ValueString()}, Zone: sfos.NameRef{Name: mem.Zone.ValueString()}})
			}
			ni.BridgeDetails = &bridgeDetails{
				Members:              members,
				Routing:              framework.BoolPtr(b.Routing),
				FilterVLANs:          framework.BoolPtr(b.FilterVLANs),
				PermitARPBroadcast:   framework.BoolPtr(b.PermitARPBroadcast),
				STP:                  framework.BoolPtr(b.STP),
				STPMaxAge:            framework.Int64Ptr(b.STPMaxAge),
				MACAging:             framework.Int64Ptr(b.MACAging),
				FilterEthernetFrames: framework.BoolPtr(b.FilterEthernetFrames),
			}
		}
		if l := m.LAG; l != nil {
			var members []lagMember
			for _, n := range framework.Strings(ctx, l.Members, diags) {
				members = append(members, lagMember{Interface: sfos.NameRef{Name: n}})
			}
			ni.LAGDetails = &lagDetails{
				Members:           members,
				Mode:              l.Mode.ValueString(),
				LoadBalanceMethod: framework.StringPtr(l.LoadBalanceMethod),
				PrimaryInterface:  framework.Ref(l.PrimaryInterface),
			}
		}
		return ni
	},
	Flatten: func(ctx context.Context, a *networkInterface, prior *interfaceModel, diags *diag.Diagnostics) *interfaceModel {
		m := &interfaceModel{
			ID:           types.StringValue(a.ID),
			Name:         types.StringValue(a.Name),
			HardwareName: types.StringValue(a.HardwareName),
			Type:         types.StringValue(a.Type),
			Description:  framework.NonEmpty(deref(a.Description)),
			Zone:         framework.RefName(a.Zone),
			MTU:          types.Int64PointerValue(a.MTU),
			MSS:          types.Int64PointerValue(a.MSS),
		}
		if framework.Managed(prior, func(p *interfaceModel) bool { return p.IPv4 != nil }) {
			m.IPv4 = flattenIP(4, a.IPv4)
		}
		if framework.Managed(prior, func(p *interfaceModel) bool { return p.IPv6 != nil }) {
			m.IPv6 = flattenIP(6, a.IPv6)
		}
		// Unmanaged zone: keep it out of state so it is not reported as drift.
		if prior != nil && prior.Zone.IsNull() {
			m.Zone = types.StringNull()
		}
		if v := a.VLANDetails; v != nil && a.Type == "vlan" {
			m.VLAN = &vlanModel{ParentInterface: types.StringValue(v.ParentInterface.Name), VLANID: types.Int64Value(v.VLANID)}
		}
		if b := a.BridgeDetails; b != nil && a.Type == "bridge" {
			bm := &bridgeModel{
				Routing:              types.BoolPointerValue(b.Routing),
				FilterVLANs:          types.BoolPointerValue(b.FilterVLANs),
				PermitARPBroadcast:   types.BoolPointerValue(b.PermitARPBroadcast),
				STP:                  types.BoolPointerValue(b.STP),
				STPMaxAge:            types.Int64PointerValue(b.STPMaxAge),
				MACAging:             types.Int64PointerValue(b.MACAging),
				FilterEthernetFrames: types.BoolPointerValue(b.FilterEthernetFrames),
			}
			for _, mem := range b.Members {
				bm.Members = append(bm.Members, bridgeMemberModel{Interface: types.StringValue(mem.Interface.Name), Zone: types.StringValue(mem.Zone.Name)})
			}
			m.Bridge = bm
		}
		if l := a.LAGDetails; l != nil && a.Type == "lag" {
			names := make([]string, 0, len(l.Members))
			for _, mem := range l.Members {
				names = append(names, mem.Interface.Name)
			}
			m.LAG = &lagModel{
				Members:           framework.StringSet(ctx, names, diags),
				Mode:              types.StringValue(l.Mode),
				LoadBalanceMethod: types.StringPointerValue(l.LoadBalanceMethod),
				PrimaryInterface:  framework.RefName(l.PrimaryInterface),
			}
		}
		return m
	},
}

func validateInterface(_ context.Context, m *interfaceModel, diags *diag.Diagnostics) {
	validateIP("ipv4", m.IPv4, diags)
	validateIP("ipv6", m.IPv6, diags)
	if m.Type.IsUnknown() {
		return
	}
	blocks := map[string]bool{"vlan": m.VLAN != nil, "bridge": m.Bridge != nil, "lag": m.LAG != nil}
	for block, set := range blocks {
		want := m.Type.ValueString() == block
		if want && !set {
			diags.AddAttributeError(path.Root(block), "Missing block", fmt.Sprintf("%q is required when type is %q.", block, block))
		}
		if !want && set {
			diags.AddAttributeError(path.Root(block), "Unexpected block", fmt.Sprintf("%q can only be set when type is %q.", block, block))
		}
	}
	if m.Type.ValueString() != "vlan" && !m.Zone.IsNull() {
		diags.AddAttributeError(path.Root("zone"), "Unexpected zone", "zone only applies to VLAN interfaces; set the zone of bridge members in bridge.members.")
	}
}

func interfaceSchema() schema.Schema {
	optBool := func(desc string) schema.BoolAttribute {
		return schema.BoolAttribute{Optional: true, Computed: true, MarkdownDescription: desc,
			PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()}}
	}
	optInt := func(desc string, lo, hi int64) schema.Int64Attribute {
		return schema.Int64Attribute{Optional: true, Computed: true, MarkdownDescription: desc,
			Validators:    []validator.Int64{int64validator.Between(lo, hi)},
			PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()}}
	}
	name := framework.NameAttribute("interface", 58, false)

	attrs := map[string]schema.Attribute{
		"id":            framework.IDAttribute(),
		"name":          name,
		"hardware_name": hardwareNameAttribute(true),
		"type": schema.StringAttribute{
			Required:            true,
			MarkdownDescription: "Interface type. " + framework.OneOfMarkdown(interfaceTypes...) + " Changing this forces a new resource.",
			Validators:          []validator.String{stringvalidator.OneOf(interfaceTypes...)},
			PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
		},
		"description": schema.StringAttribute{
			Optional:            true,
			MarkdownDescription: "Description. Only applicable to bridge interfaces.",
			Validators:          []validator.String{stringvalidator.LengthAtMost(100)},
		},
		"zone": zoneAttribute("Zone of the interface. Only applicable to VLAN interfaces."),
		"vlan": schema.SingleNestedAttribute{
			Optional:            true,
			MarkdownDescription: "VLAN settings. Required when `type` is `vlan`. Changing this forces a new resource.",
			PlanModifiers:       []planmodifier.Object{objectplanmodifier.RequiresReplace()},
			Attributes: map[string]schema.Attribute{
				"parent_interface": schema.StringAttribute{
					Required:            true,
					MarkdownDescription: "Name of the parent interface, e.g. `Port2`.",
					Validators:          []validator.String{framework.ObjectName()},
				},
				"vlan_id": schema.Int64Attribute{
					Required:            true,
					MarkdownDescription: "VLAN ID (1-4094).",
					Validators:          []validator.Int64{int64validator.Between(1, 4094)},
				},
			},
		},
		"bridge": schema.SingleNestedAttribute{
			Optional:            true,
			MarkdownDescription: "Bridge settings. Required when `type` is `bridge`.",
			Attributes: map[string]schema.Attribute{
				"members": schema.ListNestedAttribute{
					Required:            true,
					MarkdownDescription: "Bridge members (at least two).",
					Validators:          []validator.List{listvalidator.SizeAtLeast(2)},
					NestedObject: schema.NestedAttributeObject{
						Attributes: map[string]schema.Attribute{
							"interface": schema.StringAttribute{Required: true, MarkdownDescription: "Name of the member interface.", Validators: []validator.String{framework.ObjectName()}},
							"zone":      schema.StringAttribute{Required: true, MarkdownDescription: "Zone of the member.", Validators: []validator.String{framework.ObjectName()}},
						},
					},
				},
				"routing":                optBool("Route traffic between the bridge and other interfaces."),
				"filter_vlans":           optBool("Filter VLAN traffic."),
				"permit_arp_broadcast":   optBool("Permit ARP broadcasts."),
				"stp":                    optBool("Enable Spanning Tree Protocol."),
				"stp_max_age":            optInt("STP maximum age in seconds (6-40).", 6, 40),
				"mac_aging":              optInt("MAC address aging time in seconds (0-65535).", 0, 65535),
				"filter_ethernet_frames": optBool("Filter Ethernet frames by type."),
			},
		},
		"lag": schema.SingleNestedAttribute{
			Optional:            true,
			MarkdownDescription: "Link aggregation settings. Required when `type` is `lag`.",
			Attributes: map[string]schema.Attribute{
				"members": schema.SetAttribute{
					Required:            true,
					ElementType:         types.StringType,
					MarkdownDescription: "Names of the member interfaces.",
					Validators:          []validator.Set{setvalidator.SizeAtLeast(1), setvalidator.ValueStringsAre(framework.ObjectName())},
				},
				"mode": schema.StringAttribute{
					Required:            true,
					MarkdownDescription: "Bonding mode. " + framework.OneOfMarkdown(lagModes...),
					Validators:          []validator.String{stringvalidator.OneOf(lagModes...)},
				},
				"load_balance_method": schema.StringAttribute{
					Optional: true, Computed: true,
					MarkdownDescription: "Transmit hash policy in `lacp8023ad` mode. " + framework.OneOfMarkdown(lagLoadBalances...),
					Validators:          []validator.String{stringvalidator.OneOf(lagLoadBalances...)},
					PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				},
				"primary_interface": schema.StringAttribute{
					Optional:            true,
					MarkdownDescription: "Primary member in `activeBackup` mode.",
					Validators:          []validator.String{framework.ObjectName()},
				},
			},
		},
		"ipv4": ipAttribute(4),
		"ipv6": ipAttribute(6),
	}
	for k, v := range mtuAttributes() {
		attrs[k] = v
	}
	return schema.Schema{
		MarkdownDescription: "Manages a VLAN, bridge or LAG interface (*Configure > Network > Interfaces*). " +
			"Physical ports cannot be created; configure them with `sophosfirewall_physical_interface`.",
		Attributes: attrs,
	}
}
