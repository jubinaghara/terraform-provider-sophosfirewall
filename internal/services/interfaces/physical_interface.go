package interfaces

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
)

type physicalInterfaceModel struct {
	ID           types.String `tfsdk:"id"`
	Name         types.String `tfsdk:"name"`
	HardwareName types.String `tfsdk:"hardware_name"`
	Type         types.String `tfsdk:"type"`
	MemberOf     types.String `tfsdk:"member_of"`
	Zone         types.String `tfsdk:"zone"`
	IPv4         *ipModel     `tfsdk:"ipv4"`
	IPv6         *ipModel     `tfsdk:"ipv6"`
	MTU          types.Int64  `tfsdk:"mtu"`
	MSS          types.Int64  `tfsdk:"mss"`
	OverrideMAC  types.Bool   `tfsdk:"override_mac"`
	MACAddress   types.String `tfsdk:"mac_address"`
}

// PhysicalInterface configures interfaces that always exist on the
// appliance (physical ports, XFRM and cellular WAN interfaces).
var PhysicalInterface = &framework.Resource[physicalInterfaceModel, networkInterface]{
	Name:  "physical_interface",
	Title: "physical interface",
	Path:  interfacesPath,
	Adopt: true,
	// The derived sophosfirewall_interface data source already covers lookups.
	NoDataSource: true,
	CreateOnly:   []string{"type", "hardwareName"},
	Schema: schema.Schema{
		MarkdownDescription: "Configures an existing physical port (or XFRM / cellular WAN interface), e.g. `Port2`. " +
			"The interface must already exist: creating the resource adopts it and destroying it only removes it from " +
			"Terraform state, leaving the configuration on the firewall unchanged.",
		Attributes: func() map[string]schema.Attribute {
			attrs := map[string]schema.Attribute{
				"id":            framework.IDAttribute(),
				"name":          framework.NameAttribute("interface to adopt", 58, true),
				"hardware_name": hardwareNameAttribute(false),
				"type": schema.StringAttribute{
					Computed:            true,
					MarkdownDescription: "Interface type reported by the firewall, e.g. `physical`.",
					PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				},
				"member_of": schema.StringAttribute{
					Computed:            true,
					MarkdownDescription: "Name of the bridge or LAG this interface belongs to, if any.",
				},
				"zone": zoneAttribute("Zone of the interface."),
				"ipv4": ipAttribute(4),
				"ipv6": ipAttribute(6),
				"override_mac": schema.BoolAttribute{
					Optional: true, Computed: true,
					MarkdownDescription: "Override the factory MAC address with `mac_address`.",
					PlanModifiers:       []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
				},
				"mac_address": schema.StringAttribute{
					Optional: true, Computed: true,
					MarkdownDescription: "MAC address used when `override_mac` is true.",
					Validators:          []validator.String{framework.MACAddress()},
					PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				},
			}
			for k, v := range mtuAttributes() {
				attrs[k] = v
			}
			return attrs
		}(),
	},
	Validate: func(_ context.Context, m *physicalInterfaceModel, diags *diag.Diagnostics) {
		validateIP("ipv4", m.IPv4, diags)
		validateIP("ipv6", m.IPv6, diags)
	},
	Expand: func(_ context.Context, m *physicalInterfaceModel, diags *diag.Diagnostics) *networkInterface {
		return &networkInterface{
			Name:        m.Name.ValueString(),
			Zone:        framework.Ref(m.Zone),
			IPv4:        expandIP(4, m.IPv4, diags),
			IPv6:        expandIP(6, m.IPv6, diags),
			MTU:         framework.Int64Ptr(m.MTU),
			MSS:         framework.Int64Ptr(m.MSS),
			OverrideMAC: framework.BoolPtr(m.OverrideMAC),
			MACAddress:  framework.StringPtr(m.MACAddress),
		}
	},
	Flatten: func(_ context.Context, a *networkInterface, prior *physicalInterfaceModel, _ *diag.Diagnostics) *physicalInterfaceModel {
		m := &physicalInterfaceModel{
			ID:           types.StringValue(a.ID),
			Name:         types.StringValue(a.Name),
			HardwareName: types.StringValue(a.HardwareName),
			Type:         types.StringValue(a.Type),
			MemberOf:     framework.NonEmpty(a.MemberOf),
			Zone:         framework.RefName(a.Zone),
			MTU:          types.Int64PointerValue(a.MTU),
			MSS:          types.Int64PointerValue(a.MSS),
			OverrideMAC:  types.BoolPointerValue(a.OverrideMAC),
			MACAddress:   types.StringPointerValue(a.MACAddress),
		}
		if framework.Managed(prior, func(p *physicalInterfaceModel) bool { return p.IPv4 != nil }) {
			m.IPv4 = flattenIP(4, a.IPv4)
		}
		if framework.Managed(prior, func(p *physicalInterfaceModel) bool { return p.IPv6 != nil }) {
			m.IPv6 = flattenIP(6, a.IPv6)
		}
		// Unmanaged zone: keep it out of state so it is not reported as drift.
		if prior != nil && prior.Zone.IsNull() {
			m.Zone = types.StringNull()
		}
		return m
	},
}
