// Package interfaces implements network interfaces: VLAN, bridge and LAG
// interfaces that can be created, and physical ports that can be configured.
package interfaces

import (
	"fmt"
	"net/netip"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfos"
)

const interfacesPath = "/network/interfaces/network-interfaces"

// ---- API payload (shared by all interface resources) ----

type networkInterface struct {
	ID            string         `json:"id,omitempty"`
	Name          string         `json:"name"`
	HardwareName  string         `json:"hardwareName,omitempty"`
	Description   *string        `json:"description,omitempty"`
	Type          string         `json:"type,omitempty"`
	MemberOf      string         `json:"memberOf,omitempty"`
	VLANDetails   *vlanDetails   `json:"vlanDetails,omitempty"`
	BridgeDetails *bridgeDetails `json:"bridgeDetails,omitempty"`
	LAGDetails    *lagDetails    `json:"lagDetails,omitempty"`
	Zone          *sfos.NameRef  `json:"zone,omitempty"`
	IPv4          *ipConfig      `json:"ipv4,omitempty"`
	IPv6          *ipConfig      `json:"ipv6,omitempty"`
	MTU           *int64         `json:"mtu,omitempty"`
	MSS           *int64         `json:"mss,omitempty"`
	OverrideMAC   *bool          `json:"overrideMac,omitempty"`
	MACAddress    *string        `json:"macAddress,omitempty"`
}

type vlanDetails struct {
	VLANID          int64        `json:"vlanId"`
	ParentInterface sfos.NameRef `json:"parentInterface"`
}

type bridgeMember struct {
	Interface sfos.NameRef `json:"interface"`
	Zone      sfos.NameRef `json:"zone"`
}

type bridgeDetails struct {
	Members              []bridgeMember `json:"members"`
	Routing              *bool          `json:"routing,omitempty"`
	FilterVLANs          *bool          `json:"filterVlans,omitempty"`
	PermitARPBroadcast   *bool          `json:"permitArpBroadcast,omitempty"`
	STP                  *bool          `json:"stp,omitempty"`
	STPMaxAge            *int64         `json:"stpMaxAge,omitempty"`
	MACAging             *int64         `json:"macAging,omitempty"`
	FilterEthernetFrames *bool          `json:"filterEthernetFrames,omitempty"`
}

type lagMember struct {
	Interface sfos.NameRef `json:"interface"`
}

type lagDetails struct {
	Members           []lagMember   `json:"members"`
	Mode              string        `json:"mode,omitempty"`
	LoadBalanceMethod *string       `json:"loadBalanceMethod,omitempty"`
	PrimaryInterface  *sfos.NameRef `json:"primaryInterface,omitempty"`
}

// ipConfig covers both the "ipv4" and "ipv6" objects; unused keys are omitted.
type ipConfig struct {
	AssignmentType   string  `json:"assignmentType,omitempty"`
	IPv4Address      string  `json:"ipv4Address,omitempty"`
	CIDR             int64   `json:"cidr,omitempty"`
	IPv6Address      string  `json:"ipv6Address,omitempty"`
	PrefixLength     int64   `json:"prefixLength,omitempty"`
	GatewayName      *string `json:"gatewayName,omitempty"`
	GatewayIPAddress *string `json:"gatewayIpAddress,omitempty"`
}

// ---- IP configuration blocks ----

type ipModel struct {
	AssignmentType types.String `tfsdk:"assignment_type"`
	Address        types.String `tfsdk:"address"`
	GatewayName    types.String `tfsdk:"gateway_name"`
	GatewayAddress types.String `tfsdk:"gateway_address"`
}

func ipAttribute(version int) schema.SingleNestedAttribute {
	bits, example := 32, "192.0.2.1/24"
	if version == 6 {
		bits, example = 128, "2001:db8::1/64"
	}
	computedString := func(desc string, v ...validator.String) schema.StringAttribute {
		return schema.StringAttribute{Optional: true, Computed: true, MarkdownDescription: desc, Validators: v}
	}
	return schema.SingleNestedAttribute{
		Optional:            true,
		MarkdownDescription: fmt.Sprintf("IPv%d configuration. Omit to leave it unmanaged.", version),
		Attributes: map[string]schema.Attribute{
			"assignment_type": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "How the address is assigned. " + framework.OneOfMarkdown("static", "dhcp"),
				Validators:          []validator.String{stringvalidator.OneOf("static", "dhcp")},
			},
			"address": computedString(
				fmt.Sprintf("Interface address with prefix length, e.g. `%s`. Required for `static`; reported by the firewall for `dhcp`.", example),
				framework.InterfaceAddress(bits)),
			"gateway_name": computedString("Name of the gateway."),
			"gateway_address": computedString("Gateway address. Only applicable to `static`.",
				framework.IPAddress(bits), stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("gateway_name"))),
		},
	}
}

func expandIP(version int, m *ipModel, diags *diag.Diagnostics) *ipConfig {
	if m == nil {
		return nil
	}
	c := &ipConfig{
		AssignmentType:   m.AssignmentType.ValueString(),
		GatewayName:      framework.StringPtr(m.GatewayName),
		GatewayIPAddress: framework.StringPtr(m.GatewayAddress),
	}
	if a := framework.StringPtr(m.Address); a != nil {
		p, err := netip.ParsePrefix(*a)
		if err != nil {
			diags.AddError("Invalid interface address", err.Error())
			return nil
		}
		if version == 4 {
			c.IPv4Address, c.CIDR = p.Addr().String(), int64(p.Bits())
		} else {
			c.IPv6Address, c.PrefixLength = p.Addr().String(), int64(p.Bits())
		}
	}
	return c
}

func flattenIP(version int, c *ipConfig) *ipModel {
	if c == nil {
		return nil
	}
	m := &ipModel{
		AssignmentType: types.StringValue(c.AssignmentType),
		Address:        types.StringNull(),
		GatewayName:    framework.NonEmpty(deref(c.GatewayName)),
		GatewayAddress: framework.NonEmpty(deref(c.GatewayIPAddress)),
	}
	addr, bits := c.IPv4Address, c.CIDR
	if version == 6 {
		addr, bits = c.IPv6Address, c.PrefixLength
	}
	if addr != "" && bits > 0 {
		m.Address = types.StringValue(fmt.Sprintf("%s/%d", addr, bits))
	}
	return m
}

func validateIP(name string, m *ipModel, diags *diag.Diagnostics) {
	if m == nil || m.AssignmentType.IsUnknown() || m.Address.IsUnknown() {
		return
	}
	static := m.AssignmentType.ValueString() == "static"
	switch {
	case static && m.Address.IsNull():
		diags.AddAttributeError(path.Root(name).AtName("address"), "Missing address", "address is required when assignment_type is \"static\".")
	case !static && !m.Address.IsNull():
		diags.AddAttributeError(path.Root(name).AtName("address"), "Unexpected address", "address can only be set when assignment_type is \"static\".")
	}
}

// ---- attributes shared by all interface resources ----

func mtuAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"mtu": schema.Int64Attribute{
			Optional: true, Computed: true,
			MarkdownDescription: "Maximum transmission unit (576-9000). The firewall requires it to exceed `mss` by at least 40, so set `mss` too when lowering the MTU below the current MSS + 40.",
			Validators:          []validator.Int64{int64validator.Between(576, 9000)},
			PlanModifiers:       []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
		},
		"mss": schema.Int64Attribute{
			Optional: true, Computed: true,
			MarkdownDescription: "Maximum segment size (536-8960).",
			Validators:          []validator.Int64{int64validator.Between(536, 8960)},
			PlanModifiers:       []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
		},
	}
}

func hardwareNameAttribute(settable bool) schema.StringAttribute {
	a := schema.StringAttribute{
		Computed:            true,
		MarkdownDescription: "Hardware name of the interface.",
		PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
	}
	if settable {
		a.Optional = true
		a.MarkdownDescription += " Required by the firewall for bridge and LAG interfaces; derived automatically for VLANs. Changing this forces a new resource."
		a.Validators = []validator.String{stringvalidator.LengthBetween(1, 10)}
		a.PlanModifiers = append(a.PlanModifiers, stringplanmodifier.RequiresReplace())
	}
	return a
}

func zoneAttribute(description string) schema.StringAttribute {
	return schema.StringAttribute{
		Optional:            true,
		MarkdownDescription: description,
		Validators:          []validator.String{framework.ObjectName()},
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// validateMTU checks the firewall rule "MTU must exceed MSS by at least 40
// bytes" when both values are configured.
func validateMTU(mtu, mss types.Int64, diags *diag.Diagnostics) {
	if mtu.IsNull() || mtu.IsUnknown() || mss.IsNull() || mss.IsUnknown() {
		return
	}
	if mtu.ValueInt64()-mss.ValueInt64() < 40 {
		diags.AddAttributeError(path.Root("mss"), "Invalid MSS",
			fmt.Sprintf("mss (%d) must be at least 40 lower than mtu (%d).", mss.ValueInt64(), mtu.ValueInt64()))
	}
}
