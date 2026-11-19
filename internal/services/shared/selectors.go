// Package shared holds schema fragments and API types reused by several
// services, chiefly the match criteria of firewall and NAT rules.
package shared

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfos"
)

// NetworkList is the set of address objects a rule can match. All keys are
// always encoded (as [] when empty) so the payload fully describes the
// selection and merge patches never leave stale entries behind.
type NetworkList struct {
	IPv4Addresses []sfos.NameRef `json:"ipv4Addresses"`
	IPv4Groups    []sfos.NameRef `json:"ipv4Groups"`
	FQDNAddresses []sfos.NameRef `json:"fqdnAddresses"`
	FQDNGroups    []sfos.NameRef `json:"fqdnGroups"`
	MACAddresses  []sfos.NameRef `json:"macAddresses"`
	Countries     []sfos.NameRef `json:"countries"`
	CountryGroups []sfos.NameRef `json:"countryGroups"`
}

// ZoneList selects zones.
type ZoneList struct {
	Zones []sfos.NameRef `json:"zones"`
}

// ServiceList selects services and service groups.
type ServiceList struct {
	Services      []sfos.NameRef `json:"services"`
	ServiceGroups []sfos.NameRef `json:"serviceGroups"`
}

// InterfaceList selects interfaces.
type InterfaceList struct {
	Interfaces []sfos.NameRef `json:"interfaces"`
}

// NetworksModel is the Terraform side of NetworkList.
type NetworksModel struct {
	IPv4Addresses types.Set `tfsdk:"ipv4_addresses"`
	IPv4Groups    types.Set `tfsdk:"ipv4_groups"`
	FQDNAddresses types.Set `tfsdk:"fqdn_addresses"`
	FQDNGroups    types.Set `tfsdk:"fqdn_groups"`
	MACAddresses  types.Set `tfsdk:"mac_addresses"`
	Countries     types.Set `tfsdk:"countries"`
	CountryGroups types.Set `tfsdk:"country_groups"`
}

// NetworksAttribute is an optional block of address object names. When
// omitted the rule matches any network.
func NetworksAttribute(description string) schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		Optional:            true,
		MarkdownDescription: description + " Omit to match any network.",
		Attributes: map[string]schema.Attribute{
			"ipv4_addresses": framework.NameSetAttribute("Names of IPv4 address objects."),
			"ipv4_groups":    framework.NameSetAttribute("Names of IPv4 address groups."),
			"fqdn_addresses": framework.NameSetAttribute("Names of FQDN address objects."),
			"fqdn_groups":    framework.NameSetAttribute("Names of FQDN groups."),
			"mac_addresses":  framework.NameSetAttribute("Names of MAC address objects."),
			"countries":      framework.NameSetAttribute("Names of countries."),
			"country_groups": framework.NameSetAttribute("Names of country groups."),
		},
	}
}

// ExpandNetworkList converts the block into API lists.
func ExpandNetworkList(ctx context.Context, m *NetworksModel, diags *diag.Diagnostics) NetworkList {
	if m == nil {
		m = &NetworksModel{}
	}
	return NetworkList{
		IPv4Addresses: framework.Refs(ctx, m.IPv4Addresses, diags),
		IPv4Groups:    framework.Refs(ctx, m.IPv4Groups, diags),
		FQDNAddresses: framework.Refs(ctx, m.FQDNAddresses, diags),
		FQDNGroups:    framework.Refs(ctx, m.FQDNGroups, diags),
		MACAddresses:  framework.Refs(ctx, m.MACAddresses, diags),
		Countries:     framework.Refs(ctx, m.Countries, diags),
		CountryGroups: framework.Refs(ctx, m.CountryGroups, diags),
	}
}

// ExpandNetworks returns "any" for a nil block.
func ExpandNetworks(ctx context.Context, m *NetworksModel, diags *diag.Diagnostics) sfos.Selector[NetworkList] {
	if m == nil {
		return sfos.MatchAny[NetworkList]()
	}
	return sfos.Match(ExpandNetworkList(ctx, m, diags))
}

// FlattenNetworkList returns nil when nothing is selected.
func FlattenNetworkList(ctx context.Context, l NetworkList, diags *diag.Diagnostics) *NetworksModel {
	m := &NetworksModel{
		IPv4Addresses: framework.RefSet(ctx, l.IPv4Addresses, diags),
		IPv4Groups:    framework.RefSet(ctx, l.IPv4Groups, diags),
		FQDNAddresses: framework.RefSet(ctx, l.FQDNAddresses, diags),
		FQDNGroups:    framework.RefSet(ctx, l.FQDNGroups, diags),
		MACAddresses:  framework.RefSet(ctx, l.MACAddresses, diags),
		Countries:     framework.RefSet(ctx, l.Countries, diags),
		CountryGroups: framework.RefSet(ctx, l.CountryGroups, diags),
	}
	for _, s := range []types.Set{m.IPv4Addresses, m.IPv4Groups, m.FQDNAddresses, m.FQDNGroups, m.MACAddresses, m.Countries, m.CountryGroups} {
		if !s.IsNull() {
			return m
		}
	}
	return nil
}

// FlattenNetworks returns nil for "any".
func FlattenNetworks(ctx context.Context, s sfos.Selector[NetworkList], diags *diag.Diagnostics) *NetworksModel {
	if s.Any {
		return nil
	}
	return FlattenNetworkList(ctx, s.Items, diags)
}

// ExpandZones returns "any" for a null set.
func ExpandZones(ctx context.Context, v types.Set, diags *diag.Diagnostics) sfos.Selector[ZoneList] {
	if v.IsNull() {
		return sfos.MatchAny[ZoneList]()
	}
	return sfos.Match(ZoneList{Zones: framework.Refs(ctx, v, diags)})
}

// FlattenZones returns a null set for "any".
func FlattenZones(ctx context.Context, s sfos.Selector[ZoneList], diags *diag.Diagnostics) types.Set {
	if s.Any {
		return types.SetNull(types.StringType)
	}
	return framework.RefSet(ctx, s.Items.Zones, diags)
}

// ExpandServices returns "any" when both sets are null.
func ExpandServices(ctx context.Context, services, groups types.Set, diags *diag.Diagnostics) sfos.Selector[ServiceList] {
	if services.IsNull() && groups.IsNull() {
		return sfos.MatchAny[ServiceList]()
	}
	return sfos.Match(ServiceList{
		Services:      framework.Refs(ctx, services, diags),
		ServiceGroups: framework.Refs(ctx, groups, diags),
	})
}

// FlattenServices returns null sets for "any".
func FlattenServices(ctx context.Context, s sfos.Selector[ServiceList], diags *diag.Diagnostics) (services, groups types.Set) {
	return framework.RefSet(ctx, s.Items.Services, diags), framework.RefSet(ctx, s.Items.ServiceGroups, diags)
}

// ExpandInterfaces returns "any" for a null set.
func ExpandInterfaces(ctx context.Context, v types.Set, diags *diag.Diagnostics) sfos.Selector[InterfaceList] {
	if v.IsNull() {
		return sfos.MatchAny[InterfaceList]()
	}
	return sfos.Match(InterfaceList{Interfaces: framework.Refs(ctx, v, diags)})
}

// FlattenInterfaces returns a null set for "any".
func FlattenInterfaces(ctx context.Context, s sfos.Selector[InterfaceList], diags *diag.Diagnostics) types.Set {
	if s.Any {
		return types.SetNull(types.StringType)
	}
	return framework.RefSet(ctx, s.Items.Interfaces, diags)
}
