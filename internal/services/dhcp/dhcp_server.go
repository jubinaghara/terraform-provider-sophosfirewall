// Package dhcp implements the DHCP server of the firewall.
package dhcp

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfos"
)

// OptionTypes are the DHCP option value types accepted by the API.
var OptionTypes = []string{
	"boolean", "string", "oneByte", "twoByte", "fourByte", "oneByteArray",
	"twoByteArray", "fourByteArray", "ipv4Addr", "ipv4AddrArray", "fqdn",
}

var (
	domainNameRe = regexp.MustCompile(`^\w(\.?\w|-)*$`)
	bootFileRe   = regexp.MustCompile(`^[^;'|]*$`)
	hostnameRe   = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.?$`)
)

type serverModel struct {
	ID                  types.String         `tfsdk:"id"`
	Name                types.String         `tfsdk:"name"`
	Enabled             types.Bool           `tfsdk:"enabled"`
	Interface           types.String         `tfsdk:"interface"`
	PrefixLength        types.Int64          `tfsdk:"prefix_length"`
	Gateway             types.String         `tfsdk:"gateway"`
	AddressPools        []addressPoolModel   `tfsdk:"address_pools"`
	StaticMappings      []staticMappingModel `tfsdk:"static_mappings"`
	DefaultLeaseTime    types.Int64          `tfsdk:"default_lease_time"`
	MaxLeaseTime        types.Int64          `tfsdk:"max_lease_time"`
	DomainName          types.String         `tfsdk:"domain_name"`
	PrimaryDNS          types.String         `tfsdk:"primary_dns"`
	SecondaryDNS        types.String         `tfsdk:"secondary_dns"`
	PrimaryWINS         types.String         `tfsdk:"primary_wins"`
	SecondaryWINS       types.String         `tfsdk:"secondary_wins"`
	ConflictDetection   types.Bool           `tfsdk:"conflict_detection"`
	AcceptRelayRequests types.Bool           `tfsdk:"accept_relay_requests"`
	BootServer          types.String         `tfsdk:"boot_server"`
	BootFile            types.String         `tfsdk:"boot_file"`
	Options             []optionModel        `tfsdk:"dhcp_options"`
}

type addressPoolModel struct {
	StartAddress types.String `tfsdk:"start_address"`
	EndAddress   types.String `tfsdk:"end_address"`
}

type staticMappingModel struct {
	MACAddress types.String `tfsdk:"mac_address"`
	IPAddress  types.String `tfsdk:"ip_address"`
	Hostname   types.String `tfsdk:"hostname"`
}

type optionModel struct {
	Code  types.Int64  `tfsdk:"code"`
	Type  types.String `tfsdk:"type"`
	Value types.String `tfsdk:"value"`
}

type server struct {
	ID                  string              `json:"id,omitempty"`
	Name                string              `json:"name"`
	Enabled             *bool               `json:"enabled,omitempty"` // read-only
	Interface           sfos.NameRef        `json:"interface"`
	AcceptRelayRequests *bool               `json:"acceptRelayRequests,omitempty"`
	AddressPools        []addressPool       `json:"addressPools"`
	ClientReservations  []clientReservation `json:"clientReservations"`
	CIDR                int64               `json:"cidr"`
	DomainName          *string             `json:"domainName,omitempty"`
	Gateway             string              `json:"gatewayIpv4"`
	MaxLifetime         int64               `json:"maxLifetime"`
	DefaultLifetime     int64               `json:"defaultLifetime"`
	ConflictDetection   *bool               `json:"conflictDetection,omitempty"`
	PrimaryDNS          *string             `json:"primaryDnsIpv4,omitempty"`
	SecondaryDNS        *string             `json:"secondaryDnsIpv4,omitempty"`
	PrimaryWINS         *string             `json:"primaryWins,omitempty"`
	SecondaryWINS       *string             `json:"secondaryWins,omitempty"`
	BootNextServer      *bootNextServer     `json:"bootNextServer,omitempty"`
	BootFile            *string             `json:"bootFile,omitempty"`
	Options             []option            `json:"dhcpOptions"`
}

type addressPool struct {
	Start string `json:"startAddressIpv4"`
	End   string `json:"endAddressIpv4"`
}

type clientReservation struct {
	Hostname   string `json:"hostname,omitempty"`
	MACAddress string `json:"macAddress"`
	IPAddress  string `json:"ipv4Address"`
}

// bootNextServer is a oneOf: either an IPv4 address or an FQDN.
type bootNextServer struct {
	IPv4Address string `json:"ipv4Address,omitempty"`
	FQDN        string `json:"fqdn,omitempty"`
}

type option struct {
	Option string `json:"option,omitempty"` // resolved name, response only
	Code   int64  `json:"code"`
	Type   string `json:"type,omitempty"`
	Value  string `json:"value"`
}

// Server manages /network/dhcp/server/servers/ipv4.
var Server = &framework.Resource[serverModel, server]{
	Name:       "dhcp_server",
	Title:      "DHCP server",
	Path:       "/network/dhcp/server/servers/ipv4",
	Schema:     serverSchema(),
	CreateOnly: []string{"name"},
	Validate:   validateServer,
	Expand:     expandServer,
	Flatten:    flattenServer,
}

func serverSchema() schema.Schema {
	ipv4 := framework.IPAddress(32)
	optIP := func(desc string, also ...path.Expression) schema.StringAttribute {
		v := []validator.String{ipv4}
		if len(also) > 0 {
			v = append(v, stringvalidator.AlsoRequires(also...))
		}
		return schema.StringAttribute{Optional: true, MarkdownDescription: desc, Validators: v}
	}
	lease := func(desc string) schema.Int64Attribute {
		return schema.Int64Attribute{
			Required:            true,
			MarkdownDescription: desc + " in minutes (1-43200).",
			Validators:          []validator.Int64{int64validator.Between(1, 43200)},
		}
	}
	name := framework.NameAttribute("DHCP server", 50, true)

	return schema.Schema{
		MarkdownDescription: "Manages an IPv4 DHCP server (*Configure > Network > DHCP*).",
		Attributes: map[string]schema.Attribute{
			"id":   framework.IDAttribute(),
			"name": name,
			"enabled": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether the DHCP server is enabled. Read-only: the API does not allow switching it.",
				PlanModifiers:       []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
			},
			"interface": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the interface the server listens on, e.g. `Port1` or `Port2.100`.",
				Validators:          []validator.String{framework.ObjectName()},
			},
			"prefix_length": schema.Int64Attribute{
				Required:            true,
				MarkdownDescription: "Prefix length of the subnet handed out to clients (1-31), e.g. `24` for 255.255.255.0.",
				Validators:          []validator.Int64{int64validator.Between(1, 31)},
			},
			"gateway": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Default gateway handed out to clients.",
				Validators:          []validator.String{ipv4},
			},
			"address_pools": schema.SetNestedAttribute{
				Optional:            true,
				MarkdownDescription: "Dynamic IP lease ranges (at most 8).",
				Validators:          []validator.Set{setvalidator.SizeBetween(1, 8)},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"start_address": schema.StringAttribute{Required: true, MarkdownDescription: "First address of the range.", Validators: []validator.String{ipv4}},
						"end_address":   schema.StringAttribute{Required: true, MarkdownDescription: "Last address of the range.", Validators: []validator.String{ipv4}},
					},
				},
			},
			"static_mappings": schema.SetNestedAttribute{
				Optional:            true,
				MarkdownDescription: "Static IP-MAC mappings (client reservations).",
				Validators:          []validator.Set{setvalidator.SizeAtLeast(1)},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"mac_address": schema.StringAttribute{Required: true, MarkdownDescription: "Client MAC address, e.g. `00:1a:2b:3c:4d:5e`.", Validators: []validator.String{framework.MACAddress()}},
						"ip_address":  schema.StringAttribute{Required: true, MarkdownDescription: "Reserved IPv4 address.", Validators: []validator.String{ipv4}},
						"hostname": schema.StringAttribute{
							Optional:            true,
							MarkdownDescription: "Client hostname.",
							Validators:          []validator.String{stringvalidator.LengthBetween(1, 50)},
						},
					},
				},
			},
			"default_lease_time": lease("Default lease time"),
			"max_lease_time":     lease("Maximum lease time"),
			"domain_name": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Domain name (suffix) handed out to clients.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 250),
					stringvalidator.RegexMatches(domainNameRe, "must be a domain name such as branch.local"),
				},
			},
			"primary_dns":    optIP("Primary DNS server handed out to clients."),
			"secondary_dns":  optIP("Secondary DNS server. Requires `primary_dns`.", path.MatchRoot("primary_dns")),
			"primary_wins":   optIP("Primary WINS server handed out to clients."),
			"secondary_wins": optIP("Secondary WINS server. Requires `primary_wins`.", path.MatchRoot("primary_wins")),
			"conflict_detection": framework.BoolDefault(
				"Check that an address is unused (ping) before leasing it.", false),
			"accept_relay_requests": framework.BoolDefault(
				"Accept requests forwarded by DHCP relay agents.", false),
			"boot_server": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Next (TFTP) server for network boot, as an IPv4 address or a fully qualified domain name.",
				Validators: []validator.String{stringvalidator.Any(
					ipv4,
					stringvalidator.All(
						stringvalidator.LengthBetween(1, 253),
						stringvalidator.RegexMatches(hostnameRe, "must be a fully qualified domain name"),
						stringvalidator.RegexMatches(regexp.MustCompile(`[^0-9.]`), "must not look like an IPv4 address"),
					),
				)},
			},
			"boot_file": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Boot file name for network boot, e.g. `pxelinux.0`.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 1024),
					stringvalidator.RegexMatches(bootFileRe, "must not contain ;, ' or |"),
				},
			},
			"dhcp_options": schema.SetNestedAttribute{
				Optional:            true,
				MarkdownDescription: "Additional DHCP options. See *Appendix A* of the SFOS command line help for the standard option codes.",
				Validators:          []validator.Set{setvalidator.SizeAtLeast(1)},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"code": schema.Int64Attribute{
							Required:            true,
							MarkdownDescription: "Option code (1-255).",
							Validators:          []validator.Int64{int64validator.Between(1, 255)},
						},
						"type": schema.StringAttribute{
							Optional: true,
							MarkdownDescription: "Value type. Required for custom (non-standard) codes; for standard codes it may be " +
								"omitted, and must match the standard type when set. `fqdn` is only valid for standard codes. " +
								framework.OneOfMarkdown(OptionTypes...),
							Validators: []validator.String{stringvalidator.OneOf(OptionTypes...)},
						},
						"value": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "Option value.",
							Validators:          []validator.String{stringvalidator.LengthBetween(1, 1024)},
						},
					},
				},
			},
		},
	}
}

func validateServer(_ context.Context, m *serverModel, diags *diag.Diagnostics) {
	if known(m.DefaultLeaseTime) && known(m.MaxLeaseTime) && m.DefaultLeaseTime.ValueInt64() > m.MaxLeaseTime.ValueInt64() {
		diags.AddAttributeError(path.Root("default_lease_time"), "Invalid lease time",
			fmt.Sprintf("default_lease_time (%d) must not exceed max_lease_time (%d).", m.DefaultLeaseTime.ValueInt64(), m.MaxLeaseTime.ValueInt64()))
	}
	for _, p := range m.AddressPools {
		start, ok1 := addr(p.StartAddress)
		end, ok2 := addr(p.EndAddress)
		if ok1 && ok2 && end.Less(start) {
			diags.AddAttributeError(path.Root("address_pools"), "Invalid address pool",
				fmt.Sprintf("start_address %s must not be greater than end_address %s.", start, end))
		}
	}
	macs, ips := map[string]bool{}, map[string]bool{}
	for _, s := range m.StaticMappings {
		if known(s.MACAddress) {
			mac := strings.ToLower(s.MACAddress.ValueString())
			if macs[mac] {
				diags.AddAttributeError(path.Root("static_mappings"), "Duplicate MAC address", fmt.Sprintf("%s is mapped more than once.", s.MACAddress.ValueString()))
			}
			macs[mac] = true
		}
		if known(s.IPAddress) {
			ip := s.IPAddress.ValueString()
			if ips[ip] {
				diags.AddAttributeError(path.Root("static_mappings"), "Duplicate IP address", fmt.Sprintf("%s is reserved more than once.", ip))
			}
			ips[ip] = true
		}
	}
	codes := map[int64]bool{}
	for _, o := range m.Options {
		if !known(o.Code) {
			continue
		}
		if codes[o.Code.ValueInt64()] {
			diags.AddAttributeError(path.Root("dhcp_options"), "Duplicate DHCP option", fmt.Sprintf("Option code %d is set more than once.", o.Code.ValueInt64()))
		}
		codes[o.Code.ValueInt64()] = true
	}
}

type knowable interface {
	IsNull() bool
	IsUnknown() bool
}

func known(v knowable) bool { return !v.IsNull() && !v.IsUnknown() }

func addr(v types.String) (netip.Addr, bool) {
	if !known(v) {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(v.ValueString())
	return a, err == nil
}

func expandServer(_ context.Context, m *serverModel, _ *diag.Diagnostics) *server {
	s := &server{
		Name:                m.Name.ValueString(),
		Interface:           sfos.NameRef{Name: m.Interface.ValueString()},
		AcceptRelayRequests: framework.BoolPtr(m.AcceptRelayRequests),
		AddressPools:        make([]addressPool, 0, len(m.AddressPools)),
		ClientReservations:  make([]clientReservation, 0, len(m.StaticMappings)),
		CIDR:                m.PrefixLength.ValueInt64(),
		DomainName:          framework.StringPtr(m.DomainName),
		Gateway:             m.Gateway.ValueString(),
		MaxLifetime:         m.MaxLeaseTime.ValueInt64(),
		DefaultLifetime:     m.DefaultLeaseTime.ValueInt64(),
		ConflictDetection:   framework.BoolPtr(m.ConflictDetection),
		PrimaryDNS:          framework.StringPtr(m.PrimaryDNS),
		SecondaryDNS:        framework.StringPtr(m.SecondaryDNS),
		PrimaryWINS:         framework.StringPtr(m.PrimaryWINS),
		SecondaryWINS:       framework.StringPtr(m.SecondaryWINS),
		BootFile:            framework.StringPtr(m.BootFile),
		Options:             make([]option, 0, len(m.Options)),
	}
	for _, p := range m.AddressPools {
		s.AddressPools = append(s.AddressPools, addressPool{Start: p.StartAddress.ValueString(), End: p.EndAddress.ValueString()})
	}
	for _, r := range m.StaticMappings {
		s.ClientReservations = append(s.ClientReservations, clientReservation{
			Hostname: r.Hostname.ValueString(), MACAddress: r.MACAddress.ValueString(), IPAddress: r.IPAddress.ValueString(),
		})
	}
	if b := framework.StringPtr(m.BootServer); b != nil {
		if _, err := netip.ParseAddr(*b); err == nil {
			s.BootNextServer = &bootNextServer{IPv4Address: *b}
		} else {
			s.BootNextServer = &bootNextServer{FQDN: *b}
		}
	}
	for _, o := range m.Options {
		s.Options = append(s.Options, option{Code: o.Code.ValueInt64(), Type: o.Type.ValueString(), Value: o.Value.ValueString()})
	}
	return s
}

func flattenServer(_ context.Context, a *server, prior *serverModel, _ *diag.Diagnostics) *serverModel {
	m := &serverModel{
		ID:                  types.StringValue(a.ID),
		Name:                types.StringValue(a.Name),
		Enabled:             types.BoolPointerValue(a.Enabled),
		Interface:           types.StringValue(a.Interface.Name),
		PrefixLength:        types.Int64Value(a.CIDR),
		Gateway:             types.StringValue(a.Gateway),
		DefaultLeaseTime:    types.Int64Value(a.DefaultLifetime),
		MaxLeaseTime:        types.Int64Value(a.MaxLifetime),
		ConflictDetection:   framework.BoolOr(a.ConflictDetection, false),
		AcceptRelayRequests: framework.BoolOr(a.AcceptRelayRequests, false),
		DomainName:          framework.NonEmpty(deref(a.DomainName)),
		PrimaryDNS:          framework.NonEmpty(deref(a.PrimaryDNS)),
		SecondaryDNS:        framework.NonEmpty(deref(a.SecondaryDNS)),
		PrimaryWINS:         framework.NonEmpty(deref(a.PrimaryWINS)),
		SecondaryWINS:       framework.NonEmpty(deref(a.SecondaryWINS)),
		BootFile:            framework.NonEmpty(deref(a.BootFile)),
		BootServer:          types.StringNull(),
	}
	if b := a.BootNextServer; b != nil {
		m.BootServer = framework.NonEmpty(b.IPv4Address + b.FQDN)
	}

	// Optional scalars the firewall may fill in by itself (e.g. DNS servers
	// derived from the device settings) stay null unless the user manages them.
	if prior != nil {
		for _, f := range []struct {
			prior types.String
			value *types.String
		}{
			{prior.DomainName, &m.DomainName},
			{prior.PrimaryDNS, &m.PrimaryDNS},
			{prior.SecondaryDNS, &m.SecondaryDNS},
			{prior.PrimaryWINS, &m.PrimaryWINS},
			{prior.SecondaryWINS, &m.SecondaryWINS},
			{prior.BootServer, &m.BootServer},
			{prior.BootFile, &m.BootFile},
		} {
			if f.prior.IsNull() {
				*f.value = types.StringNull()
			}
		}
	}

	for _, p := range a.AddressPools {
		m.AddressPools = append(m.AddressPools, addressPoolModel{StartAddress: types.StringValue(p.Start), EndAddress: types.StringValue(p.End)})
	}

	// The firewall normalises the case of MAC addresses and upper-cases
	// hostnames: keep the spelling from the configuration when it denotes
	// the same value.
	priorMAC := map[string]string{}
	priorHost := map[string]string{}
	if prior != nil {
		for _, s := range prior.StaticMappings {
			priorMAC[strings.ToLower(s.MACAddress.ValueString())] = s.MACAddress.ValueString()
			if !s.Hostname.IsNull() && !s.Hostname.IsUnknown() {
				priorHost[strings.ToLower(s.Hostname.ValueString())] = s.Hostname.ValueString()
			}
		}
	}
	for _, r := range a.ClientReservations {
		mac := r.MACAddress
		if p, ok := priorMAC[strings.ToLower(mac)]; ok {
			mac = p
		}
		host := r.Hostname
		if p, ok := priorHost[strings.ToLower(host)]; ok {
			host = p
		}
		m.StaticMappings = append(m.StaticMappings, staticMappingModel{
			MACAddress: types.StringValue(mac),
			IPAddress:  types.StringValue(r.IPAddress),
			Hostname:   framework.NonEmpty(host),
		})
	}

	// The firewall always reports the type of an option, resolving it for
	// standard codes. Keep it out of state when the user left it to the
	// firewall, so that omitting it does not show up as drift.
	typeManaged := map[int64]bool{}
	if prior != nil {
		for _, o := range prior.Options {
			typeManaged[o.Code.ValueInt64()] = !o.Type.IsNull()
		}
	}
	for _, o := range a.Options {
		t := framework.NonEmpty(o.Type)
		if prior != nil && !typeManaged[o.Code] {
			t = types.StringNull()
		}
		m.Options = append(m.Options, optionModel{Code: types.Int64Value(o.Code), Type: t, Value: types.StringValue(o.Value)})
	}
	return m
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
