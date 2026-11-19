// Package addresses implements the network address objects:
// IPv4/IPv6 hosts, networks, ranges and lists, MAC addresses and FQDNs.
package addresses

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
)

// IPv4Address manages /network/addresses/ipv4.
var IPv4Address = newIPAddress(ipFamily{version: 4, bits: 32, prefixKey: "cidr", maxPrefix: 31})

// IPv6Address manages /network/addresses/ipv6.
var IPv6Address = newIPAddress(ipFamily{version: 6, bits: 128, prefixKey: "prefixLength", maxPrefix: 127})

// The IPv4 and IPv6 APIs are identical apart from their field names, so a
// single implementation is parameterised by the address family.
type ipFamily struct {
	version   int
	bits      int
	prefixKey string
	maxPrefix int
}

// key returns the family specific JSON key, e.g. key("Address") == "ipv4Address".
func (f ipFamily) key(suffix string) string { return fmt.Sprintf("ipv%d%s", f.version, suffix) }

type ipAddressModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	IPAddress   types.String `tfsdk:"ip_address"`
	Network     types.String `tfsdk:"network"`
	RangeStart  types.String `tfsdk:"range_start"`
	RangeEnd    types.String `tfsdk:"range_end"`
	IPAddresses types.Set    `tfsdk:"ip_addresses"`
}

// ipAddressPayload is the JSON object; its keys depend on the family.
type ipAddressPayload map[string]any

func newIPAddress(f ipFamily) *framework.Resource[ipAddressModel, ipAddressPayload] {
	title := fmt.Sprintf("IPv%d address object", f.version)
	return &framework.Resource[ipAddressModel, ipAddressPayload]{
		Name:       fmt.Sprintf("ipv%d_address", f.version),
		Title:      title,
		Path:       fmt.Sprintf("/network/addresses/ipv%d", f.version),
		Schema:     f.schema(title),
		Expand:     f.expand,
		Flatten:    f.flatten,
		CreateOnly: []string{"type"},
	}
}

func (f ipFamily) schema(title string) schema.Schema {
	kinds := []string{"ip_address", "network", "range_start", "ip_addresses"}
	others := func(self string) []path.Expression {
		var out []path.Expression
		for _, k := range kinds {
			if k != self {
				out = append(out, path.MatchRoot(k))
			}
		}
		return out
	}
	replace := []planmodifier.String{framework.ReplaceOnPresenceChange()}
	ip := framework.IPAddress(f.bits)

	return schema.Schema{
		MarkdownDescription: fmt.Sprintf("Manages an %s (*Objects > Hosts and services > IP host*). "+
			"Set exactly one of `ip_address`, `network`, `range_start`/`range_end` or `ip_addresses`; "+
			"switching between them recreates the object.", title),
		Attributes: map[string]schema.Attribute{
			"id":          framework.IDAttribute(),
			"name":        framework.NameAttribute(title, 60, false),
			"description": framework.DescriptionAttribute(255),
			"ip_address": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "A single host address.",
				Validators:          []validator.String{ip, stringvalidator.ExactlyOneOf(others("ip_address")...)},
				PlanModifiers:       replace,
			},
			"network": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: fmt.Sprintf("A network in CIDR notation, e.g. `%s`.", map[int]string{4: "192.0.2.0/24", 6: "2001:db8::/64"}[f.version]),
				Validators:          []validator.String{framework.Prefix(f.bits, 1, f.maxPrefix)},
				PlanModifiers:       replace,
			},
			"range_start": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "First address of an address range. Requires `range_end`.",
				Validators:          []validator.String{ip, stringvalidator.AlsoRequires(path.MatchRoot("range_end"))},
				PlanModifiers:       replace,
			},
			"range_end": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Last address of an address range. Requires `range_start`.",
				Validators:          []validator.String{ip, stringvalidator.AlsoRequires(path.MatchRoot("range_start"))},
			},
			"ip_addresses": schema.SetAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "A list of host addresses.",
				Validators:          []validator.Set{setvalidator.SizeAtLeast(1), setvalidator.ValueStringsAre(ip)},
				PlanModifiers:       []planmodifier.Set{framework.ReplaceSetOnPresenceChange()},
			},
		},
	}
}

func (f ipFamily) expand(ctx context.Context, m *ipAddressModel, diags *diag.Diagnostics) *ipAddressPayload {
	body := ipAddressPayload{"name": m.Name.ValueString()}
	if d := framework.StringPtr(m.Description); d != nil {
		body["description"] = *d
	}
	switch {
	case !m.IPAddress.IsNull():
		body["type"] = f.key("Address")
		body[f.key("Address")] = m.IPAddress.ValueString()
	case !m.Network.IsNull():
		p, err := netip.ParsePrefix(m.Network.ValueString())
		if err != nil {
			diags.AddAttributeError(path.Root("network"), "Invalid network", err.Error())
			return nil
		}
		body["type"] = f.key("Network")
		body[f.key("NetworkAddress")] = p.Addr().String()
		body[f.prefixKey] = p.Bits()
	case !m.RangeStart.IsNull():
		body["type"] = f.key("Range")
		body[f.key("AddressStart")] = m.RangeStart.ValueString()
		body[f.key("AddressEnd")] = m.RangeEnd.ValueString()
	case !m.IPAddresses.IsNull():
		body["type"] = f.key("List")
		body[f.key("Addresses")] = framework.Strings(ctx, m.IPAddresses, diags)
	}
	return &body
}

func (f ipFamily) flatten(ctx context.Context, a *ipAddressPayload, _ *ipAddressModel, diags *diag.Diagnostics) *ipAddressModel {
	o := *a
	m := &ipAddressModel{
		ID:          types.StringValue(str(o["id"])),
		Name:        types.StringValue(str(o["name"])),
		Description: types.StringValue(str(o["description"])),
		IPAddress:   types.StringNull(),
		Network:     types.StringNull(),
		RangeStart:  types.StringNull(),
		RangeEnd:    types.StringNull(),
		IPAddresses: types.SetNull(types.StringType),
	}
	switch str(o["type"]) {
	case f.key("Address"):
		m.IPAddress = types.StringValue(str(o[f.key("Address")]))
	case f.key("Network"):
		m.Network = types.StringValue(fmt.Sprintf("%s/%d", str(o[f.key("NetworkAddress")]), num(o[f.prefixKey])))
	case f.key("Range"):
		m.RangeStart = types.StringValue(str(o[f.key("AddressStart")]))
		m.RangeEnd = types.StringValue(str(o[f.key("AddressEnd")]))
	case f.key("List"):
		var list []string
		if items, ok := o[f.key("Addresses")].([]any); ok {
			for _, it := range items {
				list = append(list, str(it))
			}
		}
		m.IPAddresses = framework.StringSet(ctx, list, diags)
	default:
		diags.AddError("Unsupported address type", fmt.Sprintf("The firewall returned unknown IPv%d address type %q.", f.version, str(o["type"])))
	}
	return m
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func num(v any) int64 {
	f, _ := v.(float64)
	return int64(f)
}
