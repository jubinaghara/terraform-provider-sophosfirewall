// Package dns implements DNS objects.
package dns

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfos"
)

const (
	defaultTTL    = 3600
	defaultWeight = 1
)

var domainRe = regexp.MustCompile(`^[A-Za-z0-9_-]+(\.[A-Za-z0-9-]+)*$`)

// targets are the mutually exclusive answer attributes of a host entry.
var targets = []string{"ipv4_address", "ipv4_interface", "ipv6_address", "ipv6_interface"}

type hostEntryModel struct {
	ID                      types.String   `tfsdk:"id"`
	Name                    types.String   `tfsdk:"name"`
	Domain                  types.String   `tfsdk:"domain"`
	EnableReverseResolution types.Bool     `tfsdk:"enable_reverse_resolution"`
	Addresses               []addressModel `tfsdk:"addresses"`
}

type addressModel struct {
	IPv4Address   types.String `tfsdk:"ipv4_address"`
	IPv4Interface types.String `tfsdk:"ipv4_interface"`
	IPv6Address   types.String `tfsdk:"ipv6_address"`
	IPv6Interface types.String `tfsdk:"ipv6_interface"`
	TTL           types.Int64  `tfsdk:"ttl"`
	Weight        types.Int64  `tfsdk:"weight"`
	PublishOnWAN  types.Bool   `tfsdk:"publish_on_wan"`
}

func (a *addressModel) values() []types.String {
	return []types.String{a.IPv4Address, a.IPv4Interface, a.IPv6Address, a.IPv6Interface}
}

type hostEntry struct {
	ID                      string   `json:"id,omitempty"`
	Name                    string   `json:"name"`
	Domain                  string   `json:"domain"`
	EnableReverseResolution *bool    `json:"enableReverseResolution,omitempty"`
	HostEntries             []record `json:"hostEntries"`
}

type record struct {
	TTL          int64       `json:"ttl"`
	Weight       int64       `json:"weight"`
	PublishOnWAN bool        `json:"publishOnWan"`
	IPv4         *ipv4Target `json:"ipv4,omitempty"`
	IPv6         *ipv6Target `json:"ipv6,omitempty"`
}

type ipv4Target struct {
	Address   string        `json:"ipv4Address,omitempty"`
	Interface *sfos.NameRef `json:"ipv4Interface,omitempty"`
}

type ipv6Target struct {
	Address   string        `json:"ipv6Address,omitempty"`
	Interface *sfos.NameRef `json:"ipv6Interface,omitempty"`
}

// HostEntry manages /network/dns/host-entries.
var HostEntry = &framework.Resource[hostEntryModel, hostEntry]{
	Name:  "dns_host_entry",
	Title: "DNS host entry",
	Path:  "/network/dns/host-entries",
	Schema: schema.Schema{
		MarkdownDescription: "Manages a DNS host entry (*Configure > Network > DNS > DNS host entry*): a static " +
			"record the firewall's DNS server answers for `domain`, pointing to fixed addresses or to the " +
			"current address of a firewall interface.",
		Attributes: map[string]schema.Attribute{
			"id":   framework.IDAttribute(),
			"name": framework.NameAttribute("DNS host entry", 64, false),
			"domain": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Fully qualified host name that is resolved, e.g. `intranet.example.com`. Changing this forces a new resource.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 253),
					stringvalidator.RegexMatches(domainRe, "must be a host name such as intranet.example.com"),
				},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"enable_reverse_resolution": framework.BoolDefault("Also answer reverse (PTR) lookups for the addresses.", false),
			"addresses": schema.ListNestedAttribute{
				Required:            true,
				MarkdownDescription: "Answers for the host name (1-8). Each sets exactly one of `ipv4_address`, `ipv4_interface`, `ipv6_address` or `ipv6_interface`.",
				Validators:          []validator.List{listvalidator.SizeBetween(1, 8)},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"ipv4_address": schema.StringAttribute{
							Optional:            true,
							MarkdownDescription: "Static IPv4 address.",
							Validators:          []validator.String{framework.IPAddress(32)},
						},
						"ipv4_interface": schema.StringAttribute{
							Optional:            true,
							MarkdownDescription: "Name of the interface whose IPv4 address is returned, e.g. `Port1`.",
							Validators:          []validator.String{framework.ObjectName()},
						},
						"ipv6_address": schema.StringAttribute{
							Optional:            true,
							MarkdownDescription: "Static IPv6 address.",
							Validators:          []validator.String{framework.IPAddress(128)},
						},
						"ipv6_interface": schema.StringAttribute{
							Optional:            true,
							MarkdownDescription: "Name of the interface whose IPv6 address is returned, e.g. `Port2`.",
							Validators:          []validator.String{framework.ObjectName()},
						},
						"ttl": schema.Int64Attribute{
							Optional:            true,
							Computed:            true,
							Default:             int64default.StaticInt64(defaultTTL),
							MarkdownDescription: fmt.Sprintf("Time to live in seconds (1-604800). Defaults to `%d`.", defaultTTL),
							Validators:          []validator.Int64{int64validator.Between(1, 604800)},
						},
						"weight": schema.Int64Attribute{
							Optional:            true,
							Computed:            true,
							Default:             int64default.StaticInt64(defaultWeight),
							MarkdownDescription: fmt.Sprintf("Relative weight among the answers (1-255). Defaults to `%d`.", defaultWeight),
							Validators:          []validator.Int64{int64validator.Between(1, 255)},
						},
						"publish_on_wan": framework.BoolDefault("Also answer queries received on WAN interfaces.", false),
					},
				},
			},
		},
	},
	CreateOnly: []string{"domain"},
	Validate: func(_ context.Context, m *hostEntryModel, diags *diag.Diagnostics) {
		for i, a := range m.Addresses {
			set := 0
			for _, v := range a.values() {
				if v.IsUnknown() {
					return
				}
				if !v.IsNull() {
					set++
				}
			}
			if set != 1 {
				diags.AddAttributeError(path.Root("addresses").AtListIndex(i), "Invalid address",
					fmt.Sprintf("Exactly one of %s must be set, got %d.", strings.Join(targets, ", "), set))
			}
		}
	},
	Expand: func(_ context.Context, m *hostEntryModel, _ *diag.Diagnostics) *hostEntry {
		h := &hostEntry{
			Name:                    m.Name.ValueString(),
			Domain:                  m.Domain.ValueString(),
			EnableReverseResolution: framework.BoolPtr(m.EnableReverseResolution),
			HostEntries:             make([]record, 0, len(m.Addresses)),
		}
		for _, a := range m.Addresses {
			r := record{TTL: a.TTL.ValueInt64(), Weight: a.Weight.ValueInt64(), PublishOnWAN: a.PublishOnWAN.ValueBool()}
			if a.TTL.IsNull() || a.TTL.IsUnknown() {
				r.TTL = defaultTTL
			}
			if a.Weight.IsNull() || a.Weight.IsUnknown() {
				r.Weight = defaultWeight
			}
			switch {
			case !a.IPv4Address.IsNull():
				r.IPv4 = &ipv4Target{Address: a.IPv4Address.ValueString()}
			case !a.IPv4Interface.IsNull():
				r.IPv4 = &ipv4Target{Interface: &sfos.NameRef{Name: a.IPv4Interface.ValueString()}}
			case !a.IPv6Address.IsNull():
				r.IPv6 = &ipv6Target{Address: a.IPv6Address.ValueString()}
			case !a.IPv6Interface.IsNull():
				r.IPv6 = &ipv6Target{Interface: &sfos.NameRef{Name: a.IPv6Interface.ValueString()}}
			}
			h.HostEntries = append(h.HostEntries, r)
		}
		return h
	},
	Flatten: func(_ context.Context, a *hostEntry, _ *hostEntryModel, _ *diag.Diagnostics) *hostEntryModel {
		m := &hostEntryModel{
			ID:                      types.StringValue(a.ID),
			Name:                    types.StringValue(a.Name),
			Domain:                  types.StringValue(a.Domain),
			EnableReverseResolution: framework.BoolOr(a.EnableReverseResolution, false),
		}
		for _, r := range a.HostEntries {
			e := addressModel{
				IPv4Address:   types.StringNull(),
				IPv4Interface: types.StringNull(),
				IPv6Address:   types.StringNull(),
				IPv6Interface: types.StringNull(),
				TTL:           types.Int64Value(r.TTL),
				Weight:        types.Int64Value(r.Weight),
				PublishOnWAN:  types.BoolValue(r.PublishOnWAN),
			}
			if r.IPv4 != nil {
				e.IPv4Address = framework.NonEmpty(r.IPv4.Address)
				e.IPv4Interface = framework.RefName(r.IPv4.Interface)
			}
			if r.IPv6 != nil {
				e.IPv6Address = framework.NonEmpty(r.IPv6.Address)
				e.IPv6Interface = framework.RefName(r.IPv6.Interface)
			}
			m.Addresses = append(m.Addresses, e)
		}
		return m
	},
}
