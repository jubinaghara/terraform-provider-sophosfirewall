// Package servicesobj implements the network service objects: TCP/UDP port
// services, IP protocol services, ICMP and ICMPv6 services, and service groups.
package servicesobj

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
)

// API values of the service "type" field.
const (
	typeTCPOrUDP = "tcpOrUdp"
	typeIP       = "ip"
	typeICMP     = "icmp"
	typeICMPv6   = "icmpv6"
)

// anyPort is the port range the firewall uses when a port is omitted.
const anyPort = "1:65535"

type serviceModel struct {
	ID          types.String     `tfsdk:"id"`
	Name        types.String     `tfsdk:"name"`
	Description types.String     `tfsdk:"description"`
	TCPUDP      []tcpUDPModel    `tfsdk:"tcp_udp"`
	IPProtocols types.Set        `tfsdk:"ip_protocols"`
	ICMP        []icmpEntryModel `tfsdk:"icmp"`
	ICMPv6      []icmpEntryModel `tfsdk:"icmpv6"`
}

type tcpUDPModel struct {
	Protocol        types.String `tfsdk:"protocol"`
	SourcePort      types.String `tfsdk:"source_port"`
	DestinationPort types.String `tfsdk:"destination_port"`
}

type icmpEntryModel struct {
	Type types.String `tfsdk:"type"`
	Code types.String `tfsdk:"code"`
}

// ---- API payload ----

type service struct {
	ID          string         `json:"id,omitempty"`
	Name        string         `json:"name"`
	Description *string        `json:"description,omitempty"`
	Type        string         `json:"type,omitempty"`
	Services    []serviceEntry `json:"services"`
}

// serviceEntry is the union of the four oneOf branches of a service entry.
type serviceEntry struct {
	Protocol        string     `json:"protocol,omitempty"`
	SourcePort      *portRange `json:"sourcePort,omitempty"`
	DestinationPort *portRange `json:"destinationPort,omitempty"`
	IPProtocol      string     `json:"ipProtocol,omitempty"`
	ICMPType        string     `json:"icmpType,omitempty"`
	ICMPCode        string     `json:"icmpCode,omitempty"`
	ICMPv6Type      string     `json:"icmpv6Type,omitempty"`
	ICMPv6Code      string     `json:"icmpv6Code,omitempty"`
}

type portRange struct {
	From int64 `json:"from,omitempty"`
	To   int64 `json:"to,omitempty"`
}

// Service manages /network/services.
var Service = &framework.Resource[serviceModel, service]{
	Name:       "service",
	Title:      "service",
	Path:       "/network/services",
	Schema:     serviceSchema(),
	Expand:     expandService,
	Flatten:    flattenService,
	CreateOnly: []string{"type"},
}

func serviceSchema() schema.Schema {
	kinds := []string{"tcp_udp", "ip_protocols", "icmp", "icmpv6"}
	others := func(self string) []path.Expression {
		var out []path.Expression
		for _, k := range kinds {
			if k != self {
				out = append(out, path.MatchRoot(k))
			}
		}
		return out
	}
	listReplace := []planmodifier.List{replaceListOnPresenceChange()}

	icmpEntry := func(family string, types, codes []string) schema.NestedAttributeObject {
		return schema.NestedAttributeObject{
			Attributes: map[string]schema.Attribute{
				"type": schema.StringAttribute{
					Required:            true,
					MarkdownDescription: fmt.Sprintf("%s type. %s", family, framework.OneOfMarkdown(types...)),
					Validators:          []validator.String{stringvalidator.OneOf(types...)},
				},
				"code": schema.StringAttribute{
					Optional: true,
					Computed: true,
					Default:  stringdefault.StaticString("any"),
					MarkdownDescription: fmt.Sprintf("%s code; valid codes depend on `type`. Defaults to `any`. %s",
						family, framework.OneOfMarkdown(codes...)),
					Validators: []validator.String{stringvalidator.OneOf(codes...)},
				},
			},
		}
	}
	port := func(what string) schema.StringAttribute {
		return schema.StringAttribute{
			Optional: true,
			Computed: true,
			Default:  stringdefault.StaticString(anyPort),
			MarkdownDescription: fmt.Sprintf("%s port, either a single port such as `443` or a range `from:to` such as `1024:65535`. "+
				"Defaults to `%s` (any port).", what, anyPort),
			Validators: []validator.String{portValidator{}},
		}
	}

	return schema.Schema{
		MarkdownDescription: "Manages a service (*Objects > Hosts and services > Services*). " +
			"Set exactly one of `tcp_udp`, `ip_protocols`, `icmp` or `icmpv6`; switching between them recreates the service. " +
			"Built-in services such as `HTTPS` can be looked up with the `sophosfirewall_service` data source.",
		Attributes: map[string]schema.Attribute{
			"id":          framework.IDAttribute(),
			"name":        framework.NameAttribute("service", 50, false),
			"description": framework.DescriptionAttribute(255),
			"tcp_udp": schema.ListNestedAttribute{
				Optional:            true,
				MarkdownDescription: "TCP/UDP port entries (at most 100).",
				Validators: []validator.List{
					listvalidator.SizeBetween(1, 100),
					listvalidator.ExactlyOneOf(others("tcp_udp")...),
				},
				PlanModifiers: listReplace,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"protocol": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "Transport protocol. " + framework.OneOfMarkdown("tcp", "udp"),
							Validators:          []validator.String{stringvalidator.OneOf("tcp", "udp")},
						},
						"source_port":      port("Source"),
						"destination_port": port("Destination"),
					},
				},
			},
			"ip_protocols": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				MarkdownDescription: "IP protocols (at most 100), using the API keywords, e.g. `gre`, `esp`, `ah`, `sctp`, " +
					"`ospfigp` or `ipProto99` for unnamed protocol numbers.",
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, 100),
					setvalidator.ValueStringsAre(stringvalidator.OneOf(ipProtocols...)),
				},
				PlanModifiers: []planmodifier.Set{framework.ReplaceSetOnPresenceChange()},
			},
			"icmp": schema.ListNestedAttribute{
				Optional:            true,
				MarkdownDescription: "ICMPv4 type/code entries (at most 100).",
				Validators:          []validator.List{listvalidator.SizeBetween(1, 100)},
				PlanModifiers:       listReplace,
				NestedObject:        icmpEntry("ICMP", icmpTypes, icmpCodes),
			},
			"icmpv6": schema.ListNestedAttribute{
				Optional:            true,
				MarkdownDescription: "ICMPv6 type/code entries (at most 100).",
				Validators:          []validator.List{listvalidator.SizeBetween(1, 100)},
				PlanModifiers:       listReplace,
				NestedObject:        icmpEntry("ICMPv6", icmpv6Types, icmpv6Codes),
			},
		},
	}
}

func expandService(ctx context.Context, m *serviceModel, diags *diag.Diagnostics) *service {
	s := &service{
		Name:        m.Name.ValueString(),
		Description: framework.StringPtr(m.Description),
		Services:    []serviceEntry{},
	}
	switch {
	case m.TCPUDP != nil:
		s.Type = typeTCPOrUDP
		for i, e := range m.TCPUDP {
			src, err := parsePort(e.SourcePort)
			if err != nil {
				diags.AddAttributeError(path.Root("tcp_udp").AtListIndex(i).AtName("source_port"), "Invalid port", err.Error())
			}
			dst, err := parsePort(e.DestinationPort)
			if err != nil {
				diags.AddAttributeError(path.Root("tcp_udp").AtListIndex(i).AtName("destination_port"), "Invalid port", err.Error())
			}
			s.Services = append(s.Services, serviceEntry{Protocol: e.Protocol.ValueString(), SourcePort: src, DestinationPort: dst})
		}
	case !m.IPProtocols.IsNull():
		s.Type = typeIP
		for _, p := range framework.Strings(ctx, m.IPProtocols, diags) {
			s.Services = append(s.Services, serviceEntry{IPProtocol: p})
		}
	case m.ICMP != nil:
		s.Type = typeICMP
		for _, e := range m.ICMP {
			s.Services = append(s.Services, serviceEntry{ICMPType: e.Type.ValueString(), ICMPCode: e.Code.ValueString()})
		}
	case m.ICMPv6 != nil:
		s.Type = typeICMPv6
		for _, e := range m.ICMPv6 {
			s.Services = append(s.Services, serviceEntry{ICMPv6Type: e.Type.ValueString(), ICMPv6Code: e.Code.ValueString()})
		}
	}
	return s
}

func flattenService(ctx context.Context, a *service, _ *serviceModel, diags *diag.Diagnostics) *serviceModel {
	m := &serviceModel{
		ID:          types.StringValue(a.ID),
		Name:        types.StringValue(a.Name),
		Description: framework.StringOr(a.Description, ""),
		IPProtocols: types.SetNull(types.StringType),
	}
	switch a.Type {
	case typeTCPOrUDP:
		m.TCPUDP = []tcpUDPModel{}
		for _, e := range a.Services {
			m.TCPUDP = append(m.TCPUDP, tcpUDPModel{
				Protocol:        types.StringValue(e.Protocol),
				SourcePort:      types.StringValue(formatPort(e.SourcePort)),
				DestinationPort: types.StringValue(formatPort(e.DestinationPort)),
			})
		}
	case typeIP:
		var list []string
		for _, e := range a.Services {
			list = append(list, e.IPProtocol)
		}
		m.IPProtocols = framework.StringSet(ctx, list, diags)
	case typeICMP:
		m.ICMP = []icmpEntryModel{}
		for _, e := range a.Services {
			m.ICMP = append(m.ICMP, icmpEntryModel{Type: types.StringValue(e.ICMPType), Code: types.StringValue(e.ICMPCode)})
		}
	case typeICMPv6:
		m.ICMPv6 = []icmpEntryModel{}
		for _, e := range a.Services {
			m.ICMPv6 = append(m.ICMPv6, icmpEntryModel{Type: types.StringValue(e.ICMPv6Type), Code: types.StringValue(e.ICMPv6Code)})
		}
	default:
		diags.AddError("Unsupported service type", fmt.Sprintf("The firewall returned unknown service type %q for service %q.", a.Type, a.Name))
	}
	return m
}

// parsePort converts "443" or "1024:65535" into an API port range. Null and
// unknown values yield nil, which the firewall treats as any port.
func parsePort(v types.String) (*portRange, error) {
	if v.IsNull() || v.IsUnknown() {
		return nil, nil
	}
	from, to, err := splitPort(v.ValueString())
	if err != nil {
		return nil, err
	}
	return &portRange{From: from, To: to}, nil
}

// formatPort is the inverse of parsePort. The API may return a single port
// with or without "from"; an absent range means any port.
func formatPort(p *portRange) string {
	switch {
	case p == nil || p.To == 0:
		return anyPort
	case p.From == 0 || p.From == p.To:
		return strconv.FormatInt(p.To, 10)
	default:
		return fmt.Sprintf("%d:%d", p.From, p.To)
	}
}

func splitPort(s string) (from, to int64, err error) {
	num := func(part string) (int64, error) {
		n, err := strconv.ParseInt(part, 10, 32)
		if err != nil || n < 1 || n > 65535 || strconv.FormatInt(n, 10) != part {
			return 0, fmt.Errorf("%q is not a port number between 1 and 65535", part)
		}
		return n, nil
	}
	lo, hi, isRange := strings.Cut(s, ":")
	if from, err = num(lo); err != nil {
		return 0, 0, err
	}
	if !isRange {
		return from, from, nil
	}
	if to, err = num(hi); err != nil {
		return 0, 0, err
	}
	if from >= to {
		return 0, 0, fmt.Errorf("port range %q must have its start below its end; write a single port as %q", s, lo)
	}
	return from, to, nil
}

// portValidator checks the "443" / "1024:65535" port syntax.
type portValidator struct{}

func (portValidator) Description(context.Context) string {
	return "must be a port such as 443 or a port range such as 1024:65535"
}

func (v portValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (portValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if _, _, err := splitPort(req.ConfigValue.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid port", err.Error())
	}
}

// replaceListOnPresenceChange forces replacement when an optional list
// switches between set and unset, i.e. when the service type changes.
func replaceListOnPresenceChange() planmodifier.List {
	return listplanmodifier.RequiresReplaceIf(
		func(_ context.Context, req planmodifier.ListRequest, resp *listplanmodifier.RequiresReplaceIfFuncResponse) {
			resp.RequiresReplace = req.StateValue.IsNull() != req.PlanValue.IsNull()
		},
		"Switching between set and unset forces a new resource.",
		"Switching between set and unset forces a new resource.",
	)
}
