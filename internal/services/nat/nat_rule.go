// Package nat implements NAT rules.
package nat

import (
	"context"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/services/shared"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfos"
)

const ipv4RulesPath = "/nat/rules/ipv4"

var loadBalancingMethods = []string{"roundRobin", "firstAlive", "random", "stickyIp", "oneToOne"}

// ---- Terraform model ----

type ruleModel struct {
	ID                          types.String          `tfsdk:"id"`
	Name                        types.String          `tfsdk:"name"`
	Description                 types.String          `tfsdk:"description"`
	Enabled                     types.Bool            `tfsdk:"enabled"`
	Position                    types.String          `tfsdk:"position"`
	PositionReference           types.String          `tfsdk:"position_reference"`
	LinkedFirewallRule          types.String          `tfsdk:"linked_firewall_rule"`
	OriginalSourceNetworks      *shared.NetworksModel `tfsdk:"original_source_networks"`
	OriginalDestinationNetworks *shared.NetworksModel `tfsdk:"original_destination_networks"`
	OriginalServices            types.Set             `tfsdk:"original_services"`
	OriginalServiceGroups       types.Set             `tfsdk:"original_service_groups"`
	InboundInterfaces           types.Set             `tfsdk:"inbound_interfaces"`
	OutboundInterfaces          types.Set             `tfsdk:"outbound_interfaces"`
	TranslatedSource            *translatedSource     `tfsdk:"translated_source"`
	TranslatedDestination       *translatedDest       `tfsdk:"translated_destination"`
	TranslatedService           types.String          `tfsdk:"translated_service"`
	LoadBalancingMethod         types.String          `tfsdk:"load_balancing_method"`
	HealthCheck                 *healthCheckModel     `tfsdk:"health_check"`
	SourceNATOverrides          []snatOverrideModel   `tfsdk:"source_nat_overrides"`
}

func (m *ruleModel) position() shared.Position {
	return shared.Position{Position: m.Position, Reference: m.PositionReference}
}

type translatedSource struct {
	Masquerade  types.Bool   `tfsdk:"masquerade"`
	IPv4Address types.String `tfsdk:"ipv4_address"`
}

type translatedDest struct {
	IPv4Address types.String `tfsdk:"ipv4_address"`
	FQDNAddress types.String `tfsdk:"fqdn_address"`
}

type healthCheckModel struct {
	Protocol types.String `tfsdk:"protocol"`
	Port     types.Int64  `tfsdk:"port"`
	Interval types.Int64  `tfsdk:"interval"`
	Timeout  types.Int64  `tfsdk:"timeout"`
	Retries  types.Int64  `tfsdk:"retries"`
}

type snatOverrideModel struct {
	Interface        types.String      `tfsdk:"interface"`
	TranslatedSource *translatedSource `tfsdk:"translated_source"`
}

// ---- API payload ----

type rule struct {
	ID                          string                              `json:"id,omitempty"`
	Name                        string                              `json:"name"`
	Description                 *string                             `json:"description,omitempty"`
	Enabled                     *bool                               `json:"enabled,omitempty"`
	Position                    string                              `json:"position,omitempty"`
	ReferenceItem               *sfos.NameRef                       `json:"referenceItem,omitempty"`
	LinkedFirewallRule          *sfos.NameRef                       `json:"linkedFirewallRule,omitempty"`
	OriginalServicesOrGroups    sfos.Selector[shared.ServiceList]   `json:"originalServicesOrGroups"`
	TranslatedService           *sfos.NameRef                       `json:"translatedService,omitempty"`
	InboundInterfaces           sfos.Selector[shared.InterfaceList] `json:"inboundInterfaces"`
	OutboundInterfaces          sfos.Selector[shared.InterfaceList] `json:"outboundInterfaces"`
	LoadBalancingMethod         *string                             `json:"loadBalancingMethod,omitempty"`
	HealthCheck                 *healthCheck                        `json:"healthCheck,omitempty"`
	OriginalSourceNetworks      sfos.Selector[shared.NetworkList]   `json:"originalSourceNetworks"`
	OriginalDestinationNetworks sfos.Selector[shared.NetworkList]   `json:"originalDestinationNetworks"`
	TranslatedSource            *sourceTranslation                  `json:"translatedSource,omitempty"`
	TranslatedDestination       *destinationTranslation             `json:"translatedDestination,omitempty"`
	OverrideSNAT                []snatOverride                      `json:"overrideSnatForOutboundInterfaces"`
}

type sourceTranslation struct {
	Masq        bool          `json:"masq,omitempty"`
	IPv4Address *sfos.NameRef `json:"ipv4Address,omitempty"`
}

type destinationTranslation struct {
	IPv4Address *sfos.NameRef `json:"ipv4Address,omitempty"`
	FQDNAddress *sfos.NameRef `json:"fqdnAddress,omitempty"`
}

type healthCheck struct {
	Rule healthCheckRule `json:"rule"`
}

type healthCheckRule struct {
	Protocol string `json:"protocol"`
	Port     string `json:"port,omitempty"`
	Interval *int64 `json:"interval,omitempty"`
	Timeout  *int64 `json:"timeout,omitempty"`
	Retry    *int64 `json:"retry,omitempty"`
}

type snatOverride struct {
	OutboundInterface sfos.NameRef       `json:"outboundInterface"`
	TranslatedSource  *sourceTranslation `json:"translatedSource"`
}

// ---- Resource ----

// RuleIPv4 manages /nat/rules/ipv4.
var RuleIPv4 = &framework.Resource[ruleModel, rule]{
	Name:       "nat_rule",
	Title:      "NAT rule",
	Path:       ipv4RulesPath,
	Schema:     ruleSchema(),
	Expand:     expandRule,
	Flatten:    flattenRule,
	CreateOnly: []string{"position", "referenceItem", "linkedFirewallRule"},
	Validate: func(_ context.Context, m *ruleModel, diags *diag.Diagnostics) {
		m.position().Validate(diags)
	},
	AfterUpdate: func(ctx context.Context, c *sfos.Client, plan, state *ruleModel, diags *diag.Diagnostics) {
		shared.MoveIfChanged(ctx, c, ipv4RulesPath+"/move", plan.Name.ValueString(), plan.position(), state.position(), diags)
	},
}

func sourceTranslationAttribute(description string, required bool) schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		Optional:            !required,
		Required:            required,
		MarkdownDescription: description + " Set exactly one of `masquerade` or `ipv4_address`.",
		Attributes: map[string]schema.Attribute{
			"masquerade": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Masquerade (`MASQ`) behind the IP address of the outbound interface. Must be `true` when set.",
				Validators:          []validator.Bool{framework.BoolTrue()},
			},
			"ipv4_address": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Name of the IPv4 address object to translate to.",
				Validators: []validator.String{
					framework.ObjectName(),
					stringvalidator.ExactlyOneOf(path.MatchRelative().AtParent().AtName("masquerade")),
				},
			},
		},
	}
}

func ruleSchema() schema.Schema {
	ref := func(desc string) schema.StringAttribute {
		return schema.StringAttribute{Optional: true, MarkdownDescription: desc, Validators: []validator.String{framework.ObjectName()}}
	}
	attrs := map[string]schema.Attribute{
		"id":          framework.IDAttribute(),
		"name":        framework.NameAttribute("NAT rule", 60, false),
		"description": framework.DescriptionAttribute(255),
		"enabled":     framework.BoolDefault("Whether the rule is active.", true),
		"linked_firewall_rule": schema.StringAttribute{
			Optional:            true,
			MarkdownDescription: "Name of the firewall rule this NAT rule is linked to. Changing this forces a new resource.",
			Validators:          []validator.String{framework.ObjectName()},
			PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
		},
		"original_source_networks":      shared.NetworksAttribute("Original source addresses to match."),
		"original_destination_networks": shared.NetworksAttribute("Original destination addresses to match."),
		"original_services":             framework.NameSetAttribute("Original services to match. Omit both `original_services` and `original_service_groups` to match any service."),
		"original_service_groups":       framework.NameSetAttribute("Original service groups to match."),
		"inbound_interfaces":            framework.NameSetAttribute("Inbound interfaces to match. Omit to match any interface."),
		"outbound_interfaces":           framework.NameSetAttribute("Outbound interfaces to match. Omit to match any interface."),
		"translated_source":             sourceTranslationAttribute("Source NAT (SNAT). Omit to keep the original source.", false),
		"translated_destination": schema.SingleNestedAttribute{
			Optional:            true,
			MarkdownDescription: "Destination NAT (DNAT). Omit to keep the original destination. Set exactly one of `ipv4_address` or `fqdn_address`.",
			Attributes: map[string]schema.Attribute{
				"ipv4_address": schema.StringAttribute{
					Optional:            true,
					MarkdownDescription: "Name of the IPv4 address object to translate to.",
					Validators: []validator.String{
						framework.ObjectName(),
						stringvalidator.ExactlyOneOf(path.MatchRelative().AtParent().AtName("fqdn_address")),
					},
				},
				"fqdn_address": ref("Name of the FQDN address object to translate to."),
			},
		},
		"translated_service": ref("Name of the service to translate to (port forwarding). Omit to keep the original service."),
		"load_balancing_method": schema.StringAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Load balancing method when the translated destination resolves to several hosts. " + framework.OneOfMarkdown(loadBalancingMethods...),
			Validators:          []validator.String{stringvalidator.OneOf(loadBalancingMethods...)},
			PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
		"health_check": schema.SingleNestedAttribute{
			Optional:            true,
			MarkdownDescription: "Health check for load-balanced destinations.",
			Attributes: map[string]schema.Attribute{
				"protocol": schema.StringAttribute{
					Required:            true,
					MarkdownDescription: "Probe protocol. " + framework.OneOfMarkdown("tcp", "icmp"),
					Validators:          []validator.String{stringvalidator.OneOf("tcp", "icmp")},
				},
				"port": schema.Int64Attribute{
					Optional:            true,
					MarkdownDescription: "TCP port to probe.",
					Validators:          []validator.Int64{int64validator.Between(1, 65535)},
				},
				"interval": schema.Int64Attribute{
					Required:            true,
					MarkdownDescription: "Probe interval in seconds (5-65535).",
					Validators:          []validator.Int64{int64validator.Between(5, 65535)},
				},
				"timeout": schema.Int64Attribute{
					Required:            true,
					MarkdownDescription: "Probe timeout in seconds (1-10).",
					Validators:          []validator.Int64{int64validator.Between(1, 10)},
				},
				"retries": schema.Int64Attribute{
					Optional:            true,
					Computed:            true,
					MarkdownDescription: "Probe retries (1-10).",
					Validators:          []validator.Int64{int64validator.Between(1, 10)},
				},
			},
		},
		"source_nat_overrides": schema.ListNestedAttribute{
			Optional:            true,
			MarkdownDescription: "Per outbound interface overrides of `translated_source`.",
			Validators:          []validator.List{listvalidator.SizeAtLeast(1)},
			NestedObject: schema.NestedAttributeObject{
				Attributes: map[string]schema.Attribute{
					"interface": schema.StringAttribute{
						Required:            true,
						MarkdownDescription: "Name of the outbound interface.",
						Validators:          []validator.String{framework.ObjectName()},
					},
					"translated_source": sourceTranslationAttribute("Source translation used on this interface.", true),
				},
			},
		},
	}
	for k, v := range shared.PositionAttributes("NAT rule") {
		attrs[k] = v
	}
	return schema.Schema{
		MarkdownDescription: "Manages an IPv4 NAT rule (*Protect > Rules and policies > NAT rules*) for source NAT, " +
			"destination NAT / port forwarding and load balancing. Omitting a match criterion matches *any*.",
		Attributes: attrs,
	}
}

func expandSourceTranslation(t *translatedSource) *sourceTranslation {
	switch {
	case t == nil:
		return nil
	case t.Masquerade.ValueBool():
		return &sourceTranslation{Masq: true}
	default:
		return &sourceTranslation{IPv4Address: framework.Ref(t.IPv4Address)}
	}
}

func flattenSourceTranslation(t *sourceTranslation) *translatedSource {
	switch {
	case t == nil:
		return nil
	case t.Masq:
		return &translatedSource{Masquerade: types.BoolValue(true), IPv4Address: types.StringNull()}
	case t.IPv4Address != nil:
		return &translatedSource{Masquerade: types.BoolNull(), IPv4Address: framework.RefName(t.IPv4Address)}
	}
	return nil
}

func expandRule(ctx context.Context, m *ruleModel, diags *diag.Diagnostics) *rule {
	pos, refItem := m.position().API()
	r := &rule{
		Name:                        m.Name.ValueString(),
		Description:                 framework.StringPtr(m.Description),
		Enabled:                     framework.BoolPtr(m.Enabled),
		Position:                    pos,
		ReferenceItem:               refItem,
		LinkedFirewallRule:          framework.Ref(m.LinkedFirewallRule),
		OriginalSourceNetworks:      shared.ExpandNetworks(ctx, m.OriginalSourceNetworks, diags),
		OriginalDestinationNetworks: shared.ExpandNetworks(ctx, m.OriginalDestinationNetworks, diags),
		OriginalServicesOrGroups:    shared.ExpandServices(ctx, m.OriginalServices, m.OriginalServiceGroups, diags),
		InboundInterfaces:           shared.ExpandInterfaces(ctx, m.InboundInterfaces, diags),
		OutboundInterfaces:          shared.ExpandInterfaces(ctx, m.OutboundInterfaces, diags),
		TranslatedSource:            expandSourceTranslation(m.TranslatedSource),
		TranslatedService:           framework.Ref(m.TranslatedService),
		LoadBalancingMethod:         framework.StringPtr(m.LoadBalancingMethod),
		OverrideSNAT:                []snatOverride{},
	}
	if d := m.TranslatedDestination; d != nil {
		r.TranslatedDestination = &destinationTranslation{IPv4Address: framework.Ref(d.IPv4Address), FQDNAddress: framework.Ref(d.FQDNAddress)}
	}
	if h := m.HealthCheck; h != nil {
		hc := healthCheckRule{
			Protocol: h.Protocol.ValueString(),
			Interval: framework.Int64Ptr(h.Interval),
			Timeout:  framework.Int64Ptr(h.Timeout),
			Retry:    framework.Int64Ptr(h.Retries),
		}
		if p := framework.Int64Ptr(h.Port); p != nil {
			hc.Port = strconv.FormatInt(*p, 10)
		}
		r.HealthCheck = &healthCheck{Rule: hc}
	}
	for _, o := range m.SourceNATOverrides {
		r.OverrideSNAT = append(r.OverrideSNAT, snatOverride{
			OutboundInterface: sfos.NameRef{Name: o.Interface.ValueString()},
			TranslatedSource:  expandSourceTranslation(o.TranslatedSource),
		})
	}
	return r
}

func flattenRule(ctx context.Context, a *rule, prior *ruleModel, diags *diag.Diagnostics) *ruleModel {
	m := &ruleModel{
		ID:                          types.StringValue(a.ID),
		Name:                        types.StringValue(a.Name),
		Description:                 framework.StringOr(a.Description, ""),
		Enabled:                     framework.BoolOr(a.Enabled, true),
		Position:                    types.StringNull(),
		PositionReference:           types.StringNull(),
		LinkedFirewallRule:          framework.RefName(a.LinkedFirewallRule),
		OriginalSourceNetworks:      shared.FlattenNetworks(ctx, a.OriginalSourceNetworks, diags),
		OriginalDestinationNetworks: shared.FlattenNetworks(ctx, a.OriginalDestinationNetworks, diags),
		InboundInterfaces:           shared.FlattenInterfaces(ctx, a.InboundInterfaces, diags),
		OutboundInterfaces:          shared.FlattenInterfaces(ctx, a.OutboundInterfaces, diags),
		TranslatedSource:            flattenSourceTranslation(a.TranslatedSource),
		TranslatedService:           framework.RefName(a.TranslatedService),
		LoadBalancingMethod:         types.StringPointerValue(a.LoadBalancingMethod),
	}
	m.OriginalServices, m.OriginalServiceGroups = shared.FlattenServices(ctx, a.OriginalServicesOrGroups, diags)
	if m.LinkedFirewallRule.ValueString() == "none" {
		m.LinkedFirewallRule = types.StringNull()
	}
	if prior != nil {
		// Positions are write-only: keep what was configured.
		m.Position, m.PositionReference = prior.Position, prior.PositionReference
	}
	if d := a.TranslatedDestination; d != nil && (d.IPv4Address != nil || d.FQDNAddress != nil) {
		m.TranslatedDestination = &translatedDest{IPv4Address: framework.RefName(d.IPv4Address), FQDNAddress: framework.RefName(d.FQDNAddress)}
	}
	if h := a.HealthCheck; h != nil && h.Rule.Protocol != "" && framework.Managed(prior, func(p *ruleModel) bool { return p.HealthCheck != nil }) {
		hc := &healthCheckModel{
			Protocol: types.StringValue(h.Rule.Protocol),
			Port:     types.Int64Null(),
			Interval: types.Int64PointerValue(h.Rule.Interval),
			Timeout:  types.Int64PointerValue(h.Rule.Timeout),
			Retries:  types.Int64PointerValue(h.Rule.Retry),
		}
		if p, err := strconv.ParseInt(h.Rule.Port, 10, 64); err == nil && p > 0 {
			hc.Port = types.Int64Value(p)
		}
		m.HealthCheck = hc
	}
	for _, o := range a.OverrideSNAT {
		m.SourceNATOverrides = append(m.SourceNATOverrides, snatOverrideModel{
			Interface:        types.StringValue(o.OutboundInterface.Name),
			TranslatedSource: flattenSourceTranslation(o.TranslatedSource),
		})
	}
	return m
}
