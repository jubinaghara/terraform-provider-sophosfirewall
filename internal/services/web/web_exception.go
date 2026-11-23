package web

import (
	"context"
	"fmt"
	"net/netip"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfos"
)

// ---- Terraform model ----

type exceptionModel struct {
	ID          types.String              `tfsdk:"id"`
	Name        types.String              `tfsdk:"name"`
	Description types.String              `tfsdk:"description"`
	Enabled     types.Bool                `tfsdk:"enabled"`
	Conditions  *exceptionConditionsModel `tfsdk:"conditions"`
	Skip        *exceptionSkipModel       `tfsdk:"skip"`
}

type exceptionConditionsModel struct {
	URLRegexes          types.Set `tfsdk:"url_regexes"`
	WebCategories       types.Set `tfsdk:"web_categories"`
	SourceNetworks      types.Set `tfsdk:"source_networks"`
	DestinationNetworks types.Set `tfsdk:"destination_networks"`
}

type exceptionSkipModel struct {
	HTTPSDecryption       types.Bool `tfsdk:"https_decryption"`
	CertificateValidation types.Bool `tfsdk:"certificate_validation"`
	MalwareScanning       types.Bool `tfsdk:"malware_scanning"`
	ZeroDayProtection     types.Bool `tfsdk:"zero_day_protection"`
	PolicyCheck           types.Bool `tfsdk:"policy_check"`
}

// ---- API payload ----

type exception struct {
	ID          string               `json:"id,omitempty"`
	Name        string               `json:"name"`
	Description *string              `json:"description,omitempty"`
	Enabled     *bool                `json:"enabled,omitempty"`
	Conditions  *exceptionConditions `json:"conditions,omitempty"`
	Skip        *exceptionSkip       `json:"skip,omitempty"`
}

// exceptionConditions holds the four match criteria. Each one is switched
// on or off with its own enabled flag; enabled criteria are ANDed.
type exceptionConditions struct {
	SourceNetworks      *ipCondition                   `json:"sourceIpOrNetworks,omitempty"`
	DestinationNetworks *ipCondition                   `json:"destinationIpOrNetworks,omitempty"`
	URLRegexes          *valuesCondition[string]       `json:"urlRegexPatterns,omitempty"`
	WebCategories       *valuesCondition[sfos.NameRef] `json:"webCategories,omitempty"`
}

type ipCondition struct {
	Enabled bool          `json:"enabled"`
	IPv4    []ipv4Network `json:"ipv4Networks"`
	IPv6    []ipv6Network `json:"ipv6Networks"`
}

type ipv4Network struct {
	Address string `json:"ipv4Address"`
	CIDR    *int   `json:"cidr,omitempty"`
}

type ipv6Network struct {
	Address      string `json:"ipv6Address"`
	PrefixLength *int   `json:"prefixLength,omitempty"`
}

type valuesCondition[T any] struct {
	Enabled bool `json:"enabled"`
	Values  []T  `json:"values"`
}

type exceptionSkip struct {
	HTTPSDecryption       *bool `json:"httpsDecryption,omitempty"`
	CertificateValidation *bool `json:"certificateValidation,omitempty"`
	MalwareScanning       *bool `json:"malwareScanning,omitempty"`
	ZeroDayProtection     *bool `json:"zeroDayProtection,omitempty"`
	PolicyCheck           *bool `json:"policyCheck,omitempty"`
}

// Exception manages /web/exceptions.
var Exception = &framework.Resource[exceptionModel, exception]{
	Name:     "web_exception",
	Title:    "web exception",
	Path:     "/web/exceptions",
	Schema:   exceptionSchema(),
	Validate: validateException,
	Expand:   expandException,
	Flatten:  flattenException,
}

func exceptionSchema() schema.Schema {
	flag := framework.BoolDefault
	networks := func(side, host string) schema.SetAttribute {
		return schema.SetAttribute{
			Optional:    true,
			ElementType: types.StringType,
			MarkdownDescription: fmt.Sprintf("%s IPv4 or IPv6 networks in CIDR notation, e.g. `192.0.2.0/24`, `2001:db8::/32`, "+
				"or `192.0.2.10/32` for a single host. Omit to match any %s address.", side, host),
			Validators: []validator.Set{setvalidator.SizeAtLeast(1), setvalidator.ValueStringsAre(anyPrefix())},
		}
	}
	return schema.Schema{
		MarkdownDescription: "Manages a web filter exception (*Protect > Web > Exceptions*). Traffic that matches all " +
			"configured `conditions` bypasses the checks selected in `skip`, e.g. HTTPS decryption for banking sites " +
			"or malware scanning for a trusted update server.",
		Attributes: map[string]schema.Attribute{
			"id":          framework.IDAttribute(),
			"name":        framework.NameAttribute("web exception", 60, false),
			"description": framework.DescriptionAttribute(250),
			"enabled":     flag("Whether the exception is active.", true),
			"conditions": schema.SingleNestedAttribute{
				Required: true,
				MarkdownDescription: "Traffic the exception applies to. At least one condition must be set. A request must " +
					"match every condition that is set (AND) and any one entry within a condition (OR). " +
					"Omitted conditions are switched off on the firewall.",
				Attributes: map[string]schema.Attribute{
					"url_regexes": schema.SetAttribute{
						Optional:    true,
						ElementType: types.StringType,
						MarkdownDescription: "Regular expressions matched against the request URL, e.g. " +
							"`^([A-Za-z0-9.-]*\\.)?example\\.com/`. Omit to match any URL.",
						Validators: []validator.Set{
							setvalidator.SizeAtLeast(1),
							setvalidator.ValueStringsAre(stringvalidator.LengthBetween(1, 2048)),
						},
					},
					"web_categories": schema.SetAttribute{
						Optional:            true,
						ElementType:         types.StringType,
						MarkdownDescription: "Names of web categories, e.g. `Banking`. Omit to match any category.",
						Validators: []validator.Set{
							setvalidator.SizeAtLeast(1),
							setvalidator.ValueStringsAre(stringvalidator.LengthBetween(1, 60), framework.ObjectName()),
						},
					},
					"source_networks":      networks("Client (source)", "client"),
					"destination_networks": networks("Server (destination)", "server"),
				},
			},
			"skip": schema.SingleNestedAttribute{
				Optional: true,
				MarkdownDescription: "Checks bypassed for matching traffic. Omit the block to skip nothing; the " +
					"firewall's skip settings are then not tracked, so changes made elsewhere are not reported as drift.",
				Attributes: map[string]schema.Attribute{
					"https_decryption":       flag("Skip HTTPS decryption.", false),
					"certificate_validation": flag("Skip HTTPS certificate validation. Must be true when `https_decryption` is true.", false),
					"malware_scanning":       flag("Skip malware and content scanning.", false),
					"zero_day_protection":    flag("Skip zero-day protection (Sandstorm) analysis.", false),
					"policy_check":           flag("Skip the web policy check, i.e. allow the request whatever the web policy says.", false),
				},
			},
		},
	}
}

func validateException(_ context.Context, m *exceptionModel, diags *diag.Diagnostics) {
	// The firewall cannot validate certificates of traffic it does not
	// decrypt: skipping HTTPS decryption always skips validation too.
	if sk := m.Skip; sk != nil && sk.HTTPSDecryption.ValueBool() && !sk.CertificateValidation.IsUnknown() && !sk.CertificateValidation.ValueBool() {
		diags.AddAttributeError(path.Root("skip").AtName("certificate_validation"), "Certificate validation must be skipped",
			"The firewall always skips certificate validation when HTTPS decryption is skipped. Set certificate_validation = true.")
	}
	c := m.Conditions
	if c == nil {
		return
	}
	for _, s := range []types.Set{c.URLRegexes, c.WebCategories, c.SourceNetworks, c.DestinationNetworks} {
		if !s.IsNull() {
			return
		}
	}
	diags.AddAttributeError(path.Root("conditions"), "Missing condition",
		"Set at least one of url_regexes, web_categories, source_networks or destination_networks.")
}

func expandException(ctx context.Context, m *exceptionModel, diags *diag.Diagnostics) *exception {
	a := &exception{
		Name:        m.Name.ValueString(),
		Description: framework.StringPtr(m.Description),
		Enabled:     framework.BoolPtr(m.Enabled),
	}
	if c := m.Conditions; c != nil {
		// Every condition is always sent: an omitted one is switched off
		// with empty lists, so removing it from the configuration clears it.
		urls := framework.Strings(ctx, c.URLRegexes, diags)
		if urls == nil {
			urls = []string{}
		}
		a.Conditions = &exceptionConditions{
			SourceNetworks:      expandIPCondition(ctx, c.SourceNetworks, diags),
			DestinationNetworks: expandIPCondition(ctx, c.DestinationNetworks, diags),
			URLRegexes:          &valuesCondition[string]{Enabled: !c.URLRegexes.IsNull(), Values: urls},
			WebCategories:       &valuesCondition[sfos.NameRef]{Enabled: !c.WebCategories.IsNull(), Values: framework.Refs(ctx, c.WebCategories, diags)},
		}
	}
	// An omitted skip block is sent as "skip nothing" rather than left out:
	// dropping the block from the configuration would otherwise produce
	// "skip": null in the merge patch.
	s := m.Skip
	if s == nil {
		f := types.BoolValue(false)
		s = &exceptionSkipModel{HTTPSDecryption: f, CertificateValidation: f, MalwareScanning: f, ZeroDayProtection: f, PolicyCheck: f}
	}
	a.Skip = &exceptionSkip{
		HTTPSDecryption:       framework.BoolPtr(s.HTTPSDecryption),
		CertificateValidation: framework.BoolPtr(s.CertificateValidation),
		MalwareScanning:       framework.BoolPtr(s.MalwareScanning),
		ZeroDayProtection:     framework.BoolPtr(s.ZeroDayProtection),
		PolicyCheck:           framework.BoolPtr(s.PolicyCheck),
	}
	return a
}

func expandIPCondition(ctx context.Context, v types.Set, diags *diag.Diagnostics) *ipCondition {
	c := &ipCondition{Enabled: !v.IsNull(), IPv4: []ipv4Network{}, IPv6: []ipv6Network{}}
	for _, s := range framework.Strings(ctx, v, diags) {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			diags.AddError("Invalid network", fmt.Sprintf("%q is not a network in CIDR notation: %s", s, err))
			continue
		}
		bits := p.Bits()
		if p.Addr().Is4() {
			c.IPv4 = append(c.IPv4, ipv4Network{Address: p.Addr().String(), CIDR: &bits})
		} else {
			c.IPv6 = append(c.IPv6, ipv6Network{Address: p.Addr().String(), PrefixLength: &bits})
		}
	}
	return c
}

func flattenException(ctx context.Context, a *exception, prior *exceptionModel, diags *diag.Diagnostics) *exceptionModel {
	m := &exceptionModel{
		ID:          types.StringValue(a.ID),
		Name:        types.StringValue(a.Name),
		Description: framework.StringOr(a.Description, ""),
		Enabled:     framework.BoolOr(a.Enabled, true),
		Conditions: &exceptionConditionsModel{
			URLRegexes:          types.SetNull(types.StringType),
			WebCategories:       types.SetNull(types.StringType),
			SourceNetworks:      types.SetNull(types.StringType),
			DestinationNetworks: types.SetNull(types.StringType),
		},
	}
	// Switched-off conditions are null, whatever values the firewall keeps.
	if c := a.Conditions; c != nil {
		if u := c.URLRegexes; u != nil && u.Enabled {
			m.Conditions.URLRegexes = framework.StringSet(ctx, u.Values, diags)
		}
		if w := c.WebCategories; w != nil && w.Enabled {
			m.Conditions.WebCategories = framework.RefSet(ctx, w.Values, diags)
		}
		m.Conditions.SourceNetworks = flattenIPCondition(ctx, c.SourceNetworks, diags)
		m.Conditions.DestinationNetworks = flattenIPCondition(ctx, c.DestinationNetworks, diags)
	}
	if s := a.Skip; s != nil && framework.Managed(prior, func(p *exceptionModel) bool { return p.Skip != nil }) {
		m.Skip = &exceptionSkipModel{
			HTTPSDecryption:       framework.BoolOr(s.HTTPSDecryption, false),
			CertificateValidation: framework.BoolOr(s.CertificateValidation, false),
			MalwareScanning:       framework.BoolOr(s.MalwareScanning, false),
			ZeroDayProtection:     framework.BoolOr(s.ZeroDayProtection, false),
			PolicyCheck:           framework.BoolOr(s.PolicyCheck, false),
		}
	}
	return m
}

func flattenIPCondition(ctx context.Context, c *ipCondition, diags *diag.Diagnostics) types.Set {
	if c == nil || !c.Enabled {
		return types.SetNull(types.StringType)
	}
	var out []string
	for _, n := range c.IPv4 {
		out = append(out, fmt.Sprintf("%s/%d", n.Address, intOr(n.CIDR, 32)))
	}
	for _, n := range c.IPv6 {
		// Re-format so that the firewall's spelling of the address
		// (e.g. leading zeros) does not show up as drift.
		addr := n.Address
		if a, err := netip.ParseAddr(addr); err == nil {
			addr = a.String()
		}
		out = append(out, fmt.Sprintf("%s/%d", addr, intOr(n.PrefixLength, 128)))
	}
	sort.Strings(out)
	return framework.StringSet(ctx, out, diags)
}

func intOr(p *int, def int) int {
	if p == nil {
		return def
	}
	return *p
}

// anyPrefix validates a canonical IPv4 or IPv6 network in CIDR notation.
type prefixValidator struct{}

func anyPrefix() validator.String { return prefixValidator{} }

func (prefixValidator) Description(context.Context) string {
	return "must be an IPv4 or IPv6 network in CIDR notation"
}

func (v prefixValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (prefixValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	s := req.ConfigValue.ValueString()
	p, err := netip.ParsePrefix(s)
	switch {
	case err != nil || p.Addr().Zone() != "":
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid value",
			fmt.Sprintf("%q is not an IPv4 or IPv6 network in CIDR notation, e.g. 192.0.2.0/24 or 192.0.2.10/32", s))
	case p.Addr().Is4In6():
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid value", fmt.Sprintf("%q: write IPv4 networks in dotted notation", s))
	case p.Masked().String() != s:
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid value",
			fmt.Sprintf("%q must be the canonical network address %q", s, p.Masked().String()))
	}
}
