// Package ips implements intrusion prevention (IPS) objects.
package ips

import (
	"context"
	"fmt"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfos"
)

// PoliciesPath is the IPS policy collection.
const PoliciesPath = "/intrusion-prevention/policies"

// Rule actions, verbatim from the API.
var actions = []string{"recommended", "allowPacket", "dropPacket", "disable", "dropSession", "reset", "bypassSession"}

// Signature sources, verbatim from the API.
var signatureSources = []string{"default", "custom"}

const (
	selectionFilter = "signatureFilter"
	selectionList   = "signatureList"

	// smartFilterKey is the filter attribute that matches text in signature names.
	smartFilterKey = "smartFilter"
)

// filterAttributes maps the dedicated filter attributes of a rule to the
// signature attribute keys of GET /intrusion-prevention/signature-attributes.
// Their order is the order in which filter rows are sent.
var filterAttributes = []struct{ tf, api string }{
	{"categories", "category"},
	{"severities", "severity"},
	{"platforms", "platform"},
	{"targets", "target"},
}

// ---- Terraform model ----

type policyModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Rules       []ruleModel  `tfsdk:"rules"`
}

type ruleModel struct {
	Name              types.String `tfsdk:"name"`
	Action            types.String `tfsdk:"action"`
	SignatureSource   types.String `tfsdk:"signature_source"`
	Categories        types.Set    `tfsdk:"categories"`
	Severities        types.Set    `tfsdk:"severities"`
	Platforms         types.Set    `tfsdk:"platforms"`
	Targets           types.Set    `tfsdk:"targets"`
	SmartFilter       types.Set    `tfsdk:"smart_filter"`
	AdditionalFilters types.Map    `tfsdk:"additional_filters"`
	Signatures        types.Set    `tfsdk:"signatures"`
}

// filterSets returns the dedicated filter sets in filterAttributes order.
func (r *ruleModel) filterSets() []types.Set {
	return []types.Set{r.Categories, r.Severities, r.Platforms, r.Targets}
}

func (r *ruleModel) setFilterSets(sets []types.Set) {
	r.Categories, r.Severities, r.Platforms, r.Targets = sets[0], sets[1], sets[2], sets[3]
}

// usesFilters reports whether any signature filter is configured.
func (r *ruleModel) usesFilters() bool {
	for _, s := range append(r.filterSets(), r.SmartFilter) {
		if !s.IsNull() {
			return true
		}
	}
	return !r.AdditionalFilters.IsNull()
}

// ---- API payload ----

type policy struct {
	ID          string  `json:"id,omitempty"`
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	Rules       []rule  `json:"rules"`
}

type rule struct {
	Name             string         `json:"name"`
	Action           string         `json:"action"`
	SignatureSource  string         `json:"signatureSource"`
	SelectionMode    string         `json:"selectionMode"`
	SignatureFilters []filterRow    `json:"signatureFilters,omitempty"`
	SignatureList    []sfos.NameRef `json:"signatureList,omitempty"`
}

type filterRow struct {
	Attribute string   `json:"attribute"`
	Operator  string   `json:"operator"`
	Values    []string `json:"values"`
}

// ---- Resource ----

// Policy manages /intrusion-prevention/policies.
var Policy = &framework.Resource[policyModel, policy]{
	Name:     "ips_policy",
	Title:    "IPS policy",
	Path:     PoliciesPath,
	Schema:   policySchema(),
	Validate: validatePolicy,
	Expand:   expandPolicy,
	Flatten:  flattenPolicy,
}

var setElem = types.SetType{ElemType: types.StringType}

func filterSet(description string) schema.SetAttribute {
	return schema.SetAttribute{
		Optional:            true,
		ElementType:         types.StringType,
		MarkdownDescription: description,
		Validators:          []validator.Set{setvalidator.SizeAtLeast(1), setvalidator.ValueStringsAre(stringvalidator.LengthAtLeast(1))},
	}
}

func policySchema() schema.Schema {
	reserved := []string{smartFilterKey}
	for _, f := range filterAttributes {
		reserved = append(reserved, f.api)
	}
	attributeValues := "The values are those listed for the attribute by `GET /intrusion-prevention/signature-attributes` " +
		"on the firewall and are passed through verbatim, as they depend on the installed signature pattern."

	return schema.Schema{
		MarkdownDescription: "Manages an intrusion prevention policy (*Protect > Intrusion prevention > IPS policies*). " +
			"A policy is an ordered list of rules; the first rule that selects a signature decides its action. " +
			"Attach a policy to traffic with `security_features.ips_policy` of a `sophosfirewall_firewall_rule`.",
		Attributes: map[string]schema.Attribute{
			"id":          framework.IDAttribute(),
			"name":        framework.NameAttribute("IPS policy", 60, true),
			"description": framework.DescriptionAttribute(255),
			"rules": schema.ListNestedAttribute{
				Required: true,
				MarkdownDescription: "Rules of the policy, evaluated in order. Each rule selects signatures either by " +
					"filters (`categories`, `severities`, `platforms`, `targets`, `smart_filter`, `additional_filters`; " +
					"a signature must match every configured filter) or by name (`signatures`), not both.",
				Validators: []validator.List{listvalidator.SizeAtLeast(1)},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "Name of the rule, unique within the policy.",
							Validators:          []validator.String{stringvalidator.LengthBetween(1, 60), framework.ObjectName()},
						},
						"action": schema.StringAttribute{
							Optional: true,
							Computed: true,
							Default:  stringdefault.StaticString("recommended"),
							MarkdownDescription: "Action for traffic matching a selected signature. `recommended` uses the " +
								"action Sophos recommends for each signature, `disable` turns the signatures off. " +
								framework.OneOfMarkdown(actions...) + " Defaults to `recommended`.",
							Validators: []validator.String{stringvalidator.OneOf(actions...)},
						},
						"signature_source": schema.StringAttribute{
							Optional: true,
							Computed: true,
							Default:  stringdefault.StaticString("default"),
							MarkdownDescription: "Signatures the rule selects from: the Sophos signature pattern (`default`) or " +
								"custom signatures (`custom`). " + framework.OneOfMarkdown(signatureSources...) + " Defaults to `default`.",
							Validators: []validator.String{stringvalidator.OneOf(signatureSources...)},
						},
						"categories": filterSet("Signature categories to select, e.g. `browser-ie`. " + attributeValues),
						"severities": filterSet("Signature severities to select, e.g. `Critical` or `Major`. " + attributeValues),
						"platforms":  filterSet("Platforms to select, e.g. `Windows` or `Linux`. " + attributeValues),
						"targets":    filterSet("Targets to select: `Client`, `Server` or both. " + attributeValues),
						"smart_filter": filterSet("Select signatures whose name contains any of these texts, e.g. `CVE-2021-44228` " +
							"(*Smart filter* in the web admin console)."),
						"additional_filters": schema.MapAttribute{
							Optional:    true,
							ElementType: setElem,
							MarkdownDescription: "Filters on further signature attributes, as a map from attribute key to the values to select, " +
								"for attributes the firewall lists beyond category, severity, platform and target. " +
								"Use the dedicated attributes for those.",
							Validators: []validator.Map{
								mapvalidator.SizeAtLeast(1),
								mapvalidator.KeysAre(stringvalidator.LengthAtLeast(1), stringvalidator.NoneOf(reserved...)),
								mapvalidator.ValueSetsAre(setvalidator.SizeAtLeast(1), setvalidator.ValueStringsAre(stringvalidator.LengthAtLeast(1))),
							},
						},
						"signatures": schema.SetAttribute{
							Optional:    true,
							ElementType: types.StringType,
							MarkdownDescription: "Names of individual signatures to select, e.g. " +
								"`SERVER-ORACLE Oracle WebLogic Server CVE-2018-2894`. Conflicts with the filter attributes.",
							Validators: []validator.Set{setvalidator.SizeAtLeast(1), setvalidator.ValueStringsAre(stringvalidator.LengthAtLeast(1))},
						},
					},
				},
			},
		},
	}
}

func validatePolicy(_ context.Context, m *policyModel, diags *diag.Diagnostics) {
	seen := map[string]bool{}
	for i, r := range m.Rules {
		p := path.Root("rules").AtListIndex(i)
		if !r.Name.IsUnknown() && !r.Name.IsNull() {
			if seen[r.Name.ValueString()] {
				diags.AddAttributeError(p.AtName("name"), "Duplicate rule name",
					fmt.Sprintf("Rule names must be unique within a policy; %q is used more than once.", r.Name.ValueString()))
			}
			seen[r.Name.ValueString()] = true
		}
		unknown := r.Signatures.IsUnknown() || r.AdditionalFilters.IsUnknown() || r.SmartFilter.IsUnknown()
		for _, s := range r.filterSets() {
			unknown = unknown || s.IsUnknown()
		}
		if unknown {
			continue
		}
		switch {
		case r.usesFilters() && !r.Signatures.IsNull():
			diags.AddAttributeError(p.AtName("signatures"), "Conflicting signature selection",
				"A rule selects signatures either by filters or by name: set `signatures` or the filter attributes, not both.")
		case !r.usesFilters() && r.Signatures.IsNull():
			diags.AddAttributeError(p, "Missing signature selection",
				"Set `signatures` or at least one of `categories`, `severities`, `platforms`, `targets`, `smart_filter` or `additional_filters`.")
		}
	}
}

func sortedStrings(ctx context.Context, s types.Set, diags *diag.Diagnostics) []string {
	v := framework.Strings(ctx, s, diags)
	sort.Strings(v)
	return v
}

func expandPolicy(ctx context.Context, m *policyModel, diags *diag.Diagnostics) *policy {
	p := &policy{
		Name:        m.Name.ValueString(),
		Description: framework.StringPtr(m.Description),
		Rules:       make([]rule, 0, len(m.Rules)),
	}
	for _, rm := range m.Rules {
		r := rule{
			Name:            rm.Name.ValueString(),
			Action:          rm.Action.ValueString(),
			SignatureSource: rm.SignatureSource.ValueString(),
			SelectionMode:   selectionFilter,
		}
		if r.Action == "" {
			r.Action = "recommended"
		}
		if r.SignatureSource == "" {
			r.SignatureSource = "default"
		}
		if !rm.Signatures.IsNull() && !rm.Signatures.IsUnknown() {
			r.SelectionMode = selectionList
			for _, n := range sortedStrings(ctx, rm.Signatures, diags) {
				r.SignatureList = append(r.SignatureList, sfos.NameRef{Name: n})
			}
			p.Rules = append(p.Rules, r)
			continue
		}
		add := func(attribute string, values []string) {
			if len(values) > 0 {
				r.SignatureFilters = append(r.SignatureFilters, filterRow{Attribute: attribute, Operator: "in", Values: values})
			}
		}
		for i, s := range rm.filterSets() {
			add(filterAttributes[i].api, sortedStrings(ctx, s, diags))
		}
		if !rm.AdditionalFilters.IsNull() && !rm.AdditionalFilters.IsUnknown() {
			var extra map[string]types.Set
			diags.Append(rm.AdditionalFilters.ElementsAs(ctx, &extra, false)...)
			keys := make([]string, 0, len(extra))
			for k := range extra {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				add(k, sortedStrings(ctx, extra[k], diags))
			}
		}
		add(smartFilterKey, sortedStrings(ctx, rm.SmartFilter, diags))
		p.Rules = append(p.Rules, r)
	}
	return p
}

func flattenPolicy(ctx context.Context, a *policy, _ *policyModel, diags *diag.Diagnostics) *policyModel {
	m := &policyModel{
		ID:          types.StringValue(a.ID),
		Name:        types.StringValue(a.Name),
		Description: framework.StringOr(a.Description, ""),
	}
	for _, r := range a.Rules {
		m.Rules = append(m.Rules, flattenRule(ctx, r, diags))
	}
	return m
}

func flattenRule(ctx context.Context, r rule, diags *diag.Diagnostics) ruleModel {
	rm := ruleModel{
		Name:              types.StringValue(r.Name),
		Action:            types.StringValue(r.Action),
		SignatureSource:   types.StringValue(r.SignatureSource),
		SmartFilter:       types.SetNull(types.StringType),
		AdditionalFilters: types.MapNull(setElem),
		Signatures:        types.SetNull(types.StringType),
	}
	// Rows are grouped by attribute; repeated rows for one attribute are merged.
	values := map[string][]string{}
	var order []string
	if r.SelectionMode != selectionList {
		for _, f := range r.SignatureFilters {
			if _, ok := values[f.Attribute]; !ok {
				order = append(order, f.Attribute)
			}
			values[f.Attribute] = append(values[f.Attribute], f.Values...)
		}
	}
	sets := make([]types.Set, len(filterAttributes))
	for i, f := range filterAttributes {
		sets[i] = framework.StringSet(ctx, values[f.api], diags)
		delete(values, f.api)
	}
	rm.setFilterSets(sets)
	rm.SmartFilter = framework.StringSet(ctx, values[smartFilterKey], diags)
	delete(values, smartFilterKey)

	extra := map[string]attr.Value{}
	for _, k := range order {
		if v, ok := values[k]; ok && len(v) > 0 {
			extra[k] = framework.StringSet(ctx, v, diags)
		}
	}
	if len(extra) > 0 {
		mv, d := types.MapValue(setElem, extra)
		diags.Append(d...)
		rm.AdditionalFilters = mv
	}

	if r.SelectionMode == selectionList {
		rm.Signatures = framework.RefSet(ctx, r.SignatureList, diags)
	}
	return rm
}
