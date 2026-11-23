// Package application implements application control objects such as
// application filter policies.
package application

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

const (
	selectionFilter = "applicationFilter"
	selectionList   = "applicationList"
	// defaultSchedule is the built-in schedule that is always active.
	defaultSchedule = "All The Time"
	// cloudApplication is the characteristics value the firewall adds to a
	// rule that filters by classification.
	cloudApplication = "Cloud Application"
)

// Actions are the actions of an application filter policy rule.
var Actions = []string{"allow", "deny"}

// filterAttribute maps a typed rule attribute to the API filter attribute key.
type filterAttribute struct {
	tf, api, description string
}

// filterAttributes are the well-known filter attributes, in the order the
// rows are sent. Values are not validated: the firewall defines them and
// lists them under GET /application/attributes.
var filterAttributes = []filterAttribute{
	{"categories", "category", "Application categories to match, e.g. `P2P`, `Proxy and Tunnel` or `General Business`."},
	{"risks", "risk", "Risk levels to match, as listed by the firewall for the `risk` attribute."},
	{"characteristics", "characteristics", "Characteristics to match, e.g. `Can bypass firewall policy`, `Bandwidth Intensive` or `Widely Used`."},
	{"technologies", "technology", "Technologies to match, e.g. `Browser Based` or `Client Server`."},
	{"classifications", "classification", "Cloud application classifications to match, e.g. `Sanctioned`. " +
		"A classification filter only matches cloud applications: the firewall adds a `characteristics` " +
		"filter with `Cloud Application` to the rule, which is not reported as drift when `characteristics` is not configured."},
	{"smart_filters", "smartFilter", "Smart search expressions to match application names against, e.g. `live`."},
}

// ---- Terraform model ----

type policyModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Rules       []ruleModel  `tfsdk:"rules"`
}

type ruleModel struct {
	Name            types.String `tfsdk:"name"`
	Action          types.String `tfsdk:"action"`
	Schedule        types.String `tfsdk:"schedule"`
	Applications    types.Set    `tfsdk:"applications"`
	Categories      types.Set    `tfsdk:"categories"`
	Risks           types.Set    `tfsdk:"risks"`
	Characteristics types.Set    `tfsdk:"characteristics"`
	Technologies    types.Set    `tfsdk:"technologies"`
	Classifications types.Set    `tfsdk:"classifications"`
	SmartFilters    types.Set    `tfsdk:"smart_filters"`
	OtherFilters    types.Map    `tfsdk:"other_filters"`
}

// filterSets returns pointers to the typed filter sets in filterAttributes order.
func (r *ruleModel) filterSets() []*types.Set {
	return []*types.Set{&r.Categories, &r.Risks, &r.Characteristics, &r.Technologies, &r.Classifications, &r.SmartFilters}
}

// ---- API payload ----

type policy struct {
	ID          string       `json:"id,omitempty"`
	Name        string       `json:"name"`
	Description *string      `json:"description,omitempty"`
	Rules       []policyRule `json:"rules,omitempty"`
}

type policyRule struct {
	Name               string        `json:"name"`
	SelectionMode      string        `json:"selectionMode"`
	ApplicationFilters []filterRow   `json:"applicationFilters,omitempty"`
	ApplicationList    []string      `json:"applicationList,omitempty"`
	Action             string        `json:"action"`
	Schedule           *sfos.NameRef `json:"schedule,omitempty"`
}

type filterRow struct {
	Attribute string   `json:"attribute"`
	Operator  string   `json:"operator"`
	Values    []string `json:"values"`
}

// ---- Resource ----

var stringSetType = types.SetType{ElemType: types.StringType}

// FilterPolicy manages /application/policies.
var FilterPolicy = &framework.Resource[policyModel, policy]{
	Name:     "application_filter_policy",
	Title:    "application filter policy",
	Path:     "/application/policies",
	Schema:   policySchema(),
	Expand:   expandPolicy,
	Flatten:  flattenPolicy,
	Validate: validatePolicy,
}

func valueSetAttribute(description string) schema.SetAttribute {
	return schema.SetAttribute{
		Optional:            true,
		ElementType:         types.StringType,
		MarkdownDescription: description,
		Validators: []validator.Set{
			setvalidator.SizeAtLeast(1),
			setvalidator.ValueStringsAre(stringvalidator.LengthAtLeast(1)),
		},
	}
}

func policySchema() schema.Schema {
	ruleAttrs := map[string]schema.Attribute{
		"name": schema.StringAttribute{
			Required:            true,
			MarkdownDescription: "Name of the rule, unique within the policy.",
			Validators:          []validator.String{stringvalidator.LengthBetween(1, 60), framework.ObjectName()},
		},
		"action": schema.StringAttribute{
			Required:            true,
			MarkdownDescription: "Action for matching applications. " + framework.OneOfMarkdown(Actions...),
			Validators:          []validator.String{stringvalidator.OneOf(Actions...)},
		},
		"schedule": schema.StringAttribute{
			Optional:            true,
			Computed:            true,
			Default:             stringdefault.StaticString(defaultSchedule),
			MarkdownDescription: "Name of the schedule during which the rule applies. Defaults to `" + defaultSchedule + "`.",
			Validators:          []validator.String{stringvalidator.LengthBetween(1, 60), framework.ObjectName()},
		},
		"applications": schema.SetAttribute{
			Optional:    true,
			ElementType: types.StringType,
			MarkdownDescription: "Individual applications to match by name, e.g. `Discord` or `Microsoft Teams` " +
				"(see *Protect > Applications > Application list* or GET /application/apps). " +
				"Conflicts with the filter attributes.",
			Validators: []validator.Set{
				setvalidator.SizeAtLeast(1),
				setvalidator.ValueStringsAre(stringvalidator.LengthAtLeast(1)),
			},
		},
		"other_filters": schema.MapAttribute{
			Optional:    true,
			ElementType: stringSetType,
			MarkdownDescription: "Additional filters keyed by API attribute name, for attributes the firewall " +
				"supports beyond the ones above. Each value is the set of attribute values to match.",
			Validators: []validator.Map{
				mapvalidator.SizeAtLeast(1),
				mapvalidator.KeysAre(stringvalidator.LengthAtLeast(1)),
				mapvalidator.ValueSetsAre(setvalidator.SizeAtLeast(1)),
			},
		},
	}
	for _, f := range filterAttributes {
		ruleAttrs[f.tf] = valueSetAttribute(f.description)
	}
	return schema.Schema{
		MarkdownDescription: "Manages an application filter policy (*Protect > Applications > Application filter*). " +
			"Firewall rules apply a policy through `security_features.application_policy`. Rules are evaluated " +
			"top to bottom, so their order matters. Each rule matches either a list of individual `applications` " +
			"or applications selected by filters: `categories`, `risks`, `characteristics`, `technologies`, " +
			"`classifications`, `smart_filters` and `other_filters`. Within a filter any value matches; " +
			"the firewall lists valid values under *Protect > Applications* and GET /application/attributes.",
		Attributes: map[string]schema.Attribute{
			"id":          framework.IDAttribute(),
			"name":        framework.NameAttribute("application filter policy", 60, true),
			"description": framework.DescriptionAttribute(1000),
			"rules": schema.ListNestedAttribute{
				Required:            true,
				MarkdownDescription: "Ordered policy rules (at least one). Changes replace the whole rule set.",
				Validators:          []validator.List{listvalidator.SizeAtLeast(1)},
				NestedObject:        schema.NestedAttributeObject{Attributes: ruleAttrs},
			},
		},
	}
}

func validatePolicy(ctx context.Context, m *policyModel, diags *diag.Diagnostics) {
	names := map[string]bool{}
	for i := range m.Rules {
		r := &m.Rules[i]
		p := path.Root("rules").AtListIndex(i)
		if known(r.Name) {
			if names[r.Name.ValueString()] {
				diags.AddAttributeError(p.AtName("name"), "Duplicate rule name",
					fmt.Sprintf("Rule name %q is used more than once in the policy.", r.Name.ValueString()))
			}
			names[r.Name.ValueString()] = true
		}
		hasFilter, unknown := false, r.Applications.IsUnknown() || r.OtherFilters.IsUnknown()
		for _, s := range r.filterSets() {
			hasFilter = hasFilter || !s.IsNull()
			unknown = unknown || s.IsUnknown()
		}
		hasFilter = hasFilter || !r.OtherFilters.IsNull()
		hasApps := !r.Applications.IsNull()
		switch {
		case hasApps && hasFilter:
			diags.AddAttributeError(p.AtName("applications"), "Conflicting selection",
				"A rule matches either individual applications or filters: set `applications` or the filter attributes, not both.")
		case !hasApps && !hasFilter && !unknown:
			diags.AddAttributeError(p, "Missing selection",
				"Set `applications` or at least one filter attribute (`categories`, `risks`, `characteristics`, "+
					"`technologies`, `classifications`, `smart_filters` or `other_filters`).")
		}
		if known := !r.OtherFilters.IsNull() && !r.OtherFilters.IsUnknown(); known {
			for k := range r.OtherFilters.Elements() {
				if f := typedFilter(k); f != nil {
					diags.AddAttributeError(p.AtName("other_filters"), "Invalid filter attribute",
						fmt.Sprintf("Use the `%s` attribute instead of other_filters[%q].", f.tf, k))
				}
			}
		}
	}
}

func known(v types.String) bool { return !v.IsNull() && !v.IsUnknown() }

func typedFilter(apiName string) *filterAttribute {
	for i := range filterAttributes {
		if filterAttributes[i].api == apiName {
			return &filterAttributes[i]
		}
	}
	return nil
}

func expandPolicy(ctx context.Context, m *policyModel, diags *diag.Diagnostics) *policy {
	p := &policy{
		Name:        m.Name.ValueString(),
		Description: framework.StringPtr(m.Description),
		Rules:       make([]policyRule, 0, len(m.Rules)),
	}
	for i := range m.Rules {
		r := &m.Rules[i]
		out := policyRule{
			Name:     r.Name.ValueString(),
			Action:   r.Action.ValueString(),
			Schedule: framework.Ref(r.Schedule),
		}
		if !r.Applications.IsNull() {
			out.SelectionMode = selectionList
			out.ApplicationList = sortedStrings(ctx, r.Applications, diags)
		} else {
			out.SelectionMode = selectionFilter
			for j, s := range r.filterSets() {
				if values := sortedStrings(ctx, *s, diags); len(values) > 0 {
					out.ApplicationFilters = append(out.ApplicationFilters, filterRow{Attribute: filterAttributes[j].api, Operator: "in", Values: values})
				}
			}
			out.ApplicationFilters = append(out.ApplicationFilters, expandOtherFilters(ctx, r.OtherFilters, diags)...)
		}
		p.Rules = append(p.Rules, out)
	}
	return p
}

func sortedStrings(ctx context.Context, v types.Set, diags *diag.Diagnostics) []string {
	s := framework.Strings(ctx, v, diags)
	sort.Strings(s)
	return s
}

func expandOtherFilters(ctx context.Context, v types.Map, diags *diag.Diagnostics) []filterRow {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	var filters map[string]types.Set
	diags.Append(v.ElementsAs(ctx, &filters, false)...)
	keys := make([]string, 0, len(filters))
	for k := range filters {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var rows []filterRow
	for _, k := range keys {
		rows = append(rows, filterRow{Attribute: k, Operator: "in", Values: sortedStrings(ctx, filters[k], diags)})
	}
	return rows
}

func flattenPolicy(ctx context.Context, a *policy, prior *policyModel, diags *diag.Diagnostics) *policyModel {
	m := &policyModel{
		ID:          types.StringValue(a.ID),
		Name:        types.StringValue(a.Name),
		Description: framework.StringOr(a.Description, ""),
	}
	for i, r := range a.Rules {
		var priorRule *ruleModel
		if prior != nil && i < len(prior.Rules) {
			priorRule = &prior.Rules[i]
		}
		m.Rules = append(m.Rules, flattenRule(ctx, r, priorRule, diags))
	}
	return m
}

func flattenRule(ctx context.Context, r policyRule, prior *ruleModel, diags *diag.Diagnostics) ruleModel {
	out := ruleModel{
		Name:         types.StringValue(r.Name),
		Action:       types.StringValue(r.Action),
		Schedule:     types.StringValue(defaultSchedule),
		Applications: types.SetNull(types.StringType),
		OtherFilters: types.MapNull(stringSetType),
	}
	if r.Schedule != nil && r.Schedule.Name != "" {
		out.Schedule = types.StringValue(r.Schedule.Name)
	}
	for _, s := range out.filterSets() {
		*s = types.SetNull(types.StringType)
	}
	if r.SelectionMode == selectionList {
		out.Applications = framework.StringSet(ctx, r.ApplicationList, diags)
		return out
	}

	// Merge rows per attribute; the order of filter rows carries no meaning.
	values := map[string][]string{}
	for _, row := range r.ApplicationFilters {
		values[row.Attribute] = append(values[row.Attribute], row.Values...)
	}
	// A classification filter makes the firewall add characteristics
	// "Cloud Application"; hide it unless the user manages characteristics
	// (on import and in data sources, prior is nil and the row is kept).
	if c := values["characteristics"]; len(values["classification"]) > 0 && len(c) == 1 && c[0] == cloudApplication &&
		prior != nil && prior.Characteristics.IsNull() {
		delete(values, "characteristics")
	}
	sets := out.filterSets()
	for j, f := range filterAttributes {
		*sets[j] = framework.StringSet(ctx, dedupe(values[f.api]), diags)
		delete(values, f.api)
	}
	if len(values) > 0 {
		elems := map[string]attr.Value{}
		for k, v := range values {
			elems[k] = framework.StringSet(ctx, dedupe(v), diags)
		}
		mv, d := types.MapValue(stringSetType, elems)
		diags.Append(d...)
		out.OtherFilters = mv
	}
	return out
}

func dedupe(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
