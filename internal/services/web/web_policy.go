package web

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfos"
)

const (
	// AllTheTime is the built-in schedule a rule applies with when none is chosen.
	AllTheTime = "All The Time"
	// defaultMaxFileSize is sent when max_file_size is not configured; the
	// API requires a value even when the size restriction is off.
	defaultMaxFileSize = 300
	// Limits of the comma-joined strings the firewall stores the lists in.
	maxGoogleDomainsLen    = 256
	maxOffice365TenantsLen = 4096
)

var (
	policyActions = []string{"allow", "deny"}
	ruleActions   = []string{"allow", "deny", "warn", "log", "quota"}
	youtubeLevels = []string{"off", "moderate", "strict"}

	// domainRe is the API's pattern for Google app domains and Microsoft 365 tenants.
	domainRe      = regexp.MustCompile(`^[a-zA-Z0-9]([.]?[a-zA-Z0-9]|-)*[a-zA-Z0-9]$`)
	directoryIDRe = regexp.MustCompile(`^[a-zA-Z0-9-]*$`)
)

// ---- Terraform model ----

type webPolicyModel struct {
	ID                       types.String   `tfsdk:"id"`
	Name                     types.String   `tfsdk:"name"`
	Description              types.String   `tfsdk:"description"`
	DefaultAction            types.String   `tfsdk:"default_action"`
	Reporting                types.Bool     `tfsdk:"reporting"`
	RestrictFileSize         types.Bool     `tfsdk:"restrict_file_size"`
	MaxFileSize              types.Int64    `tfsdk:"max_file_size"`
	EnforceSafeSearch        types.Bool     `tfsdk:"enforce_safe_search"`
	FilterByImageLicense     types.Bool     `tfsdk:"filter_by_image_license"`
	YouTubeFilter            types.String   `tfsdk:"youtube_filter"`
	QuotaLimit               types.Int64    `tfsdk:"quota_limit"`
	PropagateXForwardedFor   types.Bool     `tfsdk:"propagate_x_forwarded_for"`
	RestrictGoogleAppDomains types.Bool     `tfsdk:"restrict_google_app_domains"`
	GoogleAppDomains         types.Set      `tfsdk:"google_app_domains"`
	RestrictOffice365Tenants types.Bool     `tfsdk:"restrict_office365_tenants"`
	Office365Tenants         types.Set      `tfsdk:"office365_tenants"`
	Office365DirectoryID     types.String   `tfsdk:"office365_directory_id"`
	Rules                    []webRuleModel `tfsdk:"rules"`
}

type webRuleModel struct {
	Enabled             types.Bool   `tfsdk:"enabled"`
	Users               types.Set    `tfsdk:"users"`
	UserGroups          types.Set    `tfsdk:"user_groups"`
	Categories          types.Set    `tfsdk:"categories"`
	URLGroups           types.Set    `tfsdk:"url_groups"`
	FileTypes           types.Set    `tfsdk:"file_types"`
	DynamicCategories   types.Set    `tfsdk:"dynamic_categories"`
	UserActivities      types.Set    `tfsdk:"user_activities"`
	HTTPAction          types.String `tfsdk:"http_action"`
	FollowHTTPAction    types.Bool   `tfsdk:"follow_http_action"`
	HTTPSAction         types.String `tfsdk:"https_action"`
	Schedule            types.String `tfsdk:"schedule"`
	ApplyContentFilters types.Bool   `tfsdk:"apply_content_filters"`
	ContentFilters      types.Set    `tfsdk:"content_filters"`
}

// ---- API payload ----

type webPolicy struct {
	ID                       string    `json:"id,omitempty"`
	Name                     string    `json:"name"`
	Description              *string   `json:"description,omitempty"`
	DefaultAction            string    `json:"defaultAction,omitempty"`
	Reporting                *bool     `json:"reporting,omitempty"`
	RestrictFileSize         *bool     `json:"restrictFileSize,omitempty"`
	MaxFileSize              *int64    `json:"maxFileSize,omitempty"`
	EnforceSafeSearch        *bool     `json:"enforceSafeSearch,omitempty"`
	FilterByImageLicense     *bool     `json:"filterByImageLicense,omitempty"`
	YouTubeFilter            *string   `json:"youtubeFilter,omitempty"`
	QuotaLimit               *int64    `json:"quotaLimit,omitempty"`
	PropagateXForwardedFor   *bool     `json:"propagateXForwardedFor,omitempty"`
	RestrictGoogleAppDomains *bool     `json:"restrictGoogleAppDomains,omitempty"`
	GoogleAppDomainFilter    []string  `json:"googleAppDomainFilter,omitempty"`
	RestrictOffice365Tenants *bool     `json:"restrictOffice365Tenants,omitempty"`
	Office365FilterTenants   []string  `json:"office365FilterTenants,omitempty"`
	Office365DirectoryID     *string   `json:"office365FilterDirectoryId,omitempty"`
	Rules                    []webRule `json:"rules"`
}

type webRule struct {
	Enabled             *bool                    `json:"enabled,omitempty"`
	UsersOrGroups       sfos.Selector[ruleUsers] `json:"usersOrGroups"`
	Activities          *ruleActivities          `json:"activities,omitempty"`
	HTTPAction          string                   `json:"httpAction"`
	HTTPSAction         string                   `json:"httpsAction"`
	FollowHTTPAction    *bool                    `json:"followHttpAction,omitempty"`
	Schedule            *sfos.NameRef            `json:"schedule,omitempty"`
	ApplyContentFilters *bool                    `json:"applyContentFilters,omitempty"`
	ContentFilters      []sfos.NameRef           `json:"contentFilters,omitempty"`
}

type ruleUsers struct {
	Users      []sfos.NameRef `json:"users,omitempty"`
	UserGroups []sfos.NameRef `json:"userGroups,omitempty"`
}

type ruleActivities struct {
	Categories        []sfos.NameRef `json:"categories,omitempty"`
	URLGroups         []sfos.NameRef `json:"urlGroups,omitempty"`
	FileTypes         []sfos.NameRef `json:"fileTypes,omitempty"`
	DynamicCategories []sfos.NameRef `json:"dynamicCategories,omitempty"`
	UserActivities    []sfos.NameRef `json:"userActivities,omitempty"`
}

func (a *ruleActivities) empty() bool {
	return len(a.Categories)+len(a.URLGroups)+len(a.FileTypes)+len(a.DynamicCategories)+len(a.UserActivities) == 0
}

// ---- Resource ----

// Policy manages /web/policies.
var Policy = &framework.Resource[webPolicyModel, webPolicy]{
	Name:   "web_policy",
	Title:  "web policy",
	Path:   "/web/policies",
	Schema: webPolicySchema(),
	// Renaming is handled as a replacement, like the other web objects.
	CreateOnly:  []string{"name"},
	Expand:      expandWebPolicy,
	Flatten:     flattenWebPolicy,
	Validate:    validateWebPolicy,
	AfterCreate: fixReporting,
	AfterUpdate: func(ctx context.Context, c *sfos.Client, plan, _ *webPolicyModel, diags *diag.Diagnostics) {
		fixReporting(ctx, c, plan, diags)
	},
}

// fixReporting works around SFOS v23 storing the inverse of the
// "reporting" value sent on create or update (and inverting it on a PATCH
// that leaves it out). After every write the value is read back; if it is
// wrong, the inverse is sent, and if that does not help (the firewall has
// been fixed), the configured value.
func fixReporting(ctx context.Context, c *sfos.Client, plan *webPolicyModel, diags *diag.Diagnostics) {
	if plan.Reporting.IsUnknown() || plan.Reporting.IsNull() {
		return
	}
	want := plan.Reporting.ValueBool()
	item := sfos.ItemPath("/web/policies", plan.Name.ValueString())
	for _, send := range []bool{!want, want} {
		var got webPolicy
		if err := c.Get(ctx, item, &got); err != nil {
			diags.AddError("Unable to read web policy", err.Error())
			return
		}
		if got.Reporting == nil || *got.Reporting == want {
			return
		}
		if err := c.Patch(ctx, item, map[string]any{"reporting": send}, nil); err != nil {
			diags.AddError("Unable to set web policy reporting", err.Error())
			return
		}
	}
	var got webPolicy
	if err := c.Get(ctx, item, &got); err != nil {
		diags.AddError("Unable to read web policy", err.Error())
		return
	}
	if got.Reporting != nil && *got.Reporting != want {
		diags.AddError("Unable to set web policy reporting",
			fmt.Sprintf("The firewall keeps reporting = %t, but %t was configured.", *got.Reporting, want))
	}
}

// firewallBool is an optional flag that takes the firewall's default when
// omitted and keeps the current value from then on.
func firewallBool(description string) schema.BoolAttribute {
	return schema.BoolAttribute{
		Optional:            true,
		Computed:            true,
		MarkdownDescription: description + " Omit to keep the firewall's setting.",
		PlanModifiers:       []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
	}
}

func domainSet(description string) schema.SetAttribute {
	return schema.SetAttribute{
		Optional:            true,
		ElementType:         types.StringType,
		MarkdownDescription: description,
		Validators: []validator.Set{
			setvalidator.SizeAtLeast(1),
			setvalidator.ValueStringsAre(
				stringvalidator.LengthAtMost(253),
				stringvalidator.RegexMatches(domainRe, "must be a domain name such as example.com (letters, digits, dots and hyphens)"),
			),
		},
	}
}

func refSet(description string, maxLen int) schema.SetAttribute {
	a := framework.NameSetAttribute(description)
	a.Validators = append(a.Validators,
		setvalidator.SizeAtMost(1024),
		setvalidator.ValueStringsAre(stringvalidator.LengthAtMost(maxLen)))
	return a
}

func webPolicySchema() schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages a web policy (*Protect > Web > Policies*): an ordered list of rules that allow, " +
			"block, warn about or quota web activities (categories, URL groups, file types, dynamic categories and " +
			"user activities) for users and groups, plus a default action and policy-wide options such as SafeSearch " +
			"and YouTube restrictions. A web policy takes effect once a firewall rule references it.\n\n" +
			"Rules are evaluated top to bottom, in the order of the `rules` list.",
		Attributes: map[string]schema.Attribute{
			"id":          framework.IDAttribute(),
			"name":        framework.NameAttribute("web policy", 50, true),
			"description": framework.DescriptionAttribute(255),
			"default_action": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Action for traffic that matches no rule. " + framework.OneOfMarkdown(policyActions...),
				Validators:          []validator.String{stringvalidator.OneOf(policyActions...)},
			},
			"reporting":          firewallBool("Include traffic matched by this policy in reports."),
			"restrict_file_size": firewallBool("Block downloads larger than `max_file_size`."),
			"max_file_size": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Default:  int64default.StaticInt64(defaultMaxFileSize),
				MarkdownDescription: fmt.Sprintf("Largest allowed download in MB (1-1536) when `restrict_file_size` is `true`. "+
					"Defaults to `%d`.", defaultMaxFileSize),
				Validators: []validator.Int64{int64validator.Between(1, 1536)},
			},
			"enforce_safe_search":     firewallBool("Enforce SafeSearch on search engines."),
			"filter_by_image_license": firewallBool("Only show Creative Commons licensed images in image search results."),
			"youtube_filter": schema.StringAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: "YouTube Restricted Mode: `off`, `moderate` (standard restricted mode) or `strict`. " +
					"Omit to keep the firewall's setting. " + framework.OneOfMarkdown(youtubeLevels...),
				Validators:    []validator.String{stringvalidator.OneOf(youtubeLevels...)},
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"quota_limit": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: "Browsing time in minutes allowed per day for rules with the `quota` action " +
					"(10-1440, a multiple of 10). Omit to keep the firewall's setting.",
				Validators:    []validator.Int64{int64validator.Between(10, 1440), multipleOf{10}},
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"propagate_x_forwarded_for":   firewallBool("Send the client's IP address to web servers in an `X-Forwarded-For` header."),
			"restrict_google_app_domains": firewallBool("Only allow access to Google services for the domains in `google_app_domains`."),
			"google_app_domains": domainSet("Domains allowed to sign in to Google services, e.g. `example.com`. " +
				"The firewall stores them comma separated in at most 256 characters."),
			"restrict_office365_tenants": firewallBool("Only allow access to Microsoft 365 for the tenants in `office365_tenants`."),
			"office365_tenants": domainSet("Tenant domains or directory IDs allowed to access Microsoft 365. " +
				"The firewall stores them comma separated in at most 4,096 characters."),
			"office365_directory_id": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Microsoft 365 directory (tenant) ID sent with the tenant restriction.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 50),
					stringvalidator.RegexMatches(directoryIDRe, "may only contain letters, digits and hyphens"),
				},
			},
			"rules": schema.ListNestedAttribute{
				Optional: true,
				MarkdownDescription: "Rules in evaluation order (at most 1,024). Omit to leave the rules unmanaged; " +
					"a new policy is then created without rules. Removing the attribute later deletes all rules.",
				Validators:   []validator.List{listvalidator.SizeBetween(1, 1024)},
				NestedObject: webRuleSchema(),
			},
		},
	}
}

func webRuleSchema() schema.NestedAttributeObject {
	action := func(desc string) string {
		return desc + " " + framework.OneOfMarkdown(ruleActions...) +
			" With `dynamic_categories` only `allow` and `deny` are accepted, with `apply_content_filters` only " +
			"`deny` and `log`; otherwise `log` is not accepted."
	}
	return schema.NestedAttributeObject{
		Attributes: map[string]schema.Attribute{
			"enabled": framework.BoolDefault("Whether the rule is active.", true),
			"users": refSet("Users the rule applies to. Omit both `users` and `user_groups` to apply the rule "+
				"to anybody.", 50),
			"user_groups": refSet("User groups the rule applies to.", 256),
			"categories":  refSet("Web categories to match, e.g. `Gambling`.", 50),
			"url_groups":  refSet("URL groups to match (`sophosfirewall_url_group`).", 50),
			"file_types":  refSet("File types to match, e.g. `Executable Files`.", 50),
			"dynamic_categories": refSet("Dynamic categories to match. Rules with dynamic categories "+
				"cannot apply content filters.", 50),
			"user_activities": refSet("User activities to match.", 50),
			"http_action": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: action("Action for matching HTTP traffic."),
				Validators:          []validator.String{stringvalidator.OneOf(ruleActions...)},
			},
			"follow_http_action": framework.BoolDefault("Apply `http_action` to HTTPS traffic too. "+
				"Set to `false` to choose `https_action` separately.", true),
			"https_action": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: action("Action for matching HTTPS traffic. Required when `follow_http_action` " +
					"is `false`, not allowed otherwise."),
				Validators: []validator.String{stringvalidator.OneOf(ruleActions...)},
			},
			"schedule": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(AllTheTime),
				MarkdownDescription: fmt.Sprintf("Name of the schedule during which the rule applies. Defaults to `%s`.", AllTheTime),
				Validators:          []validator.String{stringvalidator.LengthBetween(1, 50), framework.ObjectName()},
			},
			"apply_content_filters": framework.BoolDefault("Also match the `content_filters` (keyword lists). "+
				"Requires `content_filters` and `follow_http_action`.", false),
			"content_filters": refSet("Content filters (keyword lists) to match when `apply_content_filters` is `true`.", 255),
		},
	}
}

// ---- Validation ----

func validateWebPolicy(_ context.Context, m *webPolicyModel, diags *diag.Diagnostics) {
	checkJoinedLength(m.GoogleAppDomains, "google_app_domains", maxGoogleDomainsLen, diags)
	checkJoinedLength(m.Office365Tenants, "office365_tenants", maxOffice365TenantsLen, diags)
	for i := range m.Rules {
		validateWebRule(&m.Rules[i], path.Root("rules").AtListIndex(i), diags)
	}
}

func checkJoinedLength(v types.Set, name string, max int, diags *diag.Diagnostics) {
	if v.IsNull() || v.IsUnknown() {
		return
	}
	var parts []string
	for _, e := range v.Elements() {
		s, ok := e.(types.String)
		if !ok || s.IsUnknown() {
			return
		}
		parts = append(parts, s.ValueString())
	}
	if n := len(strings.Join(parts, ",")); n > max {
		diags.AddAttributeError(path.Root(name), "List too long",
			fmt.Sprintf("The firewall stores %s comma separated in at most %d characters; this list needs %d.", name, max, n))
	}
}

func validateWebRule(r *webRuleModel, p path.Path, diags *diag.Diagnostics) {
	// Defaults are not applied yet during validation: null means the default.
	follow := r.FollowHTTPAction.IsNull() || r.FollowHTTPAction.ValueBool()
	followKnown := !r.FollowHTTPAction.IsUnknown()
	contentFilters := r.ApplyContentFilters.ValueBool()
	dynamic := !r.DynamicCategories.IsNull() && !r.DynamicCategories.IsUnknown() && len(r.DynamicCategories.Elements()) > 0

	if followKnown && !r.HTTPSAction.IsUnknown() {
		switch {
		case follow && !r.HTTPSAction.IsNull():
			diags.AddAttributeError(p.AtName("https_action"), "Invalid attribute combination",
				"https_action cannot be set while follow_http_action is true: the firewall applies http_action to HTTPS traffic. "+
					"Set follow_http_action = false to choose a separate HTTPS action.")
		case !follow && r.HTTPSAction.IsNull():
			diags.AddAttributeError(p.AtName("https_action"), "Missing required argument",
				"https_action is required when follow_http_action is false.")
		}
	}
	if contentFilters {
		if followKnown && !follow {
			diags.AddAttributeError(p.AtName("apply_content_filters"), "Invalid attribute combination",
				"apply_content_filters requires follow_http_action = true.")
		}
		if r.ContentFilters.IsNull() {
			diags.AddAttributeError(p.AtName("apply_content_filters"), "Invalid attribute combination",
				"apply_content_filters requires content_filters.")
		}
		if dynamic {
			diags.AddAttributeError(p.AtName("apply_content_filters"), "Invalid attribute combination",
				"apply_content_filters cannot be combined with dynamic_categories.")
		}
	}

	var allowed []string
	switch {
	case r.DynamicCategories.IsUnknown() || r.ApplyContentFilters.IsUnknown():
		return
	case dynamic:
		allowed = []string{"allow", "deny"}
	case contentFilters:
		allowed = []string{"deny", "log"}
	default:
		allowed = []string{"allow", "deny", "warn", "quota"}
	}
	for _, a := range []struct {
		name  string
		value types.String
	}{{"http_action", r.HTTPAction}, {"https_action", r.HTTPSAction}} {
		if a.value.IsNull() || a.value.IsUnknown() {
			continue
		}
		ok := false
		for _, v := range allowed {
			ok = ok || v == a.value.ValueString()
		}
		if !ok {
			diags.AddAttributeError(p.AtName(a.name), "Invalid action",
				fmt.Sprintf("%q is not accepted for this rule: %s", a.value.ValueString(), actionHint(dynamic, contentFilters)))
		}
	}
}

func actionHint(dynamic, contentFilters bool) string {
	switch {
	case dynamic:
		return "rules with dynamic_categories only accept allow or deny."
	case contentFilters:
		return "rules that apply content filters only accept deny or log."
	}
	return "log is only accepted together with apply_content_filters."
}

// multipleOf validates that an integer is a multiple of n.
type multipleOf struct{ n int64 }

func (v multipleOf) Description(context.Context) string {
	return fmt.Sprintf("must be a multiple of %d", v.n)
}
func (v multipleOf) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (v multipleOf) ValidateInt64(_ context.Context, req validator.Int64Request, resp *validator.Int64Response) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if req.ConfigValue.ValueInt64()%v.n != 0 {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid value",
			fmt.Sprintf("must be a multiple of %d, got %d", v.n, req.ConfigValue.ValueInt64()))
	}
}

// ---- Conversion ----

func expandWebPolicy(ctx context.Context, m *webPolicyModel, diags *diag.Diagnostics) *webPolicy {
	p := &webPolicy{
		Name:                     m.Name.ValueString(),
		Description:              framework.StringPtr(m.Description),
		DefaultAction:            m.DefaultAction.ValueString(),
		Reporting:                framework.BoolPtr(m.Reporting),
		RestrictFileSize:         framework.BoolPtr(m.RestrictFileSize),
		MaxFileSize:              framework.Int64Ptr(m.MaxFileSize),
		EnforceSafeSearch:        framework.BoolPtr(m.EnforceSafeSearch),
		FilterByImageLicense:     framework.BoolPtr(m.FilterByImageLicense),
		YouTubeFilter:            framework.StringPtr(m.YouTubeFilter),
		QuotaLimit:               framework.Int64Ptr(m.QuotaLimit),
		PropagateXForwardedFor:   framework.BoolPtr(m.PropagateXForwardedFor),
		RestrictGoogleAppDomains: framework.BoolPtr(m.RestrictGoogleAppDomains),
		GoogleAppDomainFilter:    framework.Strings(ctx, m.GoogleAppDomains, diags),
		RestrictOffice365Tenants: framework.BoolPtr(m.RestrictOffice365Tenants),
		Office365FilterTenants:   framework.Strings(ctx, m.Office365Tenants, diags),
		Office365DirectoryID:     framework.StringPtr(m.Office365DirectoryID),
		// Always sent, so that removing the rules sends [] rather than null.
		Rules: make([]webRule, 0, len(m.Rules)),
	}
	for i := range m.Rules {
		p.Rules = append(p.Rules, expandWebRule(ctx, &m.Rules[i], diags))
	}
	return p
}

func expandWebRule(ctx context.Context, r *webRuleModel, diags *diag.Diagnostics) webRule {
	out := webRule{
		Enabled:             framework.BoolPtr(r.Enabled),
		UsersOrGroups:       sfos.MatchAny[ruleUsers](),
		HTTPAction:          r.HTTPAction.ValueString(),
		HTTPSAction:         r.HTTPSAction.ValueString(),
		FollowHTTPAction:    framework.BoolPtr(r.FollowHTTPAction),
		Schedule:            framework.Ref(r.Schedule),
		ApplyContentFilters: framework.BoolPtr(r.ApplyContentFilters),
		ContentFilters:      framework.Refs(ctx, r.ContentFilters, diags),
	}
	// The API requires httpsAction; with followHttpAction it mirrors httpAction.
	if r.HTTPSAction.IsNull() || r.HTTPSAction.IsUnknown() {
		out.HTTPSAction = out.HTTPAction
	}
	if !r.Users.IsNull() || !r.UserGroups.IsNull() {
		out.UsersOrGroups = sfos.Match(ruleUsers{
			Users:      framework.Refs(ctx, r.Users, diags),
			UserGroups: framework.Refs(ctx, r.UserGroups, diags),
		})
	}
	act := &ruleActivities{
		Categories:        framework.Refs(ctx, r.Categories, diags),
		URLGroups:         framework.Refs(ctx, r.URLGroups, diags),
		FileTypes:         framework.Refs(ctx, r.FileTypes, diags),
		DynamicCategories: framework.Refs(ctx, r.DynamicCategories, diags),
		UserActivities:    framework.Refs(ctx, r.UserActivities, diags),
	}
	// The API rejects an empty activities object.
	if !act.empty() {
		out.Activities = act
	}
	return out
}

func flattenWebPolicy(ctx context.Context, a *webPolicy, prior *webPolicyModel, diags *diag.Diagnostics) *webPolicyModel {
	m := &webPolicyModel{
		ID:                       types.StringValue(a.ID),
		Name:                     types.StringValue(a.Name),
		Description:              framework.StringOr(a.Description, ""),
		DefaultAction:            types.StringValue(a.DefaultAction),
		Reporting:                types.BoolPointerValue(a.Reporting),
		RestrictFileSize:         types.BoolPointerValue(a.RestrictFileSize),
		MaxFileSize:              types.Int64Value(defaultMaxFileSize),
		EnforceSafeSearch:        types.BoolPointerValue(a.EnforceSafeSearch),
		FilterByImageLicense:     types.BoolPointerValue(a.FilterByImageLicense),
		YouTubeFilter:            types.StringPointerValue(a.YouTubeFilter),
		QuotaLimit:               types.Int64PointerValue(a.QuotaLimit),
		PropagateXForwardedFor:   types.BoolPointerValue(a.PropagateXForwardedFor),
		RestrictGoogleAppDomains: types.BoolPointerValue(a.RestrictGoogleAppDomains),
		GoogleAppDomains:         framework.StringSet(ctx, a.GoogleAppDomainFilter, diags),
		RestrictOffice365Tenants: types.BoolPointerValue(a.RestrictOffice365Tenants),
		Office365Tenants:         framework.StringSet(ctx, a.Office365FilterTenants, diags),
		Office365DirectoryID:     types.StringNull(),
	}
	if a.Office365DirectoryID != nil {
		m.Office365DirectoryID = framework.NonEmpty(*a.Office365DirectoryID)
	}
	switch {
	case a.MaxFileSize != nil && *a.MaxFileSize > 0:
		m.MaxFileSize = types.Int64Value(*a.MaxFileSize)
	case prior != nil && !prior.MaxFileSize.IsNull() && !prior.MaxFileSize.IsUnknown():
		// 0 means "no limit" (restrict_file_size = false): keep the configured value.
		m.MaxFileSize = prior.MaxFileSize
	}

	// Rules stay null unless they are managed, so that rules maintained in
	// the web admin console are not reported as drift.
	if framework.Managed(prior, func(p *webPolicyModel) bool { return p.Rules != nil }) && len(a.Rules) > 0 {
		m.Rules = make([]webRuleModel, 0, len(a.Rules))
		for i := range a.Rules {
			m.Rules = append(m.Rules, flattenWebRule(ctx, &a.Rules[i], diags))
		}
	}
	return m
}

func flattenWebRule(ctx context.Context, r *webRule, diags *diag.Diagnostics) webRuleModel {
	follow := r.FollowHTTPAction == nil || *r.FollowHTTPAction
	out := webRuleModel{
		Enabled:             framework.BoolOr(r.Enabled, true),
		Users:               types.SetNull(types.StringType),
		UserGroups:          types.SetNull(types.StringType),
		Categories:          types.SetNull(types.StringType),
		URLGroups:           types.SetNull(types.StringType),
		FileTypes:           types.SetNull(types.StringType),
		DynamicCategories:   types.SetNull(types.StringType),
		UserActivities:      types.SetNull(types.StringType),
		HTTPAction:          types.StringValue(r.HTTPAction),
		FollowHTTPAction:    types.BoolValue(follow),
		HTTPSAction:         types.StringNull(),
		Schedule:            types.StringValue(AllTheTime),
		ApplyContentFilters: framework.BoolOr(r.ApplyContentFilters, false),
		ContentFilters:      framework.RefSet(ctx, r.ContentFilters, diags),
	}
	if !follow {
		out.HTTPSAction = types.StringValue(r.HTTPSAction)
	}
	if r.Schedule != nil && r.Schedule.Name != "" {
		out.Schedule = types.StringValue(r.Schedule.Name)
	}
	if !r.UsersOrGroups.Any {
		out.Users = framework.RefSet(ctx, r.UsersOrGroups.Items.Users, diags)
		out.UserGroups = framework.RefSet(ctx, r.UsersOrGroups.Items.UserGroups, diags)
	}
	if act := r.Activities; act != nil {
		out.Categories = framework.RefSet(ctx, act.Categories, diags)
		out.URLGroups = framework.RefSet(ctx, act.URLGroups, diags)
		out.FileTypes = framework.RefSet(ctx, act.FileTypes, diags)
		out.DynamicCategories = framework.RefSet(ctx, act.DynamicCategories, diags)
		out.UserActivities = framework.RefSet(ctx, act.UserActivities, diags)
	}
	return out
}
