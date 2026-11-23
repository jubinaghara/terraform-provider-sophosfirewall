// Package trafficshaping implements QoS / traffic shaping objects.
package trafficshaping

import (
	"context"
	"fmt"
	"reflect"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfos"
)

const (
	policyPath = "/traffic-shaping/policies"

	typeGuaranteed = "guaranteed"
	typeBestEffort = "bestEffort"

	minKbps = 16
	maxKbps = 20480000
)

var (
	associations = []string{"users", "rules", "webCategories", "applications"}
	policyTypes  = []string{typeGuaranteed, typeBestEffort}
)

type policyModel struct {
	ID                 types.String    `tfsdk:"id"`
	Name               types.String    `tfsdk:"name"`
	Description        types.String    `tfsdk:"description"`
	AssociatesWith     types.String    `tfsdk:"associates_with"`
	IsShared           types.Bool      `tfsdk:"is_shared"`
	Type               types.String    `tfsdk:"type"`
	Bandwidth          *bandwidthModel `tfsdk:"bandwidth"`
	ScheduledOverrides []overrideModel `tfsdk:"scheduled_overrides"`
}

type bandwidthModel struct {
	Guaranteed *rateModel `tfsdk:"guaranteed"`
	Limit      *rateModel `tfsdk:"limit"`
}

type rateModel struct {
	AggregatedKbps types.Int64 `tfsdk:"aggregated_kbps"`
	UploadKbps     types.Int64 `tfsdk:"upload_kbps"`
	DownloadKbps   types.Int64 `tfsdk:"download_kbps"`
}

type overrideModel struct {
	Schedule  types.String    `tfsdk:"schedule"`
	Bandwidth *bandwidthModel `tfsdk:"bandwidth"`
}

type policy struct {
	ID                 string     `json:"id,omitempty"`
	Name               string     `json:"name"`
	Description        *string    `json:"description,omitempty"`
	AssociatesWith     string     `json:"associatesWith,omitempty"`
	IsShared           *bool      `json:"isShared,omitempty"`
	Type               string     `json:"type,omitempty"`
	Bandwidth          *bandwidth `json:"bandwidth,omitempty"`
	ScheduledOverrides []override `json:"scheduledOverrides"`
}

type bandwidth struct {
	Guaranteed *guaranteed `json:"guaranteed,omitempty"`
	BestEffort *rate       `json:"bestEffort,omitempty"`
}

type guaranteed struct {
	Min *rate `json:"min,omitempty"`
	Max *rate `json:"max,omitempty"`
}

type rate struct {
	AggregatedKbps *int64 `json:"aggregatedKbps,omitempty"`
	UploadKbps     *int64 `json:"uploadKbps,omitempty"`
	DownloadKbps   *int64 `json:"downloadKbps,omitempty"`
}

type override struct {
	Schedule  sfos.NameRef `json:"schedule"`
	Bandwidth bandwidth    `json:"bandwidth"`
}

// Policy manages /traffic-shaping/policies.
var Policy = &framework.Resource[policyModel, policy]{
	Name:   "traffic_shaping_policy",
	Title:  "traffic shaping policy",
	Path:   policyPath,
	Schema: policySchema(),
	// name, associatesWith, isShared and type cannot be patched; their
	// attributes force a new resource. bandwidth is listed as well because a
	// merge patch of it could send half of a min/max or upload/download pair,
	// which the API rejects: AfterUpdate sends the complete object instead.
	CreateOnly:  []string{"name", "associatesWith", "isShared", "type", "bandwidth"},
	Validate:    validatePolicy,
	Expand:      expandPolicy,
	Flatten:     flattenPolicy,
	AfterUpdate: patchBandwidth,
}

func rateSchema(description string, required, topLevel bool) schema.SingleNestedAttribute {
	kbps := func(d string) schema.Int64Attribute {
		return schema.Int64Attribute{
			Optional:            true,
			MarkdownDescription: fmt.Sprintf("%s in kbps (%d-%d).", d, minKbps, maxKbps),
			Validators:          []validator.Int64{int64validator.Between(minKbps, maxKbps)},
		}
	}
	aggregated := kbps("Combined upload and download rate")
	if topLevel {
		// The direction scope (aggregated vs. per direction) cannot be patched.
		aggregated.MarkdownDescription += " Switching between `aggregated_kbps` and `upload_kbps`/`download_kbps` forces a new resource."
		aggregated.PlanModifiers = []planmodifier.Int64{int64planmodifier.RequiresReplaceIf(
			func(_ context.Context, req planmodifier.Int64Request, resp *int64planmodifier.RequiresReplaceIfFuncResponse) {
				resp.RequiresReplace = req.StateValue.IsNull() != req.PlanValue.IsNull()
			},
			"Switching between aggregated and per-direction rates forces a new resource.",
			"Switching between aggregated and per-direction rates forces a new resource.",
		)}
	}
	return schema.SingleNestedAttribute{
		Required:            required,
		Optional:            !required,
		MarkdownDescription: description + " Set either `aggregated_kbps`, or both `upload_kbps` and `download_kbps`.",
		Attributes: map[string]schema.Attribute{
			"aggregated_kbps": aggregated,
			"upload_kbps":     kbps("Upload rate"),
			"download_kbps":   kbps("Download rate"),
		},
	}
}

func bandwidthAttributes(topLevel bool) map[string]schema.Attribute {
	guaranteedDesc := "Guaranteed minimum bandwidth. Required when `type` is `guaranteed`, not allowed for `bestEffort`."
	if !topLevel {
		guaranteedDesc = "Guaranteed minimum bandwidth. Setting it makes this a guaranteed override, omitting it a best-effort one."
	}
	return map[string]schema.Attribute{
		"guaranteed": rateSchema(guaranteedDesc, false, topLevel),
		"limit": rateSchema("Bandwidth limit: the cap of a best-effort policy or the burst ceiling of a guaranteed one "+
			"(at least the guaranteed rate).", true, topLevel),
	}
}

func policySchema() schema.Schema {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	return schema.Schema{
		MarkdownDescription: "Manages a traffic shaping policy (*Configure > System services > Traffic shaping*). " +
			"Policies are referenced by name, for example from `sophosfirewall_firewall_rule.qos.traffic_shaping_policy`. " +
			"Only `description`, the rates of `bandwidth` and `scheduled_overrides` can be changed in place; " +
			"changing anything else recreates the policy.",
		Attributes: map[string]schema.Attribute{
			"id":          framework.IDAttribute(),
			"name":        framework.NameAttribute("traffic shaping policy", 50, true),
			"description": framework.DescriptionAttribute(255),
			"associates_with": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "What the policy is applied to. " + framework.OneOfMarkdown(associations...) +
					" Changing this forces a new resource.",
				Validators:    []validator.String{stringvalidator.OneOf(associations...)},
				PlanModifiers: replace,
			},
			"is_shared": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: "Bandwidth usage type: `true` shares one bandwidth pool among all matching " +
					"users, rules, categories or applications, `false` gives each its own allocation (*Individual*). " +
					"Defaults to `false`. Changing this forces a new resource.",
				Default:       booldefault.StaticBool(false),
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.RequiresReplace()},
			},
			"type": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Policy type: `guaranteed` reserves a minimum bandwidth and can burst up to the " +
					"limit, `bestEffort` only caps the bandwidth. " + framework.OneOfMarkdown(policyTypes...) +
					" Changing this forces a new resource.",
				Validators:    []validator.String{stringvalidator.OneOf(policyTypes...)},
				PlanModifiers: replace,
			},
			"bandwidth": schema.SingleNestedAttribute{
				Required:            true,
				MarkdownDescription: "Bandwidth rates.",
				Attributes:          bandwidthAttributes(true),
			},
			"scheduled_overrides": schema.ListNestedAttribute{
				Optional: true,
				MarkdownDescription: "Bandwidth that applies instead of `bandwidth` while a schedule is active. Each " +
					"override may use a different type and direction scope than the policy. Omit to leave the " +
					"policy's overrides unmanaged.",
				Validators: []validator.List{listvalidator.SizeAtLeast(1)},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"schedule": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "Name of the schedule, e.g. `Work hours (5 Day week)`.",
							Validators:          []validator.String{stringvalidator.LengthBetween(1, 50), framework.ObjectName()},
						},
						"bandwidth": schema.SingleNestedAttribute{
							Required:            true,
							MarkdownDescription: "Bandwidth rates while the schedule is active.",
							Attributes:          bandwidthAttributes(false),
						},
					},
				},
			},
		},
	}
}

// --- validation ---

func validatePolicy(_ context.Context, m *policyModel, diags *diag.Diagnostics) {
	if m.Bandwidth != nil {
		p := path.Root("bandwidth")
		if !m.Type.IsUnknown() && !m.Type.IsNull() {
			switch g := m.Bandwidth.Guaranteed; {
			case m.Type.ValueString() == typeGuaranteed && g == nil:
				diags.AddAttributeError(p.AtName("guaranteed"), "Missing guaranteed bandwidth",
					`"guaranteed" is required when type is "guaranteed".`)
			case m.Type.ValueString() == typeBestEffort && g != nil:
				diags.AddAttributeError(p.AtName("guaranteed"), "Unexpected guaranteed bandwidth",
					`"guaranteed" can only be set when type is "guaranteed".`)
			}
		}
		validateBandwidth(p, m.Bandwidth, diags)
	}
	for i, o := range m.ScheduledOverrides {
		if o.Bandwidth != nil {
			validateBandwidth(path.Root("scheduled_overrides").AtListIndex(i).AtName("bandwidth"), o.Bandwidth, diags)
		}
	}
}

func validateBandwidth(p path.Path, b *bandwidthModel, diags *diag.Diagnostics) {
	limitOK := validateRate(p.AtName("limit"), b.Limit, diags)
	if b.Guaranteed == nil || !validateRate(p.AtName("guaranteed"), b.Guaranteed, diags) || !limitOK {
		return
	}
	g, l := b.Guaranteed, b.Limit
	if g.AggregatedKbps.IsNull() != l.AggregatedKbps.IsNull() {
		diags.AddAttributeError(p.AtName("guaranteed"), "Mismatched direction scope",
			"guaranteed and limit must both use aggregated_kbps or both use upload_kbps and download_kbps.")
		return
	}
	for _, f := range []struct {
		name string
		g, l types.Int64
	}{{"aggregated_kbps", g.AggregatedKbps, l.AggregatedKbps}, {"upload_kbps", g.UploadKbps, l.UploadKbps}, {"download_kbps", g.DownloadKbps, l.DownloadKbps}} {
		if f.g.IsNull() || f.g.IsUnknown() || f.l.IsNull() || f.l.IsUnknown() {
			continue
		}
		if f.g.ValueInt64() > f.l.ValueInt64() {
			diags.AddAttributeError(p.AtName("guaranteed").AtName(f.name), "Guaranteed rate above limit",
				fmt.Sprintf("guaranteed %s (%d) must not exceed limit %s (%d).", f.name, f.g.ValueInt64(), f.name, f.l.ValueInt64()))
		}
	}
}

// validateRate reports whether r sets exactly one direction scope.
func validateRate(p path.Path, r *rateModel, diags *diag.Diagnostics) bool {
	if r == nil {
		return false
	}
	agg := !r.AggregatedKbps.IsNull()
	up, down := !r.UploadKbps.IsNull(), !r.DownloadKbps.IsNull()
	switch {
	case agg && (up || down):
		diags.AddAttributeError(p, "Conflicting rates", "Set either aggregated_kbps, or upload_kbps and download_kbps, not both.")
	case !agg && !up && !down:
		diags.AddAttributeError(p, "Missing rate", "Set either aggregated_kbps, or both upload_kbps and download_kbps.")
	case !agg && up != down:
		diags.AddAttributeError(p, "Incomplete rates", "upload_kbps and download_kbps must be set together.")
	default:
		return true
	}
	return false
}

// --- expand ---

func expandRate(r *rateModel) *rate {
	if r == nil {
		return nil
	}
	return &rate{
		AggregatedKbps: framework.Int64Ptr(r.AggregatedKbps),
		UploadKbps:     framework.Int64Ptr(r.UploadKbps),
		DownloadKbps:   framework.Int64Ptr(r.DownloadKbps),
	}
}

func expandBandwidth(b *bandwidthModel) *bandwidth {
	if b == nil {
		return nil
	}
	if b.Guaranteed != nil {
		return &bandwidth{Guaranteed: &guaranteed{Min: expandRate(b.Guaranteed), Max: expandRate(b.Limit)}}
	}
	return &bandwidth{BestEffort: expandRate(b.Limit)}
}

func expandPolicy(_ context.Context, m *policyModel, _ *diag.Diagnostics) *policy {
	p := &policy{
		Name:           m.Name.ValueString(),
		Description:    framework.StringPtr(m.Description),
		AssociatesWith: m.AssociatesWith.ValueString(),
		IsShared:       framework.BoolPtr(m.IsShared),
		Type:           m.Type.ValueString(),
		Bandwidth:      expandBandwidth(m.Bandwidth),
		// Never null: removing the overrides sends [] to clear them.
		ScheduledOverrides: make([]override, 0, len(m.ScheduledOverrides)),
	}
	for _, o := range m.ScheduledOverrides {
		ov := override{Schedule: sfos.NameRef{Name: o.Schedule.ValueString()}}
		if b := expandBandwidth(o.Bandwidth); b != nil {
			ov.Bandwidth = *b
		}
		p.ScheduledOverrides = append(p.ScheduledOverrides, ov)
	}
	return p
}

// patchBandwidth sends the complete bandwidth object when its rates change.
func patchBandwidth(ctx context.Context, c *sfos.Client, plan, state *policyModel, diags *diag.Diagnostics) {
	nb, ob := expandBandwidth(plan.Bandwidth), expandBandwidth(state.Bandwidth)
	if nb == nil || reflect.DeepEqual(nb, ob) {
		return
	}
	id := state.ID.ValueString()
	if err := c.Patch(ctx, sfos.ItemPath(policyPath, id), map[string]any{"bandwidth": nb}, nil); err != nil {
		diags.AddError(fmt.Sprintf("Unable to update bandwidth of traffic shaping policy %q", id), err.Error())
	}
}

// --- flatten ---

func flattenRate(r *rate) *rateModel {
	if r == nil {
		return nil
	}
	m := &rateModel{AggregatedKbps: types.Int64Null(), UploadKbps: types.Int64Null(), DownloadKbps: types.Int64Null()}
	if r.AggregatedKbps != nil && *r.AggregatedKbps > 0 {
		m.AggregatedKbps = types.Int64Value(*r.AggregatedKbps)
		return m
	}
	m.UploadKbps = types.Int64PointerValue(r.UploadKbps)
	m.DownloadKbps = types.Int64PointerValue(r.DownloadKbps)
	return m
}

// flattenBandwidth reads the guaranteed branch when wantGuaranteed is true
// and the best-effort branch otherwise, ignoring whatever else is returned.
func flattenBandwidth(b *bandwidth, wantGuaranteed bool) *bandwidthModel {
	if b == nil {
		return nil
	}
	if wantGuaranteed && b.Guaranteed != nil {
		return &bandwidthModel{Guaranteed: flattenRate(b.Guaranteed.Min), Limit: flattenRate(b.Guaranteed.Max)}
	}
	return &bandwidthModel{Limit: flattenRate(b.BestEffort)}
}

func flattenPolicy(_ context.Context, a *policy, prior *policyModel, _ *diag.Diagnostics) *policyModel {
	m := &policyModel{
		ID:             types.StringValue(a.ID),
		Name:           types.StringValue(a.Name),
		Description:    framework.StringOr(a.Description, ""),
		AssociatesWith: types.StringValue(a.AssociatesWith),
		IsShared:       framework.BoolOr(a.IsShared, false),
		Type:           types.StringValue(a.Type),
		Bandwidth:      flattenBandwidth(a.Bandwidth, a.Type == typeGuaranteed),
	}
	// Overrides added on the firewall are left alone unless the
	// configuration manages them.
	if len(a.ScheduledOverrides) > 0 && framework.Managed(prior, func(p *policyModel) bool { return p.ScheduledOverrides != nil }) {
		for _, o := range a.ScheduledOverrides {
			b := o.Bandwidth
			m.ScheduledOverrides = append(m.ScheduledOverrides, overrideModel{
				Schedule:  types.StringValue(o.Schedule.Name),
				Bandwidth: flattenBandwidth(&b, b.Guaranteed != nil),
			})
		}
	}
	return m
}
