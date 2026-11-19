package framework

import (
	"context"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfos"
)

// Helpers converting between Terraform values and API payload fields.
// "Expand" direction: null and unknown values become nil (= not sent).

// StringPtr returns nil for null/unknown values.
func StringPtr(v types.String) *string {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	s := v.ValueString()
	return &s
}

// Int64Ptr returns nil for null/unknown values.
func Int64Ptr(v types.Int64) *int64 {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	i := v.ValueInt64()
	return &i
}

// BoolPtr returns nil for null/unknown values.
func BoolPtr(v types.Bool) *bool {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	b := v.ValueBool()
	return &b
}

// Strings returns the elements of a set of strings (nil when null/unknown).
func Strings(ctx context.Context, v types.Set, diags *diag.Diagnostics) []string {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	var out []string
	diags.Append(v.ElementsAs(ctx, &out, false)...)
	return out
}

// Refs converts a set of object names into API references. The result is
// never nil so that it encodes as [] rather than null.
func Refs(ctx context.Context, v types.Set, diags *diag.Diagnostics) []sfos.NameRef {
	names := Strings(ctx, v, diags)
	refs := make([]sfos.NameRef, 0, len(names))
	for _, n := range names {
		refs = append(refs, sfos.NameRef{Name: n})
	}
	return refs
}

// Ref converts an object name into an API reference (nil when null/unknown).
func Ref(v types.String) *sfos.NameRef {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	return &sfos.NameRef{Name: v.ValueString()}
}

// "Flatten" direction: absent or empty API values become null.

// StringSet builds a set of strings; empty input yields a null set.
func StringSet(ctx context.Context, values []string, diags *diag.Diagnostics) types.Set {
	if len(values) == 0 {
		return types.SetNull(types.StringType)
	}
	sorted := append([]string(nil), values...)
	sort.Strings(sorted)
	s, d := types.SetValueFrom(ctx, types.StringType, sorted)
	diags.Append(d...)
	return s
}

// RefSet builds a set of names from API references; empty input yields null.
func RefSet(ctx context.Context, refs []sfos.NameRef, diags *diag.Diagnostics) types.Set {
	names := make([]string, 0, len(refs))
	for _, r := range refs {
		names = append(names, r.Name)
	}
	return StringSet(ctx, names, diags)
}

// RefName returns the referenced name, or null for a nil/empty reference.
func RefName(r *sfos.NameRef) types.String {
	if r == nil || r.Name == "" {
		return types.StringNull()
	}
	return types.StringValue(r.Name)
}

// StringOr returns *p, or def when p is nil.
func StringOr(p *string, def string) types.String {
	if p == nil {
		return types.StringValue(def)
	}
	return types.StringValue(*p)
}

// BoolOr returns *p, or def when p is nil.
func BoolOr(p *bool, def bool) types.Bool {
	if p == nil {
		return types.BoolValue(def)
	}
	return types.BoolValue(*p)
}

// NonEmpty returns null for "" and the value otherwise.
func NonEmpty(s string) types.String {
	if s == "" {
		return types.StringNull()
	}
	return types.StringValue(s)
}

// Managed reports whether an optional block should be populated from the
// API: always on import/data source reads (prior == nil), otherwise only when
// the user configured it. Unmanaged blocks stay null so server-side defaults
// do not show up as drift.
func Managed[T any](prior *T, block func(*T) bool) bool {
	return prior == nil || block(prior)
}
