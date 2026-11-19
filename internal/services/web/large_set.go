package web

import (
	"context"
	"fmt"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// largeStringSetType is a set of strings that stays fast with tens of
// thousands of elements, such as the domains of a URL group.
//
// terraform-plugin-framework (v1.19) handles sets with quadratic algorithms
// in three places that run on every plan, apply and refresh:
//
//   - basetypes.SetType.Validate compares every pair of elements with
//     tftypes.Value.Equal to find duplicates,
//   - basetypes.SetValue.Equal looks up each element with a linear scan that
//     also copies the element slice,
//   - semantic equality compares every new element with every prior element
//     unless the value implements SetSemanticEquals.
//
// With 10,000 elements a single plan took more than ten minutes. This type
// and its value replace all three with map based, linear versions.
type largeStringSetType struct {
	basetypes.SetType
}

var (
	_ basetypes.SetTypable                    = largeStringSetType{}
	_ basetypes.SetValuableWithSemanticEquals = largeStringSetValue{}
)

var largeStringSet = largeStringSetType{SetType: basetypes.SetType{ElemType: types.StringType}}

func (t largeStringSetType) Equal(o attr.Type) bool {
	other, ok := o.(largeStringSetType)
	return ok && t.SetType.Equal(other.SetType)
}

func (t largeStringSetType) String() string { return "web.largeStringSetType" }

func (t largeStringSetType) ValueType(context.Context) attr.Value { return largeStringSetValue{} }

func (t largeStringSetType) ValueFromSet(_ context.Context, in basetypes.SetValue) (basetypes.SetValuable, diag.Diagnostics) {
	return largeStringSetValue{SetValue: in}, nil
}

func (t largeStringSetType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	v, err := t.SetType.ValueFromTerraform(ctx, in)
	if err != nil {
		return nil, err
	}
	return largeStringSetValue{SetValue: v.(basetypes.SetValue)}, nil
}

// Validate implements the deprecated xattr.TypeWithValidate, which the
// framework still calls for every attribute value it reads. Terraform never
// sends duplicate set elements; this is a cheap safety net.
func (t largeStringSetType) Validate(_ context.Context, in tftypes.Value, p path.Path) diag.Diagnostics {
	var diags diag.Diagnostics
	if in.Type() == nil || !in.IsKnown() || in.IsNull() {
		return diags
	}
	var elems []tftypes.Value
	if err := in.As(&elems); err != nil {
		diags.AddAttributeError(p, "Set Type Validation Error", err.Error())
		return diags
	}
	seen := make(map[string]struct{}, len(elems))
	for _, e := range elems {
		if !e.IsKnown() || e.IsNull() {
			continue
		}
		var s string
		if err := e.As(&s); err != nil {
			diags.AddAttributeError(p, "Set Type Validation Error", err.Error())
			return diags
		}
		if _, dup := seen[s]; dup {
			diags.AddAttributeError(p.AtSetValue(types.StringValue(s)), "Duplicate Set Element",
				fmt.Sprintf("This attribute contains duplicate values of: %q", s))
		}
		seen[s] = struct{}{}
	}
	return diags
}

// largeStringSetValue is the value of a largeStringSetType.
type largeStringSetValue struct {
	basetypes.SetValue
}

func newLargeStringSet(ctx context.Context, values []string, diags *diag.Diagnostics) largeStringSetValue {
	if len(values) == 0 {
		return largeStringSetValue{SetValue: types.SetNull(types.StringType)}
	}
	sorted := append([]string(nil), values...)
	sort.Strings(sorted)
	elems := make([]attr.Value, len(sorted))
	for i, v := range sorted {
		elems[i] = types.StringValue(v)
	}
	// Not types.SetValueFrom: its reflection path runs the quadratic
	// SetType.Validate.
	s, d := basetypes.NewSetValue(types.StringType, elems)
	diags.Append(d...)
	return largeStringSetValue{SetValue: s}
}

func (v largeStringSetValue) Type(context.Context) attr.Type { return largeStringSet }

func (v largeStringSetValue) Equal(o attr.Value) bool {
	other, ok := o.(largeStringSetValue)
	if !ok {
		return false
	}
	return sameStrings(v.SetValue, other.SetValue)
}

// SetSemanticEquals lets the framework skip its pairwise element comparison
// when the firewall returned the same domains.
func (v largeStringSetValue) SetSemanticEquals(_ context.Context, prior basetypes.SetValuable) (bool, diag.Diagnostics) {
	p, ok := prior.(largeStringSetValue)
	return ok && sameStrings(v.SetValue, p.SetValue), nil
}

// sameStrings compares two sets of strings in linear time.
func sameStrings(a, b basetypes.SetValue) bool {
	if a.IsNull() != b.IsNull() || a.IsUnknown() != b.IsUnknown() {
		return false
	}
	if a.IsNull() || a.IsUnknown() {
		return true
	}
	ae, be := a.Elements(), b.Elements()
	if len(ae) != len(be) {
		return false
	}
	seen := make(map[attr.Value]struct{}, len(ae))
	for _, e := range ae {
		seen[e] = struct{}{}
	}
	for _, e := range be {
		if _, ok := seen[e]; !ok {
			return false
		}
	}
	return true
}
