package framework

import (
	"reflect"

	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// MergePatch returns a JSON merge patch (RFC 7396) that turns oldObj into
// newObj, containing only what changed:
//
//   - keys that are new or changed carry the new value,
//   - keys that disappeared are set to null,
//   - nested objects are diffed recursively, arrays are replaced whole.
//
// One refinement handles the API's oneOf unions (e.g. {"any": true} versus
// {"zones": [...]}): when an object switches to a branch whose keys do not
// overlap with the old one, the new object is sent as-is. The API clears the
// previous branch itself, and nulling the old keys would produce a body that
// matches neither branch.
func MergePatch(oldObj, newObj map[string]any) map[string]any {
	patch := map[string]any{}
	for k, nv := range newObj {
		ov, existed := oldObj[k]
		switch {
		case !existed:
			patch[k] = nv
		case reflect.DeepEqual(ov, nv):
			// unchanged
		default:
			om, oldIsObj := ov.(map[string]any)
			nm, newIsObj := nv.(map[string]any)
			if oldIsObj && newIsObj && sharesKeys(om, nm) {
				patch[k] = MergePatch(om, nm)
			} else {
				patch[k] = nv
			}
		}
	}
	for k := range oldObj {
		if _, ok := newObj[k]; !ok {
			patch[k] = nil
		}
	}
	return patch
}

func sharesKeys(a, b map[string]any) bool {
	for k := range a {
		if _, ok := b[k]; ok {
			return true
		}
	}
	return false
}

// maskUnknown returns a copy of state in which every value that is unknown
// in plan is unknown as well. Expanding both into API payloads then yields
// identical (absent) fields for values the firewall computes.
func maskUnknown(plan, state tftypes.Value) (tftypes.Value, error) {
	return tftypes.Transform(state, func(p *tftypes.AttributePath, v tftypes.Value) (tftypes.Value, error) {
		pv, _, err := tftypes.WalkAttributePath(plan, p)
		if err != nil {
			return v, nil // path does not exist in the plan (e.g. removed set element)
		}
		if planned, ok := pv.(tftypes.Value); ok && !planned.IsKnown() {
			return tftypes.NewValue(v.Type(), tftypes.UnknownValue), nil
		}
		return v, nil
	})
}
