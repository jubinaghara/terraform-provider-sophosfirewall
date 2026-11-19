package framework

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Reusable attribute builders keep resource schemas short and consistent.

// IDAttribute is the computed UUID assigned by the firewall.
func IDAttribute() schema.StringAttribute {
	return schema.StringAttribute{
		Computed:            true,
		MarkdownDescription: "UUID of the object assigned by the firewall.",
		PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
	}
}

// NameAttribute is the unique, user supplied object name.
func NameAttribute(title string, maxLen int, forceNew bool) schema.StringAttribute {
	a := schema.StringAttribute{
		Required:            true,
		MarkdownDescription: fmt.Sprintf("Unique name of the %s.", title),
		Validators:          []validator.String{stringvalidator.LengthBetween(1, maxLen), ObjectName()},
	}
	if forceNew {
		a.MarkdownDescription += " Changing this forces a new resource."
		a.PlanModifiers = []planmodifier.String{stringplanmodifier.RequiresReplace()}
	}
	return a
}

// DescriptionAttribute is an optional free-text description defaulting to "".
func DescriptionAttribute(maxLen int) schema.StringAttribute {
	return schema.StringAttribute{
		Optional:            true,
		Computed:            true,
		Default:             stringdefault.StaticString(""),
		MarkdownDescription: "Free-text description.",
		Validators:          []validator.String{stringvalidator.LengthAtMost(maxLen)},
	}
}

// NameSetAttribute is an optional, non-empty set of referenced object names.
func NameSetAttribute(description string) schema.SetAttribute {
	return schema.SetAttribute{
		Optional:            true,
		ElementType:         types.StringType,
		MarkdownDescription: description,
		Validators:          []validator.Set{setvalidator.SizeAtLeast(1), setvalidator.ValueStringsAre(ObjectName())},
	}
}

// BoolDefault is an optional boolean with a static default.
func BoolDefault(description string, def bool) schema.BoolAttribute {
	return schema.BoolAttribute{
		Optional:            true,
		Computed:            true,
		Default:             booldefault.StaticBool(def),
		MarkdownDescription: fmt.Sprintf("%s Defaults to `%t`.", description, def),
	}
}

// Enum is an optional string restricted to the given values.
func Enum(description string, values ...string) schema.StringAttribute {
	return schema.StringAttribute{
		Optional:            true,
		MarkdownDescription: description + " " + OneOfMarkdown(values...),
		Validators:          []validator.String{stringvalidator.OneOf(values...)},
	}
}

// OneOfMarkdown renders "One of `a`, `b`." for attribute documentation.
func OneOfMarkdown(values ...string) string {
	s := "One of "
	for i, v := range values {
		if i > 0 {
			s += ", "
		}
		s += "`" + v + "`"
	}
	return s + "."
}

// ReplaceOnPresenceChange forces replacement when an optional string
// switches between set and unset (e.g. changing the kind of an address).
func ReplaceOnPresenceChange() planmodifier.String {
	return stringplanmodifier.RequiresReplaceIf(
		func(_ context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
			resp.RequiresReplace = req.StateValue.IsNull() != req.PlanValue.IsNull()
		},
		"Switching between set and unset forces a new resource.",
		"Switching between set and unset forces a new resource.",
	)
}

// ReplaceSetOnPresenceChange is ReplaceOnPresenceChange for set attributes.
func ReplaceSetOnPresenceChange() planmodifier.Set {
	return setplanmodifier.RequiresReplaceIf(
		func(_ context.Context, req planmodifier.SetRequest, resp *setplanmodifier.RequiresReplaceIfFuncResponse) {
			resp.RequiresReplace = req.StateValue.IsNull() != req.PlanValue.IsNull()
		},
		"Switching between set and unset forces a new resource.",
		"Switching between set and unset forces a new resource.",
	)
}
