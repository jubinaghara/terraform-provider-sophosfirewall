package shared

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfos"
)

// Rule positions accepted by the rule APIs.
const (
	PositionTop    = "top"
	PositionBottom = "bottom"
	PositionBefore = "before"
	PositionAfter  = "after"
)

// Position describes where an ordered rule sits. The firewall does not
// return it, so Terraform keeps the configured value and repositions the
// rule (via the collection's /move endpoint) whenever it changes.
type Position struct {
	Position  types.String
	Reference types.String
}

// PositionAttributes returns the "position" and "position_reference" attributes.
func PositionAttributes(kind string) map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"position": schema.StringAttribute{
			Optional: true,
			MarkdownDescription: fmt.Sprintf("Where to place the %s. %s New rules default to `bottom`. "+
				"The firewall does not report rule positions, so changes made outside Terraform are not detected.",
				kind, framework.OneOfMarkdown(PositionTop, PositionBottom, PositionBefore, PositionAfter)),
			Validators: []validator.String{stringvalidator.OneOf(PositionTop, PositionBottom, PositionBefore, PositionAfter)},
		},
		"position_reference": schema.StringAttribute{
			Optional:            true,
			MarkdownDescription: fmt.Sprintf("Name of the %s to place this one `before` or `after`. Required for those positions.", kind),
			Validators: []validator.String{
				framework.ObjectName(),
				stringvalidator.AlsoRequires(path.MatchRoot("position")),
			},
		},
	}
}

// Validate checks that a reference is given exactly when one is needed.
func (p Position) Validate(diags *diag.Diagnostics) {
	if p.Position.IsUnknown() || p.Reference.IsUnknown() {
		return
	}
	needsRef := p.Position.ValueString() == PositionBefore || p.Position.ValueString() == PositionAfter
	switch {
	case needsRef && p.Reference.IsNull():
		diags.AddAttributeError(path.Root("position_reference"), "Missing position reference",
			fmt.Sprintf("position_reference is required when position is %q.", p.Position.ValueString()))
	case !needsRef && !p.Reference.IsNull():
		diags.AddAttributeError(path.Root("position_reference"), "Unexpected position reference",
			"position_reference is only valid when position is \"before\" or \"after\".")
	}
}

// API returns the position and reference for a create request.
func (p Position) API() (string, *sfos.NameRef) {
	pos := p.Position.ValueString()
	if pos == "" {
		pos = PositionBottom
	}
	return pos, framework.Ref(p.Reference)
}

type moveRequest struct {
	Name          string        `json:"name"`
	Position      string        `json:"position"`
	ReferenceItem *sfos.NameRef `json:"referenceItem,omitempty"`
}

// MoveIfChanged repositions the rule named name when the planned position differs from state.
func MoveIfChanged(ctx context.Context, c *sfos.Client, movePath, name string, plan, state Position, diags *diag.Diagnostics) {
	if plan.Position.IsNull() || (plan.Position.Equal(state.Position) && plan.Reference.Equal(state.Reference)) {
		return
	}
	pos, ref := plan.API()
	if err := c.Post(ctx, movePath, moveRequest{Name: name, Position: pos, ReferenceItem: ref}, nil); err != nil {
		diags.AddError(fmt.Sprintf("Unable to move rule %q", name), err.Error())
	}
}
