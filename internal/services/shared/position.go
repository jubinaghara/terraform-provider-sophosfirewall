package shared

import (
	"context"
	"fmt"
	"strings"

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
	if err := move(ctx, c, movePath, name, pos, ref); err != nil {
		diags.AddError(fmt.Sprintf("Unable to move rule %q", name), err.Error())
	}
}

// move calls the /move endpoint. Although the API specification lists
// top and bottom, SFOS v23 move endpoints accept only before and after,
// so top and bottom are sent as before the first / after the last rule.
func move(ctx context.Context, c *sfos.Client, movePath, name, pos string, ref *sfos.NameRef) error {
	if pos == PositionTop || pos == PositionBottom {
		names, err := listNames(ctx, c, strings.TrimSuffix(movePath, "/move"))
		if err != nil {
			return err
		}
		var others []string
		for _, n := range names {
			if n != name {
				others = append(others, n)
			}
		}
		switch {
		case len(others) == 0:
			return nil // the only rule is already at the top and the bottom
		case pos == PositionTop && names[0] == name, pos == PositionBottom && names[len(names)-1] == name:
			return nil
		case pos == PositionTop:
			pos, ref = PositionBefore, &sfos.NameRef{Name: others[0]}
		default:
			pos, ref = PositionAfter, &sfos.NameRef{Name: others[len(others)-1]}
		}
	}
	return c.Post(ctx, movePath, moveRequest{Name: name, Position: pos, ReferenceItem: ref}, nil)
}

// maxListPages bounds listNames in case the API ignores the page parameter.
const maxListPages = 1000

// listNames returns the names of all objects in a collection, in order.
func listNames(ctx context.Context, c *sfos.Client, collection string) ([]string, error) {
	var names []string
	for page := 1; page <= maxListPages; page++ {
		var resp struct {
			Items []struct {
				Name string `json:"name"`
			} `json:"items"`
			Pages struct {
				Size int `json:"size"`
			} `json:"pages"`
		}
		if err := c.Get(ctx, fmt.Sprintf("%s?page=%d", collection, page), &resp); err != nil {
			return nil, err
		}
		if len(resp.Items) > 0 && len(names) > 0 && resp.Items[0].Name == names[0] {
			break // page parameter ignored: the first page was returned again
		}
		for _, it := range resp.Items {
			names = append(names, it.Name)
		}
		if len(resp.Items) == 0 || len(resp.Items) < resp.Pages.Size || resp.Pages.Size == 0 {
			break
		}
	}
	return names, nil
}
