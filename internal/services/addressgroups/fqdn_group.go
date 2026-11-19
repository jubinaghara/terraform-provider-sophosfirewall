package addressgroups

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfos"
)

type fqdnGroup struct {
	ID          string         `json:"id,omitempty"`
	Name        string         `json:"name"`
	Description *string        `json:"description,omitempty"`
	Addresses   []sfos.NameRef `json:"fqdns"`
}

// FQDNGroup manages /network/address-groups/fqdn (FQDN host groups).
var FQDNGroup = &framework.Resource[hostGroupModel, fqdnGroup]{
	Name:   "fqdn_group",
	Title:  "FQDN address group",
	Path:   "/network/address-groups/fqdn",
	Schema: hostGroupSchema("FQDN address group", "FQDN host group", "FQDN address", "sophosfirewall_fqdn_address"),
	Expand: func(ctx context.Context, m *hostGroupModel, diags *diag.Diagnostics) *fqdnGroup {
		return &fqdnGroup{
			Name:        m.Name.ValueString(),
			Description: framework.StringPtr(m.Description),
			Addresses:   framework.Refs(ctx, m.Addresses, diags),
		}
	},
	Flatten: func(ctx context.Context, a *fqdnGroup, _ *hostGroupModel, diags *diag.Diagnostics) *hostGroupModel {
		return &hostGroupModel{
			ID:          types.StringValue(a.ID),
			Name:        types.StringValue(a.Name),
			Description: framework.StringOr(a.Description, ""),
			Addresses:   framework.RefSet(ctx, a.Addresses, diags),
		}
	},
}
