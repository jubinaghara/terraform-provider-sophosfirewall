package addressgroups

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfos"
)

type ipv6Group struct {
	ID          string         `json:"id,omitempty"`
	Name        string         `json:"name"`
	Description *string        `json:"description,omitempty"`
	Addresses   []sfos.NameRef `json:"ipv6Addresses"`
}

// IPv6Group manages /network/address-groups/ipv6 (IPv6 host groups).
var IPv6Group = &framework.Resource[hostGroupModel, ipv6Group]{
	Name:   "ipv6_group",
	Title:  "IPv6 address group",
	Path:   "/network/address-groups/ipv6",
	Schema: hostGroupSchema("IPv6 address group", "IP host group", "IPv6 address", "sophosfirewall_ipv6_address"),
	Expand: func(ctx context.Context, m *hostGroupModel, diags *diag.Diagnostics) *ipv6Group {
		return &ipv6Group{
			Name:        m.Name.ValueString(),
			Description: framework.StringPtr(m.Description),
			Addresses:   framework.Refs(ctx, m.Addresses, diags),
		}
	},
	Flatten: func(ctx context.Context, a *ipv6Group, _ *hostGroupModel, diags *diag.Diagnostics) *hostGroupModel {
		return &hostGroupModel{
			ID:          types.StringValue(a.ID),
			Name:        types.StringValue(a.Name),
			Description: framework.StringOr(a.Description, ""),
			Addresses:   framework.RefSet(ctx, a.Addresses, diags),
		}
	},
}
