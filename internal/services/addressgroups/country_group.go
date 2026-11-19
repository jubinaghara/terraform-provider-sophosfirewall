// Package addressgroups implements grouping objects for network addresses.
package addressgroups

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfos"
)

type countryGroupModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Countries   types.Set    `tfsdk:"countries"`
}

type countryGroup struct {
	ID          string         `json:"id,omitempty"`
	Name        string         `json:"name"`
	Description *string        `json:"description,omitempty"`
	Countries   []sfos.NameRef `json:"countries"`
}

// CountryGroup manages /network/address-groups/country.
var CountryGroup = &framework.Resource[countryGroupModel, countryGroup]{
	Name:  "country_group",
	Title: "country group",
	Path:  "/network/address-groups/country",
	Schema: schema.Schema{
		MarkdownDescription: "Manages a country group (*Objects > Hosts and services > Country group*). " +
			"Country groups can be referenced from firewall and NAT rules.",
		Attributes: map[string]schema.Attribute{
			"id":          framework.IDAttribute(),
			"name":        framework.NameAttribute("country group", 60, false),
			"description": framework.DescriptionAttribute(255),
			"countries":   framework.NameSetAttribute("Names of the countries in the group, as known to the firewall."),
		},
	},
	Expand: func(ctx context.Context, m *countryGroupModel, diags *diag.Diagnostics) *countryGroup {
		return &countryGroup{
			Name:        m.Name.ValueString(),
			Description: framework.StringPtr(m.Description),
			Countries:   framework.Refs(ctx, m.Countries, diags),
		}
	},
	Flatten: func(ctx context.Context, a *countryGroup, _ *countryGroupModel, diags *diag.Diagnostics) *countryGroupModel {
		return &countryGroupModel{
			ID:          types.StringValue(a.ID),
			Name:        types.StringValue(a.Name),
			Description: framework.StringOr(a.Description, ""),
			Countries:   framework.RefSet(ctx, a.Countries, diags),
		}
	},
}
