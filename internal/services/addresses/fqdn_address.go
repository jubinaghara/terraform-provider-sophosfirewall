package addresses

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
)

type fqdnAddressModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	FQDN        types.String `tfsdk:"fqdn"`
}

type fqdnAddress struct {
	ID          string  `json:"id,omitempty"`
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	FQDN        string  `json:"fqdn"`
}

// FQDNAddress manages /network/addresses/fqdn.
var FQDNAddress = &framework.Resource[fqdnAddressModel, fqdnAddress]{
	Name:  "fqdn_address",
	Title: "FQDN address object",
	Path:  "/network/addresses/fqdn",
	Schema: schema.Schema{
		MarkdownDescription: "Manages an FQDN address object (*Objects > Hosts and services > FQDN host*).",
		Attributes: map[string]schema.Attribute{
			"id":          framework.IDAttribute(),
			"name":        framework.NameAttribute("FQDN address object", 60, false),
			"description": framework.DescriptionAttribute(255),
			"fqdn": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Fully qualified domain name, e.g. `www.example.com` or `*.example.com`.",
				Validators:          []validator.String{stringvalidator.LengthBetween(1, 253)},
			},
		},
	},
	Expand: func(_ context.Context, m *fqdnAddressModel, _ *diag.Diagnostics) *fqdnAddress {
		return &fqdnAddress{
			Name:        m.Name.ValueString(),
			Description: framework.StringPtr(m.Description),
			FQDN:        m.FQDN.ValueString(),
		}
	},
	Flatten: func(_ context.Context, a *fqdnAddress, _ *fqdnAddressModel, _ *diag.Diagnostics) *fqdnAddressModel {
		return &fqdnAddressModel{
			ID:          types.StringValue(a.ID),
			Name:        types.StringValue(a.Name),
			Description: framework.StringOr(a.Description, ""),
			FQDN:        types.StringValue(a.FQDN),
		}
	},
}
