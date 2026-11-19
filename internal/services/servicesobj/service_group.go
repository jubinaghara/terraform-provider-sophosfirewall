package servicesobj

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfos"
)

type serviceGroupModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Services    types.Set    `tfsdk:"services"`
}

type serviceGroup struct {
	ID          string         `json:"id,omitempty"`
	Name        string         `json:"name"`
	Description *string        `json:"description,omitempty"`
	Services    []sfos.NameRef `json:"services"`
}

// ServiceGroup manages /network/service-groups.
var ServiceGroup = &framework.Resource[serviceGroupModel, serviceGroup]{
	Name:  "service_group",
	Title: "service group",
	Path:  "/network/service-groups",
	Schema: schema.Schema{
		MarkdownDescription: "Manages a service group (*Objects > Hosts and services > Service groups*). " +
			"Service groups can be referenced from firewall rules.",
		Attributes: map[string]schema.Attribute{
			"id":          framework.IDAttribute(),
			"name":        framework.NameAttribute("service group", 60, false),
			"description": framework.DescriptionAttribute(255),
			"services": schema.SetAttribute{
				Required:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Names of the member services, e.g. `HTTPS` or a `sophosfirewall_service` name.",
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(stringvalidator.LengthBetween(1, 50), framework.ObjectName()),
				},
			},
		},
	},
	Expand: func(ctx context.Context, m *serviceGroupModel, diags *diag.Diagnostics) *serviceGroup {
		return &serviceGroup{
			Name:        m.Name.ValueString(),
			Description: framework.StringPtr(m.Description),
			Services:    framework.Refs(ctx, m.Services, diags),
		}
	},
	Flatten: func(ctx context.Context, a *serviceGroup, _ *serviceGroupModel, diags *diag.Diagnostics) *serviceGroupModel {
		return &serviceGroupModel{
			ID:          types.StringValue(a.ID),
			Name:        types.StringValue(a.Name),
			Description: framework.StringOr(a.Description, ""),
			Services:    framework.RefSet(ctx, a.Services, diags),
		}
	},
}
