// Package zones implements network zones.
package zones

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfos"
)

// Services is the list of device services that can be allowed on a zone.
var Services = []string{
	"https", "ssh", "dns", "dynamicRouting", "ping", "ping6", "sslVpn", "userPortal",
	"webProxy", "vpnPortal", "adSso", "captivePortal", "radiusSso", "clientAuthentication",
	"chromebookSso", "wirelessProtection", "smtpRelay", "snmp", "red", "ipsec",
}

type zoneModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Type        types.String `tfsdk:"type"`
	Description types.String `tfsdk:"description"`
	Services    types.Set    `tfsdk:"services"`
}

type zone struct {
	ID          string         `json:"id,omitempty"`
	Name        string         `json:"name"`
	Type        string         `json:"type"`
	Description *string        `json:"description,omitempty"`
	Services    []sfos.NameRef `json:"services"`
}

// Zone manages /network/zones.
var Zone = &framework.Resource[zoneModel, zone]{
	Name:  "zone",
	Title: "zone",
	Path:  "/network/zones",
	Schema: schema.Schema{
		MarkdownDescription: "Manages a custom zone (*Configure > Network > Zones*). Built-in zones such as `LAN` " +
			"or `WAN` cannot be created; read them with the `sophosfirewall_zone` data source instead.",
		Attributes: map[string]schema.Attribute{
			"id":   framework.IDAttribute(),
			"name": framework.NameAttribute("zone", 60, true),
			"type": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Zone type. " + framework.OneOfMarkdown("lan", "dmz") + " Changing this forces a new resource.",
				Validators:          []validator.String{stringvalidator.OneOf("lan", "dmz")},
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"description": framework.DescriptionAttribute(60),
			"services": schema.SetAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Device services the firewall offers to hosts in this zone. " + framework.OneOfMarkdown(Services...),
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(stringvalidator.OneOf(Services...)),
				},
			},
		},
	},
	CreateOnly: []string{"name", "type"},
	Expand: func(ctx context.Context, m *zoneModel, diags *diag.Diagnostics) *zone {
		return &zone{
			Name:        m.Name.ValueString(),
			Type:        m.Type.ValueString(),
			Description: framework.StringPtr(m.Description),
			Services:    framework.Refs(ctx, m.Services, diags),
		}
	},
	Flatten: func(ctx context.Context, a *zone, _ *zoneModel, diags *diag.Diagnostics) *zoneModel {
		return &zoneModel{
			ID:          types.StringValue(a.ID),
			Name:        types.StringValue(a.Name),
			Type:        types.StringValue(a.Type),
			Description: framework.StringOr(a.Description, ""),
			Services:    framework.RefSet(ctx, a.Services, diags),
		}
	},
}
