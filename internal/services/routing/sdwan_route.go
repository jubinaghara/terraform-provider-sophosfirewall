package routing

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/services/shared"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfos"
)

const sdwanRoutesPath = "/sd-wan/routes/ipv4"

// dscpMarkings are the values accepted for dscpMarking, verbatim from the API.
var dscpMarkings = []string{
	"0-Best Effort", "1", "2", "3", "4", "5", "6", "7", "8-Class 1(CS1)", "9", "10-Class 1,Gold(AF11)", "11",
	"12-Class1,Silver(AF12)", "13", "14-Class 1,Bronze(AF13)", "15", "16-Class 2(CS2)", "17", "18-Class 2,Gold(AF21)",
	"19", "20-Class 2,Silver(AF22)", "21", "22-Class 2,Bronze(AF23)", "23", "24-Class 3(CS3)", "25",
	"26-Class 3,Gold(AF31)", "27", "28-Class 3,Silver(AF32)", "29", "30-Class 3,Bronze(AF33)", "31", "32-Class 4(CS4)",
	"33", "34-Class 4,Gold(AF41)", "35", "36-Class 4,Silver(AF42)", "37", "38-Class 4,Bronze(AF43)", "39",
	"40-Class 5(CS5)", "41", "42", "43", "44", "45", "46-Expedited Forwarding(EF)", "47", "48-Control(CS6)", "49", "50",
	"51", "52", "53", "54", "55", "56-Control(CS7)", "57", "58", "59", "60", "61", "62", "63",
}

// ---- Terraform model ----

type sdwanRouteModel struct {
	ID                  types.String          `tfsdk:"id"`
	Name                types.String          `tfsdk:"name"`
	Description         types.String          `tfsdk:"description"`
	Enabled             types.Bool            `tfsdk:"enabled"`
	Position            types.String          `tfsdk:"position"`
	PositionReference   types.String          `tfsdk:"position_reference"`
	InboundInterface    types.String          `tfsdk:"inbound_interface"`
	SourceNetworks      *shared.NetworksModel `tfsdk:"source_networks"`
	DestinationNetworks *shared.NetworksModel `tfsdk:"destination_networks"`
	Services            types.Set             `tfsdk:"services"`
	ServiceGroups       types.Set             `tfsdk:"service_groups"`
	Applications        types.Set             `tfsdk:"applications"`
	Users               types.Set             `tfsdk:"users"`
	UserGroups          types.Set             `tfsdk:"user_groups"`
	DSCPMarking         types.String          `tfsdk:"dscp_marking"`
	LinkSelection       *linkSelectionModel   `tfsdk:"link_selection"`
}

func (m *sdwanRouteModel) position() shared.Position {
	return shared.Position{Position: m.Position, Reference: m.PositionReference}
}

type linkSelectionModel struct {
	SDWANProfile                types.String          `tfsdk:"sdwan_profile"`
	PrimaryGateway              *gatewaySelectorModel `tfsdk:"primary_gateway"`
	BackupGateway               *gatewaySelectorModel `tfsdk:"backup_gateway"`
	RouteThroughSpecificGateway types.Bool            `tfsdk:"route_through_specific_gateway"`
}

type gatewaySelectorModel struct {
	Name               types.String `tfsdk:"name"`
	WANLinkLoadBalance types.Bool   `tfsdk:"wan_link_load_balance"`
}

// ---- API payload ----

type sdwanRoute struct {
	ID                  string                            `json:"id,omitempty"`
	Name                string                            `json:"name"`
	Description         *string                           `json:"description,omitempty"`
	Enabled             *bool                             `json:"enabled,omitempty"`
	Position            string                            `json:"position,omitempty"`
	ReferenceItem       *sfos.NameRef                     `json:"referenceItem,omitempty"`
	InboundInterface    sfos.Selector[sfos.NameRef]       `json:"inboundInterface"`
	SourceNetworks      sfos.Selector[shared.NetworkList] `json:"sourceNetworks"`
	DestinationNetworks sfos.Selector[shared.NetworkList] `json:"destinationNetworks"`
	ServicesOrGroups    sfos.Selector[shared.ServiceList] `json:"servicesOrGroups"`
	Applications        sfos.Selector[applicationList]    `json:"applications"`
	UsersOrGroups       sfos.Selector[userList]           `json:"usersOrGroups"`
	DSCPMarking         *string                           `json:"dscpMarking,omitempty"`
	LinkSelection       linkSelection                     `json:"linkSelection"`
}

type applicationList struct {
	Objects []sfos.NameRef `json:"objects"`
}

type userList struct {
	Users      []sfos.NameRef `json:"users"`
	UserGroups []sfos.NameRef `json:"userGroups"`
}

type linkSelection struct {
	SDWANProfile                *sfos.NameRef     `json:"sdwanProfile,omitempty"`
	Gateway                     *gatewaySelection `json:"gateway,omitempty"`
	RouteThroughSpecificGateway *bool             `json:"routeThroughSpecificGateway,omitempty"`
}

type gatewaySelection struct {
	PrimaryGateway *gatewaySelector `json:"primaryGateway,omitempty"`
	BackupGateway  *gatewaySelector `json:"backupGateway,omitempty"`
}

// gatewaySelector is {"name": "..."} or {"wanLinkLoadBalance": true}.
type gatewaySelector struct {
	Name               string `json:"name,omitempty"`
	WANLinkLoadBalance bool   `json:"wanLinkLoadBalance,omitempty"`
}

// ---- Resource ----

// SDWANRouteIPv4 manages /sd-wan/routes/ipv4.
var SDWANRouteIPv4 = &framework.Resource[sdwanRouteModel, sdwanRoute]{
	Name:       "sdwan_route",
	Title:      "SD-WAN route",
	Path:       sdwanRoutesPath,
	Schema:     sdwanRouteSchema(),
	Expand:     expandSDWANRoute,
	Flatten:    flattenSDWANRoute,
	CreateOnly: []string{"position", "referenceItem"},
	Validate: func(_ context.Context, m *sdwanRouteModel, diags *diag.Diagnostics) {
		m.position().Validate(diags)
	},
	AfterUpdate: func(ctx context.Context, c *sfos.Client, plan, state *sdwanRouteModel, diags *diag.Diagnostics) {
		shared.MoveIfChanged(ctx, c, sdwanRoutesPath+"/move", plan.Name.ValueString(), plan.position(), state.position(), diags)
	},
}

func gatewaySelectorAttribute(description string) schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		Optional:            true,
		MarkdownDescription: description + " Set exactly one of `name` or `wan_link_load_balance`.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Name of the gateway (a custom gateway or a WAN interface gateway).",
				Validators: []validator.String{
					framework.ObjectName(),
					stringvalidator.ExactlyOneOf(path.MatchRelative().AtParent().AtName("wan_link_load_balance")),
				},
			},
			"wan_link_load_balance": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Load balance across the configured WAN gateways. Must be `true` when set.",
				Validators:          []validator.Bool{framework.BoolTrue()},
			},
		},
	}
}

func sdwanRouteSchema() schema.Schema {
	attrs := map[string]schema.Attribute{
		"id":          framework.IDAttribute(),
		"name":        framework.NameAttribute("SD-WAN route", 60, true),
		"description": framework.DescriptionAttribute(255),
		"enabled": schema.BoolAttribute{
			Computed:            true,
			MarkdownDescription: "Whether the route is active. The API reports the status but does not allow changing it.",
			PlanModifiers:       []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
		},
		"inbound_interface": schema.StringAttribute{
			Optional:            true,
			MarkdownDescription: "Name of the incoming interface to match. Omit to match any interface.",
			Validators:          []validator.String{framework.ObjectName()},
		},
		"source_networks":      shared.NetworksAttribute("Source addresses to match."),
		"destination_networks": shared.NetworksAttribute("Destination addresses to match."),
		"services":             framework.NameSetAttribute("Services to match. Omit both `services` and `service_groups` to match any service."),
		"service_groups":       framework.NameSetAttribute("Service groups to match."),
		"applications":         framework.NameSetAttribute("Application objects to match. Omit to match any application."),
		"users":                framework.NameSetAttribute("Users to match. Omit both `users` and `user_groups` to match any user."),
		"user_groups":          framework.NameSetAttribute("User groups to match."),
		"dscp_marking": schema.StringAttribute{
			Optional: true,
			MarkdownDescription: "DSCP value to mark matching traffic with, as listed by the firewall, " +
				"e.g. `0-Best Effort`, `46-Expedited Forwarding(EF)` or a plain number such as `5` (0-63).",
			Validators: []validator.String{stringvalidator.OneOf(dscpMarkings...)},
		},
		"link_selection": schema.SingleNestedAttribute{
			Required: true,
			MarkdownDescription: "How matching traffic leaves the firewall: set either `sdwan_profile` or " +
				"`primary_gateway` (optionally with `backup_gateway`). Switching between the two forces a new resource.",
			Attributes: map[string]schema.Attribute{
				"sdwan_profile": schema.StringAttribute{
					Optional:            true,
					MarkdownDescription: "Name of the SD-WAN profile that selects the gateway.",
					Validators: []validator.String{
						framework.ObjectName(),
						stringvalidator.ExactlyOneOf(path.MatchRelative().AtParent().AtName("primary_gateway")),
						stringvalidator.ConflictsWith(path.MatchRelative().AtParent().AtName("backup_gateway")),
					},
					PlanModifiers: []planmodifier.String{framework.ReplaceOnPresenceChange()},
				},
				"primary_gateway": gatewaySelectorAttribute("Primary gateway."),
				"backup_gateway":  gatewaySelectorAttribute("Gateway used when the primary gateway is down."),
				"route_through_specific_gateway": framework.BoolDefault(
					"Route only through the selected gateways, dropping traffic when they are unavailable.", false),
			},
		},
	}
	for k, v := range shared.PositionAttributes("SD-WAN route") {
		attrs[k] = v
	}
	return schema.Schema{
		MarkdownDescription: "Manages an IPv4 SD-WAN route (policy route, *Configure > Routing > SD-WAN routes*). " +
			"Routes are evaluated top to bottom; omitting a match criterion matches *any*.",
		Attributes: attrs,
	}
}

func expandGatewaySelector(m *gatewaySelectorModel) *gatewaySelector {
	switch {
	case m == nil:
		return nil
	case m.WANLinkLoadBalance.ValueBool():
		return &gatewaySelector{WANLinkLoadBalance: true}
	default:
		return &gatewaySelector{Name: m.Name.ValueString()}
	}
}

func flattenGatewaySelector(a *gatewaySelector) *gatewaySelectorModel {
	switch {
	case a == nil:
		return nil
	case a.WANLinkLoadBalance:
		return &gatewaySelectorModel{Name: types.StringNull(), WANLinkLoadBalance: types.BoolValue(true)}
	case a.Name != "":
		return &gatewaySelectorModel{Name: types.StringValue(a.Name), WANLinkLoadBalance: types.BoolNull()}
	}
	return nil
}

func expandSDWANRoute(ctx context.Context, m *sdwanRouteModel, diags *diag.Diagnostics) *sdwanRoute {
	pos, refItem := m.position().API()
	r := &sdwanRoute{
		Name:                m.Name.ValueString(),
		Description:         framework.StringPtr(m.Description),
		Position:            pos,
		ReferenceItem:       refItem,
		InboundInterface:    sfos.MatchAny[sfos.NameRef](),
		SourceNetworks:      shared.ExpandNetworks(ctx, m.SourceNetworks, diags),
		DestinationNetworks: shared.ExpandNetworks(ctx, m.DestinationNetworks, diags),
		ServicesOrGroups:    shared.ExpandServices(ctx, m.Services, m.ServiceGroups, diags),
		Applications:        sfos.MatchAny[applicationList](),
		UsersOrGroups:       sfos.MatchAny[userList](),
		DSCPMarking:         framework.StringPtr(m.DSCPMarking),
	}
	ls := m.LinkSelection
	if ls == nil {
		ls = &linkSelectionModel{}
	}
	r.LinkSelection = linkSelection{
		SDWANProfile:                framework.Ref(ls.SDWANProfile),
		RouteThroughSpecificGateway: framework.BoolPtr(ls.RouteThroughSpecificGateway),
	}
	if ref := framework.Ref(m.InboundInterface); ref != nil {
		r.InboundInterface = sfos.Match(*ref)
	}
	if !m.Applications.IsNull() {
		r.Applications = sfos.Match(applicationList{Objects: framework.Refs(ctx, m.Applications, diags)})
	}
	if !m.Users.IsNull() || !m.UserGroups.IsNull() {
		r.UsersOrGroups = sfos.Match(userList{
			Users:      framework.Refs(ctx, m.Users, diags),
			UserGroups: framework.Refs(ctx, m.UserGroups, diags),
		})
	}
	if primary := expandGatewaySelector(ls.PrimaryGateway); primary != nil {
		r.LinkSelection.Gateway = &gatewaySelection{
			PrimaryGateway: primary,
			BackupGateway:  expandGatewaySelector(ls.BackupGateway),
		}
	}
	return r
}

func flattenSDWANRoute(ctx context.Context, a *sdwanRoute, prior *sdwanRouteModel, diags *diag.Diagnostics) *sdwanRouteModel {
	m := &sdwanRouteModel{
		ID:                  types.StringValue(a.ID),
		Name:                types.StringValue(a.Name),
		Description:         framework.StringOr(a.Description, ""),
		Enabled:             framework.BoolOr(a.Enabled, true),
		Position:            types.StringNull(),
		PositionReference:   types.StringNull(),
		InboundInterface:    types.StringNull(),
		SourceNetworks:      shared.FlattenNetworks(ctx, a.SourceNetworks, diags),
		DestinationNetworks: shared.FlattenNetworks(ctx, a.DestinationNetworks, diags),
		Applications:        types.SetNull(types.StringType),
		Users:               types.SetNull(types.StringType),
		UserGroups:          types.SetNull(types.StringType),
		DSCPMarking:         types.StringPointerValue(a.DSCPMarking),
		LinkSelection: &linkSelectionModel{
			SDWANProfile:                framework.RefName(a.LinkSelection.SDWANProfile),
			RouteThroughSpecificGateway: framework.BoolOr(a.LinkSelection.RouteThroughSpecificGateway, false),
		},
	}
	if prior != nil {
		// Positions are write-only: keep what was configured.
		m.Position, m.PositionReference = prior.Position, prior.PositionReference
	}
	if !a.InboundInterface.Any {
		m.InboundInterface = framework.NonEmpty(a.InboundInterface.Items.Name)
	}
	m.Services, m.ServiceGroups = shared.FlattenServices(ctx, a.ServicesOrGroups, diags)
	if !a.Applications.Any {
		m.Applications = framework.RefSet(ctx, a.Applications.Items.Objects, diags)
	}
	if !a.UsersOrGroups.Any {
		m.Users = framework.RefSet(ctx, a.UsersOrGroups.Items.Users, diags)
		m.UserGroups = framework.RefSet(ctx, a.UsersOrGroups.Items.UserGroups, diags)
	}
	if g := a.LinkSelection.Gateway; g != nil {
		m.LinkSelection.PrimaryGateway = flattenGatewaySelector(g.PrimaryGateway)
		m.LinkSelection.BackupGateway = flattenGatewaySelector(g.BackupGateway)
	}
	if m.DSCPMarking.ValueString() == "" {
		m.DSCPMarking = types.StringNull()
	}
	return m
}
