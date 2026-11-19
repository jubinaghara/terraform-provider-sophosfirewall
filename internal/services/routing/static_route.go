// Package routing implements static routes, custom gateways and SD-WAN routes.
package routing

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfos"
)

// BlackholeInterface is the pseudo interface of IPv4 blackhole routes.
const BlackholeInterface = "Blackhole"

type staticRouteModel struct {
	ID                     types.String `tfsdk:"id"`
	Name                   types.String `tfsdk:"name"`
	Description            types.String `tfsdk:"description"`
	Destination            types.String `tfsdk:"destination"`
	Gateway                types.String `tfsdk:"gateway"`
	Interface              types.String `tfsdk:"interface"`
	Metric                 types.Int64  `tfsdk:"metric"`
	AdministrativeDistance types.Int64  `tfsdk:"administrative_distance"`
}

type staticRoute struct {
	ID                     string        `json:"id,omitempty"`
	Name                   string        `json:"name"`
	Description            *string       `json:"description,omitempty"`
	DestinationAddress     string        `json:"destinationAddressIpv4,omitempty"`
	CIDR                   *int64        `json:"cidr,omitempty"`
	Gateway                *string       `json:"gatewayIpv4,omitempty"`
	Interface              *sfos.NameRef `json:"interface,omitempty"`
	Metric                 *int64        `json:"metric,omitempty"`
	AdministrativeDistance *int64        `json:"administrativeDistance,omitempty"`
}

// StaticRouteIPv4 manages /routing/static-unicast-routes/ipv4.
var StaticRouteIPv4 = &framework.Resource[staticRouteModel, staticRoute]{
	Name:  "static_route",
	Title: "static route",
	Path:  "/routing/static-unicast-routes/ipv4",
	Schema: schema.Schema{
		MarkdownDescription: "Manages an IPv4 unicast static route (*Configure > Routing > Static routes*). " +
			"Set `gateway`, `interface` or both; use `interface = \"" + BlackholeInterface + "\"` for a blackhole route. " +
			"When both are set the gateway must be on the interface's network.",
		Attributes: map[string]schema.Attribute{
			"id":          framework.IDAttribute(),
			"name":        framework.NameAttribute("static route", 20, true),
			"description": framework.DescriptionAttribute(255),
			"destination": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Destination network in CIDR notation, e.g. `192.168.10.0/24`. Use a `/32` for a host route.",
				Validators:          []validator.String{framework.Prefix(32, 0, 32)},
			},
			"gateway": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Next-hop IPv4 address.",
				Validators:          []validator.String{framework.IPAddress(32)},
			},
			"interface": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Name of the outgoing interface, e.g. `Port1`, or `" + BlackholeInterface + "` to drop matching traffic.",
				Validators:          []validator.String{framework.ObjectName()},
			},
			"metric": schema.Int64Attribute{
				Optional:            true,
				Computed:            true,
				Default:             int64default.StaticInt64(0),
				MarkdownDescription: "Routing metric (0-255). Defaults to `0`.",
				Validators:          []validator.Int64{int64validator.Between(0, 255)},
			},
			"administrative_distance": schema.Int64Attribute{
				Optional:            true,
				Computed:            true,
				Default:             int64default.StaticInt64(1),
				MarkdownDescription: "Administrative distance (1-255); lower values are preferred. Defaults to `1`.",
				Validators:          []validator.Int64{int64validator.Between(1, 255)},
			},
		},
	},
	Validate: func(_ context.Context, m *staticRouteModel, diags *diag.Diagnostics) {
		if m.Gateway.IsNull() && m.Interface.IsNull() {
			diags.AddAttributeError(path.Root("gateway"), "Missing next hop",
				"Set gateway, interface or both (use interface = \""+BlackholeInterface+"\" for a blackhole route).")
		}
		if m.Interface.ValueString() == BlackholeInterface && !m.Gateway.IsNull() && !m.Gateway.IsUnknown() {
			diags.AddAttributeError(path.Root("gateway"), "Unexpected gateway",
				"A blackhole route has no gateway; remove gateway or choose another interface.")
		}
	},
	Expand: func(_ context.Context, m *staticRouteModel, _ *diag.Diagnostics) *staticRoute {
		r := &staticRoute{
			Name:                   m.Name.ValueString(),
			Description:            framework.StringPtr(m.Description),
			Gateway:                framework.StringPtr(m.Gateway),
			Interface:              framework.Ref(m.Interface),
			Metric:                 framework.Int64Ptr(m.Metric),
			AdministrativeDistance: framework.Int64Ptr(m.AdministrativeDistance),
		}
		if d := framework.StringPtr(m.Destination); d != nil {
			if p, err := netip.ParsePrefix(*d); err == nil {
				r.DestinationAddress = p.Addr().String()
				r.CIDR = sfos.Ptr(int64(p.Bits()))
			}
		}
		return r
	},
	Flatten: func(_ context.Context, a *staticRoute, _ *staticRouteModel, _ *diag.Diagnostics) *staticRouteModel {
		m := &staticRouteModel{
			ID:                     types.StringValue(a.ID),
			Name:                   types.StringValue(a.Name),
			Description:            framework.StringOr(a.Description, ""),
			Destination:            types.StringNull(),
			Gateway:                types.StringNull(),
			Interface:              framework.RefName(a.Interface),
			Metric:                 types.Int64Value(0),
			AdministrativeDistance: types.Int64Value(1),
		}
		if a.DestinationAddress != "" {
			var bits int64 = 32
			if a.CIDR != nil {
				bits = *a.CIDR
			}
			m.Destination = types.StringValue(fmt.Sprintf("%s/%d", a.DestinationAddress, bits))
		}
		if a.Gateway != nil && *a.Gateway != "" {
			m.Gateway = types.StringValue(*a.Gateway)
		}
		if a.Metric != nil {
			m.Metric = types.Int64Value(*a.Metric)
		}
		if a.AdministrativeDistance != nil {
			m.AdministrativeDistance = types.Int64Value(*a.AdministrativeDistance)
		}
		return m
	},
}
