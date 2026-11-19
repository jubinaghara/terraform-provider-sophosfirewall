package routing

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfos"
)

var (
	healthCheckProtocols = []string{"ping", "tcp"}
	logicalOperators     = []string{"and", "or"}
)

type gatewayModel struct {
	ID          types.String      `tfsdk:"id"`
	Name        types.String      `tfsdk:"name"`
	IPAddress   types.String      `tfsdk:"ip_address"`
	Interface   types.String      `tfsdk:"interface"`
	Zone        types.String      `tfsdk:"zone"`
	HealthCheck *healthCheckModel `tfsdk:"health_check"`
}

type healthCheckModel struct {
	Enabled  types.Bool             `tfsdk:"enabled"`
	Interval types.Int64            `tfsdk:"interval"`
	Timeout  types.Int64            `tfsdk:"timeout"`
	Retries  types.Int64            `tfsdk:"retries"`
	Rules    []healthCheckRuleModel `tfsdk:"rules"`
}

type healthCheckRuleModel struct {
	Protocol        types.String `tfsdk:"protocol"`
	Host            types.String `tfsdk:"host"`
	Port            types.Int64  `tfsdk:"port"`
	LogicalOperator types.String `tfsdk:"logical_operator"`
}

type gateway struct {
	ID          string        `json:"id,omitempty"`
	Name        string        `json:"name"`
	IPv4Address *string       `json:"ipv4Address,omitempty"`
	Interface   *sfos.NameRef `json:"interface,omitempty"`
	Zone        *sfos.NameRef `json:"zone,omitempty"`
	HealthCheck *healthCheck  `json:"healthCheck,omitempty"`
}

type healthCheck struct {
	Enabled               bool              `json:"enabled"`
	IntervalBetweenChecks *int64            `json:"intervalBetweenChecks,omitempty"`
	ResponseTimeout       *int64            `json:"responseTimeout,omitempty"`
	Retries               *int64            `json:"retries,omitempty"`
	Rules                 []healthCheckRule `json:"rules,omitempty"`
}

type healthCheckRule struct {
	Protocol        string          `json:"protocol"`
	Port            *int64          `json:"port,omitempty"`
	LogicalOperator *string         `json:"logicalOperator,omitempty"`
	Host            healthCheckHost `json:"host"`
}

type healthCheckHost struct {
	IPv4Address string `json:"ipv4Address"`
}

// GatewayIPv4 manages /routing/gateways/custom/ipv4.
var GatewayIPv4 = &framework.Resource[gatewayModel, gateway]{
	Name:    "gateway",
	Title:   "gateway",
	Path:    "/routing/gateways/custom/ipv4",
	Schema:  gatewaySchema(),
	Expand:  expandGateway,
	Flatten: flattenGateway,
	Validate: func(_ context.Context, m *gatewayModel, diags *diag.Diagnostics) {
		if m.HealthCheck == nil {
			return
		}
		for i, r := range m.HealthCheck.Rules {
			if r.Protocol.ValueString() == "ping" && !r.Port.IsNull() {
				diags.AddAttributeError(path.Root("health_check").AtName("rules").AtListIndex(i).AtName("port"),
					"Unexpected port", "port is only valid for the tcp protocol.")
			}
		}
	},
}

func computedInt64(description string, minimum, maximum int64) schema.Int64Attribute {
	return schema.Int64Attribute{
		Optional:            true,
		Computed:            true,
		MarkdownDescription: description + " Defaults to the firewall's setting.",
		Validators:          []validator.Int64{int64validator.Between(minimum, maximum)},
		PlanModifiers:       []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
	}
}

func gatewaySchema() schema.Schema {
	keep := []planmodifier.String{stringplanmodifier.UseStateForUnknown()}
	return schema.Schema{
		MarkdownDescription: "Manages a custom IPv4 gateway (*Configure > Routing > Gateways*). Gateways are referenced " +
			"by name from SD-WAN routes and SD-WAN profiles. The gateways the firewall creates for WAN interfaces " +
			"cannot be managed with this resource.",
		Attributes: map[string]schema.Attribute{
			"id":   framework.IDAttribute(),
			"name": framework.NameAttribute("gateway", 50, true),
			"ip_address": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "IPv4 address of the gateway.",
				Validators:          []validator.String{framework.IPAddress(32)},
			},
			"interface": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Name of the interface through which the gateway is reached.",
				Validators:          []validator.String{stringvalidator.LengthBetween(1, 58), framework.ObjectName()},
				PlanModifiers:       keep,
			},
			"zone": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Name of the zone of the gateway.",
				Validators:          []validator.String{stringvalidator.LengthBetween(1, 60), framework.ObjectName()},
				PlanModifiers:       keep,
			},
			"health_check": schema.SingleNestedAttribute{
				Optional: true,
				MarkdownDescription: "Gateway health check. A gateway that fails its health check is taken out of " +
					"SD-WAN routing. Omit to turn health checking off.",
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Required:            true,
						MarkdownDescription: "Whether health check monitoring is turned on.",
					},
					"interval": computedInt64("Time in seconds between checks (5-65535).", 5, 65535),
					"timeout":  computedInt64("Time in seconds to wait for a response (1-10).", 1, 10),
					"retries":  computedInt64("Failed checks before the gateway is considered unreachable (1-10).", 1, 10),
					"rules": schema.ListNestedAttribute{
						Optional:            true,
						MarkdownDescription: "Monitoring conditions (1-8), evaluated in order.",
						Validators:          []validator.List{listvalidator.SizeBetween(1, 8)},
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"protocol": schema.StringAttribute{
									Required:            true,
									MarkdownDescription: "Probe protocol. " + framework.OneOfMarkdown(healthCheckProtocols...),
									Validators:          []validator.String{stringvalidator.OneOf(healthCheckProtocols...)},
								},
								"host": schema.StringAttribute{
									Required:            true,
									MarkdownDescription: "IPv4 address to probe.",
									Validators:          []validator.String{framework.IPAddress(32)},
								},
								"port": schema.Int64Attribute{
									Optional:            true,
									MarkdownDescription: "TCP port to probe. Not applicable to `ping`.",
									Validators:          []validator.Int64{int64validator.Between(1, 65535)},
								},
								"logical_operator": schema.StringAttribute{
									Optional: true,
									Computed: true,
									Default:  stringdefault.StaticString("and"),
									MarkdownDescription: "How this condition combines with the previous ones. " +
										framework.OneOfMarkdown(logicalOperators...) + " Defaults to `and`.",
									Validators: []validator.String{stringvalidator.OneOf(logicalOperators...)},
								},
							},
						},
					},
				},
			},
		},
	}
}

func expandGateway(_ context.Context, m *gatewayModel, _ *diag.Diagnostics) *gateway {
	g := &gateway{
		Name:        m.Name.ValueString(),
		IPv4Address: framework.StringPtr(m.IPAddress),
		Interface:   framework.Ref(m.Interface),
		Zone:        framework.Ref(m.Zone),
		// Without a block the health check is switched off explicitly, so
		// removing the block disables a previously configured check.
		HealthCheck: &healthCheck{},
	}
	if h := m.HealthCheck; h != nil {
		g.HealthCheck = &healthCheck{
			Enabled:               h.Enabled.ValueBool(),
			IntervalBetweenChecks: framework.Int64Ptr(h.Interval),
			ResponseTimeout:       framework.Int64Ptr(h.Timeout),
			Retries:               framework.Int64Ptr(h.Retries),
		}
		// An enabled check is rejected unless all three timings are sent
		// ("Invalid healthCheck.responseTimeout"); fill in the web console
		// defaults for the ones left unset.
		if g.HealthCheck.Enabled {
			for _, d := range []struct {
				v   **int64
				def int64
			}{{&g.HealthCheck.IntervalBetweenChecks, 60}, {&g.HealthCheck.ResponseTimeout, 2}, {&g.HealthCheck.Retries, 3}} {
				if *d.v == nil {
					def := d.def
					*d.v = &def
				}
			}
		}
		for _, r := range h.Rules {
			g.HealthCheck.Rules = append(g.HealthCheck.Rules, healthCheckRule{
				Protocol:        r.Protocol.ValueString(),
				Port:            framework.Int64Ptr(r.Port),
				LogicalOperator: framework.StringPtr(r.LogicalOperator),
				Host:            healthCheckHost{IPv4Address: r.Host.ValueString()},
			})
		}
	}
	return g
}

func flattenGateway(_ context.Context, a *gateway, prior *gatewayModel, _ *diag.Diagnostics) *gatewayModel {
	m := &gatewayModel{
		ID:        types.StringValue(a.ID),
		Name:      types.StringValue(a.Name),
		IPAddress: types.StringPointerValue(a.IPv4Address),
		Interface: framework.RefName(a.Interface),
		Zone:      framework.RefName(a.Zone),
	}
	h := a.HealthCheck
	if h == nil {
		return m
	}
	// A disabled check without rules is the firewall's default: only show it
	// when the user manages the block.
	configured := prior != nil && prior.HealthCheck != nil
	if !configured && (prior != nil || (!h.Enabled && len(h.Rules) == 0)) {
		return m
	}
	hc := &healthCheckModel{
		Enabled:  types.BoolValue(h.Enabled),
		Interval: types.Int64PointerValue(h.IntervalBetweenChecks),
		Timeout:  types.Int64PointerValue(h.ResponseTimeout),
		Retries:  types.Int64PointerValue(h.Retries),
	}
	for _, r := range h.Rules {
		op := "and"
		if r.LogicalOperator != nil && *r.LogicalOperator != "" {
			op = *r.LogicalOperator
		}
		rm := healthCheckRuleModel{
			Protocol:        types.StringValue(r.Protocol),
			Host:            types.StringValue(r.Host.IPv4Address),
			Port:            types.Int64Null(),
			LogicalOperator: types.StringValue(op),
		}
		if r.Port != nil && *r.Port > 0 {
			rm.Port = types.Int64Value(*r.Port)
		}
		hc.Rules = append(hc.Rules, rm)
	}
	m.HealthCheck = hc
	return m
}
