// Package firewall implements firewall rules.
package firewall

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/services/shared"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfos"
)

const ipv4RulesPath = "/firewall/rules/ipv4"

// ---- Terraform model ----

type ruleModel struct {
	ID                  types.String          `tfsdk:"id"`
	Name                types.String          `tfsdk:"name"`
	Description         types.String          `tfsdk:"description"`
	Enabled             types.Bool            `tfsdk:"enabled"`
	Action              types.String          `tfsdk:"action"`
	LogTraffic          types.Bool            `tfsdk:"log_traffic"`
	Position            types.String          `tfsdk:"position"`
	PositionReference   types.String          `tfsdk:"position_reference"`
	SourceZones         types.Set             `tfsdk:"source_zones"`
	DestinationZones    types.Set             `tfsdk:"destination_zones"`
	SourceNetworks      *shared.NetworksModel `tfsdk:"source_networks"`
	DestinationNetworks *shared.NetworksModel `tfsdk:"destination_networks"`
	Services            types.Set             `tfsdk:"services"`
	ServiceGroups       types.Set             `tfsdk:"service_groups"`
	Schedule            types.String          `tfsdk:"schedule"`
	UserAuthentication  *userAuthModel        `tfsdk:"user_authentication"`
	Exclusions          *exclusionsModel      `tfsdk:"exclusions"`
	SecurityFeatures    *securityModel        `tfsdk:"security_features"`
	EmailScanning       *emailScanningModel   `tfsdk:"email_scanning"`
	QoS                 *qosModel             `tfsdk:"qos"`
	Heartbeat           *heartbeatModel       `tfsdk:"synchronized_security_heartbeat"`
}

func (m *ruleModel) position() shared.Position {
	return shared.Position{Position: m.Position, Reference: m.PositionReference}
}

type userAuthModel struct {
	Users                  types.Set  `tfsdk:"users"`
	UserGroups             types.Set  `tfsdk:"user_groups"`
	ExcludeFromAccounting  types.Bool `tfsdk:"exclude_from_accounting"`
	WebAuthForUnknownUsers types.Bool `tfsdk:"web_authentication_for_unknown_users"`
}

type exclusionsModel struct {
	SourceZones         types.Set             `tfsdk:"source_zones"`
	DestinationZones    types.Set             `tfsdk:"destination_zones"`
	SourceNetworks      *shared.NetworksModel `tfsdk:"source_networks"`
	DestinationNetworks *shared.NetworksModel `tfsdk:"destination_networks"`
	Services            types.Set             `tfsdk:"services"`
	ServiceGroups       types.Set             `tfsdk:"service_groups"`
}

type securityModel struct {
	WebPolicy                 types.String `tfsdk:"web_policy"`
	ApplicationPolicy         types.String `tfsdk:"application_policy"`
	IPSPolicy                 types.String `tfsdk:"ips_policy"`
	ScanHTTPAndDecryptedHTTPS types.Bool   `tfsdk:"scan_http_and_decrypted_https"`
	ZeroDayProtection         types.Bool   `tfsdk:"zero_day_protection"`
	ScanFTP                   types.Bool   `tfsdk:"scan_ftp"`
	WebProxy                  types.Bool   `tfsdk:"web_proxy"`
	DecryptHTTPSWebProxyMode  types.Bool   `tfsdk:"decrypt_https_web_proxy_mode"`
	BlockQUICProtocol         types.Bool   `tfsdk:"block_quic_protocol"`
	WebCategoryBasedQoSPolicy types.Bool   `tfsdk:"web_category_based_qos_policy"`
	ApplicationBasedQoSPolicy types.Bool   `tfsdk:"application_based_qos_policy"`
	ScanWithNDRThreatIntel    types.Bool   `tfsdk:"scan_with_ndr_active_threat_intelligence"`
}

type emailScanningModel struct {
	SMTP  types.Bool `tfsdk:"smtp"`
	SMTPS types.Bool `tfsdk:"smtps"`
	IMAP  types.Bool `tfsdk:"imap"`
	IMAPS types.Bool `tfsdk:"imaps"`
	POP3  types.Bool `tfsdk:"pop3"`
	POP3S types.Bool `tfsdk:"pop3s"`
}

type qosModel struct {
	TrafficShapingPolicy types.String `tfsdk:"traffic_shaping_policy"`
	DSCPMarking          types.String `tfsdk:"dscp_marking"`
}

type heartbeatModel struct {
	SourceMinimumLevel               types.String `tfsdk:"source_minimum_level"`
	BlockSourceWithoutHeartbeat      types.Bool   `tfsdk:"block_source_without_heartbeat"`
	DestinationMinimumLevel          types.String `tfsdk:"destination_minimum_level"`
	BlockDestinationWithoutHeartbeat types.Bool   `tfsdk:"block_destination_without_heartbeat"`
}

// ---- API payload ----

type rule struct {
	ID                  string                            `json:"id,omitempty"`
	Name                string                            `json:"name"`
	Description         *string                           `json:"description,omitempty"`
	RuleType            string                            `json:"ruleType,omitempty"`
	Enabled             *bool                             `json:"enabled,omitempty"`
	Action              *string                           `json:"action,omitempty"`
	SourceZones         sfos.Selector[shared.ZoneList]    `json:"sourceZones"`
	DestinationZones    sfos.Selector[shared.ZoneList]    `json:"destinationZones"`
	SourceNetworks      sfos.Selector[shared.NetworkList] `json:"sourceNetworks"`
	DestinationNetworks sfos.Selector[shared.NetworkList] `json:"destinationNetworks"`
	ServicesOrGroups    sfos.Selector[shared.ServiceList] `json:"servicesOrGroups"`
	UserAuthentication  *userAuthentication               `json:"userAuthentication,omitempty"`
	Exclusions          *exclusions                       `json:"exclusions,omitempty"`
	Heartbeat           *heartbeat                        `json:"synchronizedSecurityHeartbeat,omitempty"`
	SecurityFeatures    *securityFeatures                 `json:"securityFeatures,omitempty"`
	EmailScanning       *emailScanning                    `json:"emailScanning,omitempty"`
	QoS                 *qos                              `json:"qos,omitempty"`
	LogTraffic          *bool                             `json:"logTraffic,omitempty"`
	Schedule            *sfos.NameRef                     `json:"schedule,omitempty"`
	Position            string                            `json:"position,omitempty"`
	ReferenceItem       *sfos.NameRef                     `json:"referenceItem,omitempty"`
}

type userList struct {
	Users      []sfos.NameRef `json:"users"`
	UserGroups []sfos.NameRef `json:"userGroups"`
}

type userAuthentication struct {
	UsersOrGroups                    *sfos.Selector[userList] `json:"usersOrGroups,omitempty"`
	ExcludeUsersFromAccounting       *bool                    `json:"excludeUsersFromAccounting,omitempty"`
	WebAuthenticationForUnknownUsers *bool                    `json:"webAuthenticationForUnknownUsers,omitempty"`
}

type exclusions struct {
	SourceZones         shared.ZoneList    `json:"sourceZones"`
	DestinationZones    shared.ZoneList    `json:"destinationZones"`
	SourceNetworks      shared.NetworkList `json:"sourceNetworks"`
	DestinationNetworks shared.NetworkList `json:"destinationNetworks"`
	ServicesOrGroups    shared.ServiceList `json:"servicesOrGroups"`
}

type heartbeatSide struct {
	BlockClientsWithNoHeartbeat *bool   `json:"blockClientsWithNoHeartbeat,omitempty"`
	MinimumLevel                *string `json:"minimumLevel,omitempty"`
}

type heartbeat struct {
	Source      *heartbeatSide `json:"source,omitempty"`
	Destination *heartbeatSide `json:"destination,omitempty"`
}

type securityFeatures struct {
	WebPolicy                           *sfos.NameRef `json:"webPolicy,omitempty"`
	ApplicationPolicy                   *sfos.NameRef `json:"applicationPolicy,omitempty"`
	IPSPolicy                           *sfos.NameRef `json:"ipsPolicy,omitempty"`
	ScanHTTPAndDecryptedHTTPS           *bool         `json:"scanHttpAndDecryptedHttps,omitempty"`
	ZeroDayProtection                   *bool         `json:"zeroDayProtection,omitempty"`
	ScanFTP                             *bool         `json:"scanFtp,omitempty"`
	WebProxy                            *bool         `json:"webProxy,omitempty"`
	DecryptHTTPSWebProxyMode            *bool         `json:"decryptHTTPSWebProxyMode,omitempty"`
	BlockQUICProtocol                   *bool         `json:"blockQuicProtocol,omitempty"`
	WebCategoryBasedQoSPolicy           *bool         `json:"webCategoryBasedQosPolicy,omitempty"`
	ApplicationBasedQoSPolicy           *bool         `json:"applicationBasedQosPolicy,omitempty"`
	ScanWithNDRActiveThreatIntelligence *bool         `json:"scanWithNdrActiveThreatIntelligence,omitempty"`
}

type emailScanning struct {
	SMTP  *bool `json:"smtp,omitempty"`
	SMTPS *bool `json:"smtps,omitempty"`
	IMAP  *bool `json:"imap,omitempty"`
	IMAPS *bool `json:"imaps,omitempty"`
	POP3  *bool `json:"pop3,omitempty"`
	POP3S *bool `json:"pop3s,omitempty"`
}

type qos struct {
	TrafficShapingPolicy *sfos.NameRef `json:"trafficShapingPolicy,omitempty"`
	DSCPMarking          *string       `json:"dscpMarking,omitempty"`
}

// ---- Resource ----

// RuleIPv4 manages /firewall/rules/ipv4 (rules of type "firewall").
var RuleIPv4 = &framework.Resource[ruleModel, rule]{
	Name:       "firewall_rule",
	Title:      "firewall rule",
	Path:       ipv4RulesPath,
	Schema:     ruleSchema(),
	Expand:     expandRule,
	Flatten:    flattenRule,
	CreateOnly: []string{"ruleType", "position", "referenceItem"},
	Validate: func(_ context.Context, m *ruleModel, diags *diag.Diagnostics) {
		m.position().Validate(diags)
	},
	AfterUpdate: func(ctx context.Context, c *sfos.Client, plan, state *ruleModel, diags *diag.Diagnostics) {
		shared.MoveIfChanged(ctx, c, ipv4RulesPath+"/move", plan.Name.ValueString(), plan.position(), state.position(), diags)
	},
}

var heartbeatLevels = []string{"noRestriction", "green", "yellow"}

func ruleSchema() schema.Schema {
	flag := framework.BoolDefault
	ref := func(desc string) schema.StringAttribute {
		return schema.StringAttribute{Optional: true, MarkdownDescription: desc, Validators: []validator.String{framework.ObjectName()}}
	}
	level := func(desc string) schema.StringAttribute {
		return schema.StringAttribute{
			Optional: true, Computed: true,
			Default:             stringdefault.StaticString("noRestriction"),
			MarkdownDescription: desc + " " + framework.OneOfMarkdown(heartbeatLevels...) + " Defaults to `noRestriction`.",
			Validators:          []validator.String{stringvalidator.OneOf(heartbeatLevels...)},
		}
	}

	attrs := map[string]schema.Attribute{
		"id":          framework.IDAttribute(),
		"name":        framework.NameAttribute("firewall rule", 60, false),
		"description": framework.DescriptionAttribute(255),
		"enabled":     flag("Whether the rule is active.", true),
		"action": schema.StringAttribute{
			Optional: true, Computed: true,
			Default:             stringdefault.StaticString("accept"),
			MarkdownDescription: "Action for matching traffic. " + framework.OneOfMarkdown("accept", "drop", "reject") + " Defaults to `accept`.",
			Validators:          []validator.String{stringvalidator.OneOf("accept", "drop", "reject")},
		},
		"log_traffic":          flag("Log traffic matching the rule.", false),
		"source_zones":         framework.NameSetAttribute("Source zones. Omit to match any zone."),
		"destination_zones":    framework.NameSetAttribute("Destination zones. Omit to match any zone."),
		"source_networks":      shared.NetworksAttribute("Source networks and devices."),
		"destination_networks": shared.NetworksAttribute("Destination networks."),
		"services":             framework.NameSetAttribute("Names of services. Omit both `services` and `service_groups` to match any service."),
		"service_groups":       framework.NameSetAttribute("Names of service groups."),
		"schedule":             ref("Name of the schedule during which the rule is active. Omit for always."),
		"user_authentication": schema.SingleNestedAttribute{
			Optional:            true,
			MarkdownDescription: "Match known users. When set, the rule applies only to authenticated users and their user-based policies apply.",
			Attributes: map[string]schema.Attribute{
				"users":                                framework.NameSetAttribute("Names of users. Omit both `users` and `user_groups` to match any known user."),
				"user_groups":                          framework.NameSetAttribute("Names of user groups."),
				"exclude_from_accounting":              flag("Exclude this traffic from user data accounting.", false),
				"web_authentication_for_unknown_users": flag("Use web authentication for unknown users.", false),
			},
		},
		"exclusions": schema.SingleNestedAttribute{
			Optional:            true,
			MarkdownDescription: "Traffic excluded from the rule.",
			Attributes: map[string]schema.Attribute{
				"source_zones":         framework.NameSetAttribute("Excluded source zones."),
				"destination_zones":    framework.NameSetAttribute("Excluded destination zones."),
				"source_networks":      shared.NetworksAttribute("Excluded source networks."),
				"destination_networks": shared.NetworksAttribute("Excluded destination networks."),
				"services":             framework.NameSetAttribute("Excluded services."),
				"service_groups":       framework.NameSetAttribute("Excluded service groups."),
			},
		},
		"security_features": schema.SingleNestedAttribute{
			Optional: true,
			MarkdownDescription: "Security features applied to allowed traffic. Only valid when `action` is `accept`. " +
				"When `web_policy` is unset and `scan_http_and_decrypted_https` is false, `web_proxy`, `web_category_based_qos_policy`, " +
				"`block_quic_protocol` and `decrypt_https_web_proxy_mode` must be false.",
			Attributes: map[string]schema.Attribute{
				"web_policy":                               ref("Name of the web policy."),
				"application_policy":                       ref("Name of the application control policy."),
				"ips_policy":                               ref("Name of the intrusion prevention policy."),
				"scan_http_and_decrypted_https":            flag("Scan HTTP and decrypted HTTPS.", false),
				"zero_day_protection":                      flag("Use zero-day protection (requires HTTP scanning).", false),
				"scan_ftp":                                 flag("Scan FTP for malware.", false),
				"web_proxy":                                flag("Use the web proxy instead of the DPI engine.", false),
				"decrypt_https_web_proxy_mode":             flag("Decrypt HTTPS in web proxy mode.", false),
				"block_quic_protocol":                      flag("Block QUIC traffic.", false),
				"web_category_based_qos_policy":            flag("Apply web category based traffic shaping.", false),
				"application_based_qos_policy":             flag("Apply application based traffic shaping.", false),
				"scan_with_ndr_active_threat_intelligence": flag("Scan with NDR active threat intelligence.", false),
			},
		},
		"email_scanning": schema.SingleNestedAttribute{
			Optional:            true,
			MarkdownDescription: "Email protocols to scan.",
			Attributes: map[string]schema.Attribute{
				"smtp":  flag("Scan SMTP.", false),
				"smtps": flag("Scan SMTPS.", false),
				"imap":  flag("Scan IMAP.", false),
				"imaps": flag("Scan IMAPS.", false),
				"pop3":  flag("Scan POP3.", false),
				"pop3s": flag("Scan POP3S.", false),
			},
		},
		"qos": schema.SingleNestedAttribute{
			Optional:            true,
			MarkdownDescription: "Traffic shaping. Ignored for user-based rules, which use the user's policy.",
			Attributes: map[string]schema.Attribute{
				"traffic_shaping_policy": ref("Name of the traffic shaping policy."),
				"dscp_marking": schema.StringAttribute{
					Optional:            true,
					MarkdownDescription: "DSCP marking as shown by the firewall, e.g. `46-Expedited Forwarding(EF)`.",
				},
			},
		},
		"synchronized_security_heartbeat": schema.SingleNestedAttribute{
			Optional:            true,
			MarkdownDescription: "Synchronized Security Heartbeat enforcement.",
			Attributes: map[string]schema.Attribute{
				"source_minimum_level":                level("Minimum heartbeat required from source devices."),
				"block_source_without_heartbeat":      flag("Block source clients without a heartbeat.", false),
				"destination_minimum_level":           level("Minimum heartbeat required from destination devices."),
				"block_destination_without_heartbeat": flag("Block destination clients without a heartbeat.", false),
			},
		},
	}
	for k, v := range shared.PositionAttributes("firewall rule") {
		attrs[k] = v
	}

	return schema.Schema{
		MarkdownDescription: "Manages an IPv4 firewall rule (*Protect > Rules and policies > Firewall rules*). " +
			"Zones, networks and services reference other objects by name; omitting a match criterion matches *any*.",
		Attributes: attrs,
	}
}

func expandRule(ctx context.Context, m *ruleModel, diags *diag.Diagnostics) *rule {
	pos, refItem := m.position().API()
	r := &rule{
		Name:                m.Name.ValueString(),
		Description:         framework.StringPtr(m.Description),
		RuleType:            "firewall",
		Enabled:             framework.BoolPtr(m.Enabled),
		Action:              framework.StringPtr(m.Action),
		LogTraffic:          framework.BoolPtr(m.LogTraffic),
		SourceZones:         shared.ExpandZones(ctx, m.SourceZones, diags),
		DestinationZones:    shared.ExpandZones(ctx, m.DestinationZones, diags),
		SourceNetworks:      shared.ExpandNetworks(ctx, m.SourceNetworks, diags),
		DestinationNetworks: shared.ExpandNetworks(ctx, m.DestinationNetworks, diags),
		ServicesOrGroups:    shared.ExpandServices(ctx, m.Services, m.ServiceGroups, diags),
		Schedule:            framework.Ref(m.Schedule),
		Position:            pos,
		ReferenceItem:       refItem,
	}

	if u := m.UserAuthentication; u != nil {
		sel := sfos.MatchAny[userList]()
		if !u.Users.IsNull() || !u.UserGroups.IsNull() {
			sel = sfos.Match(userList{Users: framework.Refs(ctx, u.Users, diags), UserGroups: framework.Refs(ctx, u.UserGroups, diags)})
		}
		r.UserAuthentication = &userAuthentication{
			UsersOrGroups:                    &sel,
			ExcludeUsersFromAccounting:       framework.BoolPtr(u.ExcludeFromAccounting),
			WebAuthenticationForUnknownUsers: framework.BoolPtr(u.WebAuthForUnknownUsers),
		}
	}
	if e := m.Exclusions; e != nil {
		r.Exclusions = &exclusions{
			SourceZones:         shared.ZoneList{Zones: framework.Refs(ctx, e.SourceZones, diags)},
			DestinationZones:    shared.ZoneList{Zones: framework.Refs(ctx, e.DestinationZones, diags)},
			SourceNetworks:      shared.ExpandNetworkList(ctx, e.SourceNetworks, diags),
			DestinationNetworks: shared.ExpandNetworkList(ctx, e.DestinationNetworks, diags),
			ServicesOrGroups:    shared.ServiceList{Services: framework.Refs(ctx, e.Services, diags), ServiceGroups: framework.Refs(ctx, e.ServiceGroups, diags)},
		}
	}
	if s := m.SecurityFeatures; s != nil {
		r.SecurityFeatures = &securityFeatures{
			WebPolicy:                           framework.Ref(s.WebPolicy),
			ApplicationPolicy:                   framework.Ref(s.ApplicationPolicy),
			IPSPolicy:                           framework.Ref(s.IPSPolicy),
			ScanHTTPAndDecryptedHTTPS:           framework.BoolPtr(s.ScanHTTPAndDecryptedHTTPS),
			ZeroDayProtection:                   framework.BoolPtr(s.ZeroDayProtection),
			ScanFTP:                             framework.BoolPtr(s.ScanFTP),
			WebProxy:                            framework.BoolPtr(s.WebProxy),
			DecryptHTTPSWebProxyMode:            framework.BoolPtr(s.DecryptHTTPSWebProxyMode),
			BlockQUICProtocol:                   framework.BoolPtr(s.BlockQUICProtocol),
			WebCategoryBasedQoSPolicy:           framework.BoolPtr(s.WebCategoryBasedQoSPolicy),
			ApplicationBasedQoSPolicy:           framework.BoolPtr(s.ApplicationBasedQoSPolicy),
			ScanWithNDRActiveThreatIntelligence: framework.BoolPtr(s.ScanWithNDRThreatIntel),
		}
	}
	if e := m.EmailScanning; e != nil {
		r.EmailScanning = &emailScanning{
			SMTP: framework.BoolPtr(e.SMTP), SMTPS: framework.BoolPtr(e.SMTPS),
			IMAP: framework.BoolPtr(e.IMAP), IMAPS: framework.BoolPtr(e.IMAPS),
			POP3: framework.BoolPtr(e.POP3), POP3S: framework.BoolPtr(e.POP3S),
		}
	}
	if q := m.QoS; q != nil {
		r.QoS = &qos{TrafficShapingPolicy: framework.Ref(q.TrafficShapingPolicy), DSCPMarking: framework.StringPtr(q.DSCPMarking)}
	}
	if h := m.Heartbeat; h != nil {
		r.Heartbeat = &heartbeat{
			Source:      &heartbeatSide{BlockClientsWithNoHeartbeat: framework.BoolPtr(h.BlockSourceWithoutHeartbeat), MinimumLevel: framework.StringPtr(h.SourceMinimumLevel)},
			Destination: &heartbeatSide{BlockClientsWithNoHeartbeat: framework.BoolPtr(h.BlockDestinationWithoutHeartbeat), MinimumLevel: framework.StringPtr(h.DestinationMinimumLevel)},
		}
	}
	return r
}

func flattenRule(ctx context.Context, a *rule, prior *ruleModel, diags *diag.Diagnostics) *ruleModel {
	if a.RuleType != "" && a.RuleType != "firewall" {
		diags.AddError("Unsupported rule type",
			fmt.Sprintf("Rule %q has type %q; sophosfirewall_firewall_rule only manages rules of type \"firewall\".", a.Name, a.RuleType))
		return nil
	}
	m := &ruleModel{
		ID:                  types.StringValue(a.ID),
		Name:                types.StringValue(a.Name),
		Description:         framework.StringOr(a.Description, ""),
		Enabled:             framework.BoolOr(a.Enabled, true),
		Action:              framework.StringOr(a.Action, "accept"),
		LogTraffic:          framework.BoolOr(a.LogTraffic, false),
		Position:            types.StringNull(),
		PositionReference:   types.StringNull(),
		SourceZones:         shared.FlattenZones(ctx, a.SourceZones, diags),
		DestinationZones:    shared.FlattenZones(ctx, a.DestinationZones, diags),
		SourceNetworks:      shared.FlattenNetworks(ctx, a.SourceNetworks, diags),
		DestinationNetworks: shared.FlattenNetworks(ctx, a.DestinationNetworks, diags),
		Schedule:            framework.RefName(a.Schedule),
	}
	m.Services, m.ServiceGroups = shared.FlattenServices(ctx, a.ServicesOrGroups, diags)
	if prior != nil {
		// Positions are write-only: keep what was configured.
		m.Position, m.PositionReference = prior.Position, prior.PositionReference
	}

	if u := a.UserAuthentication; u != nil && u.UsersOrGroups != nil {
		m.UserAuthentication = &userAuthModel{
			Users:                  framework.RefSet(ctx, u.UsersOrGroups.Items.Users, diags),
			UserGroups:             framework.RefSet(ctx, u.UsersOrGroups.Items.UserGroups, diags),
			ExcludeFromAccounting:  framework.BoolOr(u.ExcludeUsersFromAccounting, false),
			WebAuthForUnknownUsers: framework.BoolOr(u.WebAuthenticationForUnknownUsers, false),
		}
	}
	if e := a.Exclusions; e != nil {
		x := &exclusionsModel{
			SourceZones:         framework.RefSet(ctx, e.SourceZones.Zones, diags),
			DestinationZones:    framework.RefSet(ctx, e.DestinationZones.Zones, diags),
			SourceNetworks:      shared.FlattenNetworkList(ctx, e.SourceNetworks, diags),
			DestinationNetworks: shared.FlattenNetworkList(ctx, e.DestinationNetworks, diags),
			Services:            framework.RefSet(ctx, e.ServicesOrGroups.Services, diags),
			ServiceGroups:       framework.RefSet(ctx, e.ServicesOrGroups.ServiceGroups, diags),
		}
		if !x.SourceZones.IsNull() || !x.DestinationZones.IsNull() || x.SourceNetworks != nil ||
			x.DestinationNetworks != nil || !x.Services.IsNull() || !x.ServiceGroups.IsNull() {
			m.Exclusions = x
		}
	}
	// Optional blocks are only tracked when configured (or when importing),
	// so firewall-side defaults never appear as drift.
	if s := a.SecurityFeatures; s != nil && framework.Managed(prior, func(p *ruleModel) bool { return p.SecurityFeatures != nil }) {
		m.SecurityFeatures = &securityModel{
			WebPolicy:                 framework.RefName(s.WebPolicy),
			ApplicationPolicy:         framework.RefName(s.ApplicationPolicy),
			IPSPolicy:                 framework.RefName(s.IPSPolicy),
			ScanHTTPAndDecryptedHTTPS: framework.BoolOr(s.ScanHTTPAndDecryptedHTTPS, false),
			ZeroDayProtection:         framework.BoolOr(s.ZeroDayProtection, false),
			ScanFTP:                   framework.BoolOr(s.ScanFTP, false),
			WebProxy:                  framework.BoolOr(s.WebProxy, false),
			DecryptHTTPSWebProxyMode:  framework.BoolOr(s.DecryptHTTPSWebProxyMode, false),
			BlockQUICProtocol:         framework.BoolOr(s.BlockQUICProtocol, false),
			WebCategoryBasedQoSPolicy: framework.BoolOr(s.WebCategoryBasedQoSPolicy, false),
			ApplicationBasedQoSPolicy: framework.BoolOr(s.ApplicationBasedQoSPolicy, false),
			ScanWithNDRThreatIntel:    framework.BoolOr(s.ScanWithNDRActiveThreatIntelligence, false),
		}
	}
	if e := a.EmailScanning; e != nil && framework.Managed(prior, func(p *ruleModel) bool { return p.EmailScanning != nil }) {
		m.EmailScanning = &emailScanningModel{
			SMTP: framework.BoolOr(e.SMTP, false), SMTPS: framework.BoolOr(e.SMTPS, false),
			IMAP: framework.BoolOr(e.IMAP, false), IMAPS: framework.BoolOr(e.IMAPS, false),
			POP3: framework.BoolOr(e.POP3, false), POP3S: framework.BoolOr(e.POP3S, false),
		}
	}
	if q := a.QoS; q != nil && framework.Managed(prior, func(p *ruleModel) bool { return p.QoS != nil }) {
		m.QoS = &qosModel{TrafficShapingPolicy: framework.RefName(q.TrafficShapingPolicy), DSCPMarking: types.StringPointerValue(q.DSCPMarking)}
	}
	if h := a.Heartbeat; h != nil && framework.Managed(prior, func(p *ruleModel) bool { return p.Heartbeat != nil }) {
		src, dst := orEmpty(h.Source), orEmpty(h.Destination)
		m.Heartbeat = &heartbeatModel{
			SourceMinimumLevel:               framework.StringOr(src.MinimumLevel, "noRestriction"),
			BlockSourceWithoutHeartbeat:      framework.BoolOr(src.BlockClientsWithNoHeartbeat, false),
			DestinationMinimumLevel:          framework.StringOr(dst.MinimumLevel, "noRestriction"),
			BlockDestinationWithoutHeartbeat: framework.BoolOr(dst.BlockClientsWithNoHeartbeat, false),
		}
	}
	return m
}

func orEmpty(s *heartbeatSide) *heartbeatSide {
	if s == nil {
		return &heartbeatSide{}
	}
	return s
}
