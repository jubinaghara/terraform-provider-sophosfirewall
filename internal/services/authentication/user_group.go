// Package authentication implements users and groups of the firewall.
package authentication

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfos"
)

type userGroupModel struct {
	ID                        types.String `tfsdk:"id"`
	Name                      types.String `tfsdk:"name"`
	Description               types.String `tfsdk:"description"`
	SurfingQuotaPolicy        types.String `tfsdk:"surfing_quota_policy"`
	AccessTimePolicy          types.String `tfsdk:"access_time_policy"`
	NetworkTrafficQuotaPolicy types.String `tfsdk:"network_traffic_quota_policy"`
	TrafficShapingPolicy      types.String `tfsdk:"traffic_shaping_policy"`
	MACBinding                types.Bool   `tfsdk:"mac_binding"`
	QuarantineDigest          types.Bool   `tfsdk:"quarantine_digest"`
	SSLVPNPolicy              types.String `tfsdk:"ssl_vpn_policy"`
	ClientlessPolicy          types.String `tfsdk:"clientless_policy"`
	L2TP                      types.Bool   `tfsdk:"l2tp"`
	PPTP                      types.Bool   `tfsdk:"pptp"`
	IPsecRemoteAccess         types.Bool   `tfsdk:"ipsec_remote_access"`
}

type userGroup struct {
	ID               string        `json:"id,omitempty"`
	Name             string        `json:"name"`
	Description      *string       `json:"description,omitempty"`
	Policies         groupPolicies `json:"policies"`
	VPNAccess        vpnAccess     `json:"vpnAccess"`
	QuarantineDigest *bool         `json:"emailQuarantineDigest,omitempty"`
}

type groupPolicies struct {
	SurfingQuota        *sfos.NameRef `json:"surfingQuotaPolicy,omitempty"`
	AccessTime          *sfos.NameRef `json:"accessTimePolicy,omitempty"`
	NetworkTrafficQuota *sfos.NameRef `json:"networkTrafficQuotaPolicy,omitempty"`
	TrafficShaping      *sfos.NameRef `json:"trafficShapingPolicy,omitempty"`
	MACBinding          *bool         `json:"macBinding,omitempty"`
}

type vpnAccess struct {
	SSLVPN     *sfos.NameRef `json:"sslVpnRemoteAccessPolicy,omitempty"`
	Clientless *sfos.NameRef `json:"sslVpnClientlessPolicy,omitempty"`
	L2TP       *bool         `json:"l2tp,omitempty"`
	PPTP       *bool         `json:"pptp,omitempty"`
	IPsec      *bool         `json:"ipsecVpnRemoteAccess,omitempty"`
}

// UserGroup manages /authentication/user-groups.
var UserGroup = &framework.Resource[userGroupModel, userGroup]{
	Name:       "user_group",
	Title:      "user group",
	Path:       "/authentication/user-groups",
	Schema:     userGroupSchema(),
	CreateOnly: []string{"name"},
	Expand:     expandUserGroup,
	Flatten:    flattenUserGroup,
}

func userGroupSchema() schema.Schema {
	ref := func(desc string, required bool) schema.StringAttribute {
		return schema.StringAttribute{
			Required:            required,
			Optional:            !required,
			MarkdownDescription: desc,
			Validators:          []validator.String{stringvalidator.LengthBetween(1, 60), framework.ObjectName()},
		}
	}
	return schema.Schema{
		MarkdownDescription: "Manages a user group (*Configure > Authentication > Groups*). Built-in groups such as " +
			"`Open Group` or `Guest Group` can be read with the `sophosfirewall_user_group` data source.\n\n" +
			"Sign-in IP address restrictions are not managed: the SFOS v23 REST API ignores them.",
		Attributes: map[string]schema.Attribute{
			"id":                           framework.IDAttribute(),
			"name":                         framework.NameAttribute("user group", 256, true),
			"description":                  framework.DescriptionAttribute(1024),
			"surfing_quota_policy":         ref("Name of the surfing quota policy, e.g. `Unlimited Internet Access`.", true),
			"access_time_policy":           ref("Name of the access time policy, e.g. `Allowed all the time`.", true),
			"network_traffic_quota_policy": ref("Name of the network traffic quota policy.", false),
			"traffic_shaping_policy":       ref("Name of the traffic shaping policy.", false),
			"mac_binding":                  framework.BoolDefault("Bind members to the MAC address they first sign in from.", false),
			"quarantine_digest":            framework.BoolDefault("Send members the email quarantine digest.", false),
			"ssl_vpn_policy":               ref("Name of the SSL VPN remote access policy.", false),
			"clientless_policy":            ref("Name of the SSL VPN clientless access policy.", false),
			"l2tp":                         framework.BoolDefault("Allow L2TP remote access.", false),
			"pptp":                         framework.BoolDefault("Allow PPTP remote access.", false),
			"ipsec_remote_access":          framework.BoolDefault("Allow IPsec remote access.", false),
		},
	}
}

func expandUserGroup(ctx context.Context, m *userGroupModel, diags *diag.Diagnostics) *userGroup {
	g := &userGroup{
		Name:        m.Name.ValueString(),
		Description: framework.StringPtr(m.Description),
		Policies: groupPolicies{
			SurfingQuota:        framework.Ref(m.SurfingQuotaPolicy),
			AccessTime:          framework.Ref(m.AccessTimePolicy),
			NetworkTrafficQuota: framework.Ref(m.NetworkTrafficQuotaPolicy),
			TrafficShaping:      framework.Ref(m.TrafficShapingPolicy),
			MACBinding:          framework.BoolPtr(m.MACBinding),
		},
		VPNAccess: vpnAccess{
			SSLVPN:     framework.Ref(m.SSLVPNPolicy),
			Clientless: framework.Ref(m.ClientlessPolicy),
			L2TP:       framework.BoolPtr(m.L2TP),
			PPTP:       framework.BoolPtr(m.PPTP),
			IPsec:      framework.BoolPtr(m.IPsecRemoteAccess),
		},
		QuarantineDigest: framework.BoolPtr(m.QuarantineDigest),
	}
	return g
}

func flattenUserGroup(ctx context.Context, a *userGroup, prior *userGroupModel, diags *diag.Diagnostics) *userGroupModel {
	p, v := a.Policies, a.VPNAccess
	m := &userGroupModel{
		ID:                        types.StringValue(a.ID),
		Name:                      types.StringValue(a.Name),
		Description:               framework.StringOr(a.Description, ""),
		SurfingQuotaPolicy:        framework.RefName(p.SurfingQuota),
		AccessTimePolicy:          framework.RefName(p.AccessTime),
		NetworkTrafficQuotaPolicy: framework.RefName(p.NetworkTrafficQuota),
		TrafficShapingPolicy:      framework.RefName(p.TrafficShaping),
		MACBinding:                framework.BoolOr(p.MACBinding, false),
		QuarantineDigest:          framework.BoolOr(a.QuarantineDigest, false),
		SSLVPNPolicy:              framework.RefName(v.SSLVPN),
		ClientlessPolicy:          framework.RefName(v.Clientless),
		L2TP:                      framework.BoolOr(v.L2TP, false),
		PPTP:                      framework.BoolOr(v.PPTP, false),
		IPsecRemoteAccess:         framework.BoolOr(v.IPsec, false),
	}

	// Optional policies the firewall may assign by itself stay null unless
	// the user manages them, so that they do not show up as drift.
	if prior != nil {
		for _, f := range []struct {
			prior types.String
			value *types.String
		}{
			{prior.NetworkTrafficQuotaPolicy, &m.NetworkTrafficQuotaPolicy},
			{prior.TrafficShapingPolicy, &m.TrafficShapingPolicy},
			{prior.SSLVPNPolicy, &m.SSLVPNPolicy},
			{prior.ClientlessPolicy, &m.ClientlessPolicy},
		} {
			if f.prior.IsNull() {
				*f.value = types.StringNull()
			}
		}
	}
	return m
}
