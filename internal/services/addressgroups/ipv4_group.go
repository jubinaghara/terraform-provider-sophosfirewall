package addressgroups

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfos"
)

// hostGroupModel is the Terraform model shared by the IPv4, IPv6 and FQDN
// host groups: they only differ in the JSON key holding their members.
type hostGroupModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Addresses   types.Set    `tfsdk:"addresses"`
}

// hostGroupSchema builds the schema of a host group whose members are
// address objects of the given kind (e.g. "IPv4").
func hostGroupSchema(title, gui, member, memberResource string) schema.Schema {
	return schema.Schema{
		MarkdownDescription: "Manages an " + title + " (*Objects > Hosts and services > " + gui + "*). " +
			"Groups can be referenced from firewall and NAT rules wherever a single host can.",
		Attributes: map[string]schema.Attribute{
			"id":          framework.IDAttribute(),
			"name":        framework.NameAttribute(title, 60, false),
			"description": framework.DescriptionAttribute(255),
			"addresses": framework.NameSetAttribute("Names of the " + member + " objects (`" + memberResource +
				"`) in the group. Membership is unordered. Omit it for an empty group."),
		},
	}
}

type ipv4Group struct {
	ID          string         `json:"id,omitempty"`
	Name        string         `json:"name"`
	Description *string        `json:"description,omitempty"`
	Addresses   []sfos.NameRef `json:"ipv4Addresses"`
}

// IPv4Group manages /network/address-groups/ipv4 (IP host groups).
var IPv4Group = &framework.Resource[hostGroupModel, ipv4Group]{
	Name:   "ipv4_group",
	Title:  "IPv4 address group",
	Path:   "/network/address-groups/ipv4",
	Schema: hostGroupSchema("IPv4 address group", "IP host group", "IPv4 address", "sophosfirewall_ipv4_address"),
	Expand: func(ctx context.Context, m *hostGroupModel, diags *diag.Diagnostics) *ipv4Group {
		return &ipv4Group{
			Name:        m.Name.ValueString(),
			Description: framework.StringPtr(m.Description),
			Addresses:   framework.Refs(ctx, m.Addresses, diags),
		}
	},
	Flatten: func(ctx context.Context, a *ipv4Group, _ *hostGroupModel, diags *diag.Diagnostics) *hostGroupModel {
		return &hostGroupModel{
			ID:          types.StringValue(a.ID),
			Name:        types.StringValue(a.Name),
			Description: framework.StringOr(a.Description, ""),
			Addresses:   framework.RefSet(ctx, a.Addresses, diags),
		}
	},
}
