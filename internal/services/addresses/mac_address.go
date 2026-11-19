package addresses

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
)

type macAddressModel struct {
	ID           types.String `tfsdk:"id"`
	Name         types.String `tfsdk:"name"`
	Description  types.String `tfsdk:"description"`
	MACAddress   types.String `tfsdk:"mac_address"`
	MACAddresses types.Set    `tfsdk:"mac_addresses"`
}

type macAddress struct {
	ID           string   `json:"id,omitempty"`
	Name         string   `json:"name"`
	Description  *string  `json:"description,omitempty"`
	Type         string   `json:"type,omitempty"`
	MACAddress   string   `json:"macAddress,omitempty"`
	MACAddresses []string `json:"macAddresses,omitempty"`
}

// MACAddress manages /network/addresses/mac.
var MACAddress = &framework.Resource[macAddressModel, macAddress]{
	Name:  "mac_address",
	Title: "MAC address object",
	Path:  "/network/addresses/mac",
	Schema: schema.Schema{
		MarkdownDescription: "Manages a MAC address object (*Objects > Hosts and services > MAC host*). " +
			"Set exactly one of `mac_address` or `mac_addresses`; switching between them recreates the object.",
		Attributes: map[string]schema.Attribute{
			"id":          framework.IDAttribute(),
			"name":        framework.NameAttribute("MAC address object", 60, false),
			"description": framework.DescriptionAttribute(255),
			"mac_address": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "A single MAC address, e.g. `00:1a:2b:3c:4d:5e`.",
				Validators: []validator.String{
					framework.MACAddress(),
					stringvalidator.ExactlyOneOf(path.MatchRoot("mac_addresses")),
				},
				PlanModifiers: []planmodifier.String{framework.ReplaceOnPresenceChange()},
			},
			"mac_addresses": schema.SetAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "A list of MAC addresses (up to 1000).",
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, 1000),
					setvalidator.ValueStringsAre(framework.MACAddress()),
				},
				PlanModifiers: []planmodifier.Set{framework.ReplaceSetOnPresenceChange()},
			},
		},
	},
	Expand: func(ctx context.Context, m *macAddressModel, diags *diag.Diagnostics) *macAddress {
		return &macAddress{
			Name:         m.Name.ValueString(),
			Description:  framework.StringPtr(m.Description),
			MACAddress:   m.MACAddress.ValueString(),
			MACAddresses: framework.Strings(ctx, m.MACAddresses, diags),
		}
	},
	Flatten: func(ctx context.Context, a *macAddress, prior *macAddressModel, diags *diag.Diagnostics) *macAddressModel {
		m := &macAddressModel{
			ID:           types.StringValue(a.ID),
			Name:         types.StringValue(a.Name),
			Description:  framework.StringOr(a.Description, ""),
			MACAddress:   framework.NonEmpty(a.MACAddress),
			MACAddresses: framework.StringSet(ctx, a.MACAddresses, diags),
		}
		// The firewall may change the letter case; keep the configured spelling.
		if prior != nil {
			if strings.EqualFold(prior.MACAddress.ValueString(), a.MACAddress) {
				m.MACAddress = prior.MACAddress
			}
			if sameFold(framework.Strings(ctx, prior.MACAddresses, diags), a.MACAddresses) {
				m.MACAddresses = prior.MACAddresses
			}
		}
		return m
	},
}

func sameFold(a, b []string) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, s := range a {
		seen[strings.ToLower(s)]++
	}
	for _, s := range b {
		k := strings.ToLower(s)
		if seen[k] == 0 {
			return false
		}
		seen[k]--
	}
	return true
}
