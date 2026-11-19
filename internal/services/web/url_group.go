// Package web implements web protection objects.
package web

import (
	"context"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
)

// MaxURLs is the largest number of entries the API accepts in one URL group.
const MaxURLs = 10000

// urlRe is the API's pattern for URL group entries: a domain or host name
// without scheme, path, port or wildcard.
var urlRe = regexp.MustCompile(`^\w([.]?\w|-)*$`)

type urlGroupModel struct {
	ID          types.String        `tfsdk:"id"`
	Name        types.String        `tfsdk:"name"`
	Description types.String        `tfsdk:"description"`
	URLs        largeStringSetValue `tfsdk:"urls"`
}

type urlGroup struct {
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name"`
	Description *string  `json:"description,omitempty"`
	URLs        []string `json:"urls"`
}

// URLGroup manages /web/url-groups.
var URLGroup = &framework.Resource[urlGroupModel, urlGroup]{
	Name:  "url_group",
	Title: "URL group",
	Path:  "/web/url-groups",
	Schema: schema.Schema{
		MarkdownDescription: "Manages a web filter URL group (*Protect > Web > URL groups*), a list of domains " +
			"that web policies and exceptions can allow or block as a whole. An entry matches the domain and " +
			"all of its subdomains.",
		Attributes: map[string]schema.Attribute{
			"id":          framework.IDAttribute(),
			"name":        framework.NameAttribute("URL group", 50, true),
			"description": framework.DescriptionAttribute(255),
			"urls": schema.SetAttribute{
				Optional: true,
				// ElementType is kept for the derived data source, which does not copy CustomType.
				ElementType: types.StringType,
				CustomType:  largeStringSet,
				MarkdownDescription: "Domains or host names in the group, e.g. `example.com` (at most 10,000). " +
					"Schemes, paths, ports and wildcards are not allowed. Omit to create an empty group.",
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, MaxURLs),
					setvalidator.ValueStringsAre(
						stringvalidator.LengthBetween(1, 250),
						stringvalidator.RegexMatches(urlRe, "must be a domain or host name such as example.com, without scheme, path, port or wildcard"),
					),
				},
			},
		},
	},
	// Renaming is not supported by PATCH.
	CreateOnly: []string{"name"},
	Expand: func(ctx context.Context, m *urlGroupModel, diags *diag.Diagnostics) *urlGroup {
		urls := framework.Strings(ctx, m.URLs.SetValue, diags)
		if urls == nil {
			// Always send the list so that removing every entry sends [] (not null).
			urls = []string{}
		}
		return &urlGroup{
			Name:        m.Name.ValueString(),
			Description: framework.StringPtr(m.Description),
			URLs:        urls,
		}
	},
	Flatten: func(ctx context.Context, a *urlGroup, _ *urlGroupModel, diags *diag.Diagnostics) *urlGroupModel {
		return &urlGroupModel{
			ID:          types.StringValue(a.ID),
			Name:        types.StringValue(a.Name),
			Description: framework.StringOr(a.Description, ""),
			URLs:        newLargeStringSet(ctx, a.URLs, diags),
		}
	},
}
