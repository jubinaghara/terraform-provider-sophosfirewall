// provider.go
package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces
var _ provider.Provider = &SophosProvider{}

// SophosProvider is the provider implementation
type SophosProvider struct{}

// SophosProviderModel describes the provider data model
type SophosProviderModel struct {
	Endpoint types.String `tfsdk:"endpoint"`
	Username types.String `tfsdk:"username"`
	Password types.String `tfsdk:"password"`
	Insecure types.Bool   `tfsdk:"insecure"`
}

func New() provider.Provider {
	return &SophosProvider{}
}

// Metadata returns the provider type name
func (p *SophosProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "sophosfirewall"
}

// Schema defines the provider-level schema for configuration data
func (p *SophosProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Interact with Sophos Firewall XML API",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				Description: "The endpoint URL of the Sophos Firewall API",
				Required:    true,
			},
			"username": schema.StringAttribute{
				Description: "Username for API authentication",
				Required:    true,
			},
			"password": schema.StringAttribute{
				Description: "Password for API authentication",
				Required:    true,
				Sensitive:   true,
			},
			"insecure": schema.BoolAttribute{
				Description: "Skip TLS certificate verification",
				Optional:    true,
			},
		},
	}
}

// Configure prepares a Sophos API client for data sources and resources
func (p *SophosProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config SophosProviderModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	insecure := false
	if !config.Insecure.IsNull() {
		insecure = config.Insecure.ValueBool()
	}

	// Create a Sophos client using the configuration
	client := NewSophosClient(
		config.Endpoint.ValueString(),
		config.Username.ValueString(),
		config.Password.ValueString(),
		insecure,
	)

	resp.ResourceData = client
	resp.DataSourceData = client
}

// Resources defines the resources implemented in the provider
func (p *SophosProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewIPHostResource,
		NewFirewallRuleResource,
		NewMACHostResource,
	}
}

// DataSources defines the data sources implemented in the provider
func (p *SophosProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewIPHostDataSource,
	}
}

