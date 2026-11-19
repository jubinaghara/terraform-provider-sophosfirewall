// Package provider wires the SFOS client and all object types into a
// Terraform provider.
package provider

import (
	"context"
	"os"
	"strconv"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfos"
)

// Environment variables used when the corresponding argument is not set.
const (
	EnvEndpoint = "SFOS_ENDPOINT"
	EnvAPIKey   = "SFOS_API_KEY"
	EnvInsecure = "SFOS_INSECURE"
)

var _ provider.Provider = (*sfosProvider)(nil)

type sfosProvider struct {
	version string
}

type providerModel struct {
	Endpoint       types.String `tfsdk:"endpoint"`
	APIKey         types.String `tfsdk:"api_key"`
	Insecure       types.Bool   `tfsdk:"insecure"`
	RequestTimeout types.Int64  `tfsdk:"request_timeout"`
	MaxRetries     types.Int64  `tfsdk:"max_retries"`
}

// New returns a provider factory for the given release version.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &sfosProvider{version: version} }
}

func (p *sfosProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "sophosfirewall"
	resp.Version = p.version
}

func (p *sfosProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The **Sophos Firewall** provider manages Sophos Firewall (SFOS) configuration through the " +
			"Firewall Configuration REST API (`/api/firewall-config/v1`).\n\n" +
			"**Requires SFOS v23.0 or later.** Create an API key under " +
			"*Administration > API access* in the web admin console.\n\n" +
			"Provider versions `23.x` and later are a rewrite for the REST API and are not compatible with " +
			"configurations written for `1.x`, which used the legacy XML API with a username and password. " +
			"Pin `version = \"~> 1.0\"` to stay on the old provider.\n\n" +
			"> **Note:** This is not an official Sophos Firewall (SFOS) provider. It is developed independently " +
			"and has been tested in a limited capacity. Try changes on a non-production firewall first.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Address of the firewall, e.g. `https://172.16.16.16:4444` or `172.16.16.16:4444`. " +
					"The API base path is appended automatically. Can also be set with `" + EnvEndpoint + "`.",
			},
			"api_key": schema.StringAttribute{
				Optional:            true,
				Sensitive:           true,
				MarkdownDescription: "API key sent as a bearer token. Can also be set with `" + EnvAPIKey + "`.",
			},
			"insecure": schema.BoolAttribute{
				Optional: true,
				MarkdownDescription: "Skip TLS certificate verification, e.g. for the factory self-signed certificate. " +
					"Can also be set with `" + EnvInsecure + "`. Defaults to `false`.",
			},
			"request_timeout": schema.Int64Attribute{
				Optional:            true,
				MarkdownDescription: "Timeout of a single API request in seconds. Defaults to `60`.",
				Validators:          []validator.Int64{int64validator.AtLeast(1)},
			},
			"max_retries": schema.Int64Attribute{
				Optional:            true,
				MarkdownDescription: "Retries for throttled (429) or temporarily unavailable (502-504) responses. Defaults to `3`.",
				Validators:          []validator.Int64{int64validator.AtLeast(0)},
			},
		},
	}
}

func (p *sfosProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	for name, v := range map[string]interface{ IsUnknown() bool }{
		"endpoint": cfg.Endpoint, "api_key": cfg.APIKey, "insecure": cfg.Insecure,
	} {
		if v.IsUnknown() {
			resp.Diagnostics.AddAttributeError(path.Root(name), "Unknown provider configuration",
				"The provider cannot be configured with a value that is only known after apply.")
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}

	endpoint := stringOrEnv(cfg.Endpoint, EnvEndpoint)
	apiKey := stringOrEnv(cfg.APIKey, EnvAPIKey)
	insecure := cfg.Insecure.ValueBool()
	if cfg.Insecure.IsNull() {
		insecure, _ = strconv.ParseBool(os.Getenv(EnvInsecure))
	}
	if endpoint == "" {
		resp.Diagnostics.AddAttributeError(path.Root("endpoint"), "Missing endpoint",
			"Set the endpoint argument or the "+EnvEndpoint+" environment variable.")
	}
	if apiKey == "" {
		resp.Diagnostics.AddAttributeError(path.Root("api_key"), "Missing API key",
			"Set the api_key argument or the "+EnvAPIKey+" environment variable.")
	}
	if resp.Diagnostics.HasError() {
		return
	}

	timeout, retries := int64(60), int64(3)
	if !cfg.RequestTimeout.IsNull() {
		timeout = cfg.RequestTimeout.ValueInt64()
	}
	if !cfg.MaxRetries.IsNull() {
		retries = cfg.MaxRetries.ValueInt64()
	}

	client, err := sfos.NewClient(sfos.Config{
		Endpoint:   endpoint,
		APIKey:     apiKey,
		Insecure:   insecure,
		Timeout:    time.Duration(timeout) * time.Second,
		MaxRetries: int(retries),
		UserAgent:  "terraform-provider-sophosfirewall/" + p.version,
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to configure the SFOS client", err.Error())
		return
	}
	resp.ResourceData = client
	resp.DataSourceData = client
}

func (p *sfosProvider) Resources(context.Context) []func() resource.Resource {
	var out []func() resource.Resource
	for _, r := range registry {
		out = append(out, r.NewResource)
	}
	return out
}

func (p *sfosProvider) DataSources(context.Context) []func() datasource.DataSource {
	var out []func() datasource.DataSource
	for _, r := range registry {
		if r.NewDataSource() != nil {
			out = append(out, r.NewDataSource)
		}
	}
	return out
}

func stringOrEnv(v types.String, env string) string {
	if !v.IsNull() {
		return v.ValueString()
	}
	return os.Getenv(env)
}
