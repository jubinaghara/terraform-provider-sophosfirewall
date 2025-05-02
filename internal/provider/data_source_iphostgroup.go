//iphost_data

package provider

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/iphostgroup"
)

// Ensure the implementation satisfies the expected interfaces
var _ datasource.DataSource = &ipHostGroupDataSource{}

// ipHostGroupDataSource is the data source implementation
type ipHostGroupDataSource struct {
	client *iphostgroup.Client
}

// NewipHostGroupDataSource creates a new data source
func NewipHostGroupDataSource() datasource.DataSource {
	return &ipHostGroupDataSource{}
}

// Metadata returns the data source type name
func (d *ipHostGroupDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_iphostgroup"
}

// Schema defines the schema for the data source
func (d *ipHostGroupDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Fetches a Sophos Firewall IP Host Group object",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description: "Name of the IP Host",
				Required:    true,
			},
			"ip_family": schema.StringAttribute{
				Description: "IP Family (IPv4 or IPv6)",
				Computed:    true,
			},
			"description": schema.StringAttribute{
				Description: "Description of Host Group",
				Optional:    true,
				Computed:    true,
			},
			"host_list": schema.ListAttribute{
				Description: "List of host groups this IP Host belongs to",
				Computed:    true,
				ElementType: types.StringType,
			},
		},
	}
}

// Configure adds the provider configured client to the data source
func (d *ipHostGroupDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*SophosClient)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *SophosClient, got: %T", req.ProviderData),
		)
		return
	}

	d.client = iphostgroup.NewClient(client.BaseClient)
}

// Fixed Resource Read Function
func (d *ipHostGroupDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config ipHostGroupResourceModel
	
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the IP Host from the API
	ipHostGroup, err := d.client.ReadIPHostGroup(config.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading IP Host Group", err.Error())
		return
	}

	log.Printf("[DEBUG] Data Source Read function - Retrieved IP Host Group: %+v", ipHostGroup) // Log the retrieved object

	if ipHostGroup == nil {
		resp.Diagnostics.AddError(
			"IP Host Group not found",
			fmt.Sprintf("IP Host Group with name %s not found", config.Name.ValueString()),
		)
		return
	}

	// Always set these fields
	config.Name = types.StringValue(ipHostGroup.Name)
	config.IPFamily = types.StringValue(ipHostGroup.IPFamily)
	config.Description = types.StringValue(ipHostGroup.Description)

	// Map host groups consistently
	if ipHostGroup.HostList != nil && len(ipHostGroup.HostList.Hosts) > 0 {
		hosts := make([]types.String, 0, len(ipHostGroup.HostList.Hosts))
		for _, hg := range ipHostGroup.HostList.Hosts {
			hosts = append(hosts, types.StringValue(hg))
		}
		config.Hosts = hosts
	} else {
		// Always initialize to empty slice
		config.Hosts = []types.String{}
	}

	// Set the state
	diags = resp.State.Set(ctx, &config)
	resp.Diagnostics.Append(diags...)
}