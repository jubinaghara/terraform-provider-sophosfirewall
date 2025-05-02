//iphost_data

package provider

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/iphost"
)

// Ensure the implementation satisfies the expected interfaces
var _ datasource.DataSource = &ipHostDataSource{}

// ipHostDataSource is the data source implementation
type ipHostDataSource struct {
	client *iphost.Client
}

// NewIPHostDataSource creates a new data source
func NewIPHostDataSource() datasource.DataSource {
	return &ipHostDataSource{}
}

// Metadata returns the data source type name
func (d *ipHostDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_iphost"
}

// Schema defines the schema for the data source
func (d *ipHostDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Fetches a Sophos Firewall IP Host object",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description: "Name of the IP Host",
				Required:    true,
			},
			"ip_family": schema.StringAttribute{
				Description: "IP Family (IPv4 or IPv6)",
				Computed:    true,
			},
			"host_type": schema.StringAttribute{
				Description: "Host Type (IP, Network, IPRange, IPList)",
				Computed:    true,
			},
			"ip_address": schema.StringAttribute{
				Description: "IP Address for IP or Network types",
				Computed:    true,
			},
			"subnet": schema.StringAttribute{
				Description: "Subnet mask for Network type",
				Computed:    true,
			},
			"start_ip_address": schema.StringAttribute{
				Description: "Start IP Address for IPRange type",
				Computed:    true,
			},
			"end_ip_address": schema.StringAttribute{
				Description: "End IP Address for IPRange type",
				Computed:    true,
			},
			"list_of_ip_addresses": schema.StringAttribute{
				Description: "Comma-separated list of IP addresses for IPList type",
				Computed:    true,
			},
			"host_groups": schema.ListAttribute{
				Description: "List of host groups this IP Host belongs to",
				Computed:    true,
				ElementType: types.StringType,
			},
		},
	}
}

// Configure adds the provider configured client to the data source
func (d *ipHostDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

	d.client = iphost.NewClient(client.BaseClient)
}

// Fixed Resource Read Function
func (d *ipHostDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config ipHostResourceModel
	
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the IP Host from the API
	ipHost, err := d.client.ReadIPHost(config.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading IP Host", err.Error())
		return
	}

	log.Printf("[DEBUG] Data Source Read function - Retrieved IP Host: %+v", ipHost) // Log the retrieved object

	if ipHost == nil {
		resp.Diagnostics.AddError(
			"IP Host not found",
			fmt.Sprintf("IP Host with name %s not found", config.Name.ValueString()),
		)
		return
	}

	// Always set these fields
	config.Name = types.StringValue(ipHost.Name)
	config.IPFamily = types.StringValue(ipHost.IPFamily)
	config.HostType = types.StringValue(ipHost.HostType)
	
	// Handle field values based on the HostType to avoid drift
	switch ipHost.HostType {
	case "IP":
		config.IPAddress = types.StringValue(ipHost.IPAddress)
		config.Subnet = types.StringNull()
		config.StartIPAddress = types.StringNull()
		config.EndIPAddress = types.StringNull()
		config.ListOfIPAddresses = types.StringNull()
	case "Network":
		config.IPAddress = types.StringValue(ipHost.IPAddress)
		config.Subnet = types.StringValue(ipHost.Subnet)
		config.StartIPAddress = types.StringNull()
		config.EndIPAddress = types.StringNull()
		config.ListOfIPAddresses = types.StringNull()
	case "IPRange":
		config.IPAddress = types.StringNull()
		config.Subnet = types.StringNull()
		config.StartIPAddress = types.StringValue(ipHost.StartIPAddress)
		config.EndIPAddress = types.StringValue(ipHost.EndIPAddress)
		config.ListOfIPAddresses = types.StringNull()
	case "IPList":
		config.IPAddress = types.StringNull()
		config.Subnet = types.StringNull()
		config.StartIPAddress = types.StringNull()
		config.EndIPAddress = types.StringNull()
		config.ListOfIPAddresses = types.StringValue(ipHost.ListOfIPAddresses)
	case "System Host":
		// For system hosts, set all type-specific fields to null
		config.IPAddress = types.StringNull()
		config.Subnet = types.StringNull()
		config.StartIPAddress = types.StringNull()
		config.EndIPAddress = types.StringNull()
		config.ListOfIPAddresses = types.StringNull()
	}

	// Map host groups consistently
	if ipHost.HostGroupList != nil && len(ipHost.HostGroupList.HostGroups) > 0 {
		hostGroups := make([]types.String, 0, len(ipHost.HostGroupList.HostGroups))
		for _, hg := range ipHost.HostGroupList.HostGroups {
			hostGroups = append(hostGroups, types.StringValue(hg))
		}
		config.HostGroups = hostGroups
	} else {
		// Always initialize to empty slice
		config.HostGroups = []types.String{}
	}

	// Set the state
	diags = resp.State.Set(ctx, &config)
	resp.Diagnostics.Append(diags...)
}