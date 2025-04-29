// data_source_machost.go

package provider

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces
var _ datasource.DataSource = &macHostDataSource{}

// macHostDataSource is the data source implementation
type macHostDataSource struct {
	client *SophosClient
}

// NewMACHostDataSource creates a new data source
func NewMACHostDataSource() datasource.DataSource {
	return &macHostDataSource{}
}

// Metadata returns the data source type name
func (d *macHostDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_machost"
}

// Schema defines the schema for the data source
func (d *macHostDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Fetches a Sophos Firewall MAC Host object",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description: "Name of the MAC Host",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "Description of the MAC Host",
				Optional:    true,
				Computed:    true,
			},
			"type": schema.StringAttribute{
				Description: "MAC Host Type (MACAddress, MACLIST)",
				Computed:    true,
			},
			"mac_address": schema.StringAttribute{
				Description: "MAC Address for Single MAC",
				Computed:    true,
			},
			"list_of_mac_addresses": schema.ListAttribute{
				Description: "List of MAC addresses for MACList type",
				Computed:    true,
				ElementType: types.StringType,
			},
		},
	}
}

// Configure adds the provider configured client to the data source
func (d *macHostDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

	d.client = client
}

// macHostDataSourceModel maps the data source schema data
type macHostDataSourceModel struct {
	Name               types.String `tfsdk:"name"`
	Description        types.String `tfsdk:"description"`
	Type               types.String `tfsdk:"type"`
	MACAddress         types.String `tfsdk:"mac_address"`
	ListOfMACAddresses types.List   `tfsdk:"list_of_mac_addresses"`
}

// Read refreshes the Terraform state with the latest data
func (d *macHostDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config macHostDataSourceModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the MAC Host from the API
	macHost, err := d.client.ReadMACHost(config.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading MAC Host", err.Error())
		return
	}

	log.Printf("[DEBUG] Read function - Retrieved MAC Host: %+v", macHost) // Log the retrieved object


	if macHost == nil {
		resp.Diagnostics.AddError(
			"MAC Host not found",
			fmt.Sprintf("MAC Host with name %s not found", config.Name.ValueString()),
		)
		return
	}

	// Map the data from the API model to the data source model
	config.Type = types.StringValue(macHost.Type)
	if macHost.Description != "" {
		config.Description = types.StringValue(macHost.Description)
	} else {
		config.Description = types.StringNull()
	}

	// Handle MACAddress type
	if macHost.Type == "MACAddress" {
		config.MACAddress = types.StringValue(macHost.MACAddress)
		config.ListOfMACAddresses = types.ListNull(types.StringType) // Ensure the list is null
	} else if macHost.Type == "MACLIST" {
		config.MACAddress = types.StringNull() // Ensure the single address is null
		if macHost.ListOfMACAddresses != nil {
			elements := make([]types.String, 0, len(macHost.ListOfMACAddresses))
			for _, mac := range macHost.ListOfMACAddresses {
				elements = append(elements, types.StringValue(mac))
			}
			listVal, diags := types.ListValueFrom(ctx, types.StringType, elements)
			resp.Diagnostics.Append(diags...)
			if !resp.Diagnostics.HasError() {
				config.ListOfMACAddresses = listVal
			}
		} else {
			config.ListOfMACAddresses = types.ListNull(types.StringType)
		}
	} else {
		// Handle unknown type (shouldn't happen ideally, but for robustness)
		config.MACAddress = types.StringNull()
		config.ListOfMACAddresses = types.ListNull(types.StringType)
	}

	// Set the state
	diags = resp.State.Set(ctx, &config)
	resp.Diagnostics.Append(diags...)
}