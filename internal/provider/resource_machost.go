// resource_machost.go

package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/machost"
)

// Ensure the implementation satisfies the expected interfaces
var _ resource.Resource = &macHostResource{}
var _ resource.ResourceWithImportState = &macHostResource{}

// macHostResource is the resource implementation
type macHostResource struct {
	client *machost.Client
}

// macHostResourceModel maps the resource schema data
type macHostResourceModel struct {
	Name               types.String `tfsdk:"name"`
	Description        types.String `tfsdk:"description"`
	Type               types.String `tfsdk:"type"`
	MACAddress         types.String `tfsdk:"mac_address"`
	ListOfMACAddresses types.String `tfsdk:"list_of_mac_addresses"`
}

// NewMACHostResource creates a new resource
func NewMACHostResource() resource.Resource {
	return &macHostResource{}
}

// Metadata returns the resource type name
func (r *macHostResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_machost"
}

// Schema defines the schema for the resource
func (r *macHostResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Sophos Firewall MAC Host object",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description: "Name of the MAC Host",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"description": schema.StringAttribute{
				Description: "Description of the MAC Host",
				Optional:    true,
			},
			"type": schema.StringAttribute{
				Description: "MAC Host Type (MACAddress, MACLIST)",
				Required:    true,
			},
			"mac_address": schema.StringAttribute{
				Description: "MAC Address for Single MAC",
				Optional:    true,
			},
			"list_of_mac_addresses": schema.StringAttribute{
				Description: "Comma-separated list of MAC addresses for MACList type",
				Optional:    true,
			},
		},
	}
}

// Configure adds the provider configured client to the resource
func (r *macHostResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*SophosClient)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *SophosClient, got: %T", req.ProviderData),
		)
		return
	}

	r.client = machost.NewClient(client.BaseClient)
}

// parseMACList parses a comma-separated string into a slice of MAC addresses
func parseMACList(macList string) []string {
	if macList == "" {
		return nil
	}
	
	// Split by comma and deduplicate MAC addresses
	parts := strings.Split(macList, ",")
	uniqueMACs := make(map[string]bool)
	var result []string
	
	for _, part := range parts {
		trim := strings.TrimSpace(part)
		if trim != "" && !uniqueMACs[trim] {
			uniqueMACs[trim] = true
			result = append(result, trim)
		}
	}
	
	return result
}

// Create creates a new MAC Host
func (r *macHostResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan macHostResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Parse MAC addresses from the comma-separated string and ensure uniqueness
	macAddresses := parseMACList(plan.ListOfMACAddresses.ValueString())

	// Map from the terraform model to the API model
	macHost := &machost.MACHost{
		Name:              plan.Name.ValueString(),
		Description:       plan.Description.ValueString(),
		Type:              plan.Type.ValueString(),
		TransactionID:     "", // Set empty
	}
	
	// Set proper field based on type
	if plan.Type.ValueString() == "MACAddress" {
		macHost.MACAddress = plan.MACAddress.ValueString()
		macHost.ListOfMACAddresses = nil
	} else { // MACList type
		macHost.MACAddress = ""
		macHost.ListOfMACAddresses = macAddresses
		macHost.Type = "MACLIST"
	}

	// Create the MAC Host
	err := r.client.CreateMACHost(macHost)
	if err != nil {
		resp.Diagnostics.AddError("Error creating MAC Host", err.Error())
		return
	}

	// Update the plan with any computed values
	// If it's a list type, ensure consistent representation of MAC addresses
	if plan.Type.ValueString() == "MACLIST" && len(macAddresses) > 0 {
		plan.ListOfMACAddresses = types.StringValue(strings.Join(macAddresses, ","))
		plan.MACAddress = types.StringNull()
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Read refreshes the Terraform state with the latest data
func (r *macHostResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state macHostResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the MAC Host from the API
	macHost, err := r.client.ReadMACHost(state.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading MAC Host", err.Error())
		return
	}

	if macHost == nil {
		// Resource no longer exists
		resp.State.RemoveResource(ctx)
		return
	}

	// Update state with values from API
	state.Name = types.StringValue(macHost.Name)
	
	if macHost.Description != "" {
		state.Description = types.StringValue(macHost.Description)
	} else {
		state.Description = types.StringNull()
	}
	
	state.Type = types.StringValue(macHost.Type)
	
	// Handle MAC address fields based on type (case-insensitive comparison)
	typeUpper:= strings.ToUpper(macHost.Type)
	
	// Set the exact type value from the API
	state.Type = types.StringValue(macHost.Type)
	
	if typeUpper == "MACADDRESS" {
		if macHost.MACAddress != "" {
			state.MACAddress = types.StringValue(macHost.MACAddress)
		} else {
			state.MACAddress = types.StringNull()
		}
		state.ListOfMACAddresses = types.StringNull()
	} else if typeUpper == "MACLIST" {
		state.MACAddress = types.StringNull()
		
		// Convert MAC addresses back to comma-separated string
		if macHost.ListOfMACAddresses != nil && len(macHost.ListOfMACAddresses) > 0 {
			// Only include unique MAC addresses
			uniqueMACs := make(map[string]bool)
			var uniqueList []string
			
			for _, mac := range macHost.ListOfMACAddresses {
				if !uniqueMACs[mac] {
					uniqueMACs[mac] = true
					uniqueList = append(uniqueList, mac)
				}
			}
			
			state.ListOfMACAddresses = types.StringValue(strings.Join(uniqueList, ","))
		} else {
			// Always set an empty string instead of null for MACLIST type to avoid unknown values
			state.ListOfMACAddresses = types.StringValue("")
		}
	}


	// Save the updated state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

// Update updates the resource and sets the updated Terraform state
func (r *macHostResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan macHostResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Parse MAC addresses from the comma-separated string and ensure uniqueness
	macAddresses := parseMACList(plan.ListOfMACAddresses.ValueString())

	// Map from the terraform model to the API model
	macHost := &machost.MACHost{
		Name:           plan.Name.ValueString(),
		Description:    plan.Description.ValueString(),
		Type:           plan.Type.ValueString(),
		TransactionID:  "", // Set empty
	}
	
	// Set proper field based on type (case-insensitive comparison)
	typeUpper:= strings.ToUpper(plan.Type.ValueString())

	if typeUpper == "MACADDRESS" {
		macHost.MACAddress = plan.MACAddress.ValueString()
		macHost.ListOfMACAddresses = nil
		macHost.Type = "MACAddress" // Ensure consistent type naming
		
		// Update the plan with standardized type and ensure ListOfMACAddresses is null
		plan.Type = types.StringValue("MACAddress")
		plan.ListOfMACAddresses = types.StringNull()
	} else if typeUpper == "MACLIST" {
		macHost.MACAddress = ""
		macHost.ListOfMACAddresses = macAddresses
		macHost.Type = "MACLIST" // Ensure consistent type naming
		
		// Update the plan with standardized type and ensure MACAddress is null
		plan.Type = types.StringValue("MACLIST")
		plan.MACAddress = types.StringNull()
		
		// Update the plan with deduplicated MAC addresses
		if len(macAddresses) > 0 {
			plan.ListOfMACAddresses = types.StringValue(strings.Join(macAddresses, ","))
		}
	}


	// Update the MAC Host
	err := r.client.UpdateMACHost(macHost)
	if err != nil {
		resp.Diagnostics.AddError("Error updating MAC Host", err.Error())
		return
	}

	// Update the state with the updated values
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Delete deletes the resource and removes the Terraform state
func (r *macHostResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state macHostResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete the MAC Host
	err := r.client.DeleteMACHost(state.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error deleting MAC Host", err.Error())
		return
	}
}

// ImportState handles resource import
func (r *macHostResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import by name
	resource.ImportStatePassthroughID(ctx, path.Root("name"), req, resp)
}