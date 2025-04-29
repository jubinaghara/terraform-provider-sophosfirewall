package provider

import (
	"context"
	"fmt"
	"strings"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/path"
)

// Ensure the implementation satisfies the expected interfaces
var _ resource.Resource = &macHostResource{}
var _ resource.ResourceWithImportState = &macHostResource{}

// macHostResource is the resource implementation
type macHostResource struct {
	client *SophosClient
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

	r.client = client
}

// parseMACList parses a comma-separated string into a slice of MAC addresses
func parseMACList(macList string) []string {
	if macList == "" {
		return []string{} // Return empty slice instead of nil for consistency
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
// Create creates a new MAC Host
func (r *macHostResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan macHostResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Normalize the type value to be case-consistent 
	hostType := strings.ToUpper(plan.Type.ValueString())
	
	// Map from the terraform model to the API model
	macHost := &MACHost{
		Name:          plan.Name.ValueString(),
		TransactionID: "", // Set empty
	}
	
	// Set description properly (empty string if not provided)
	if !plan.Description.IsNull() {
		macHost.Description = plan.Description.ValueString()
	} else {
		macHost.Description = ""
	}
	
	// Handle field values based on the normalized type
	if hostType == "MACADDRESS" {
		macHost.Type = "MACAddress" // Set the exact case the API expects
		
		if !plan.MACAddress.IsNull() {
			// Validate MAC address format
			macAddr := plan.MACAddress.ValueString()
			if !isValidMACAddress(macAddr) {
				resp.Diagnostics.AddError("Invalid MAC Address Format", 
					fmt.Sprintf("MAC address '%s' is not in a valid format. Use format 'XX:XX:XX:XX:XX:XX'", macAddr))
				return
			}
			
			macHost.MACAddress = macAddr
		} else {
			resp.Diagnostics.AddError("Missing MAC Address", "MACAddress type requires a MAC address")
			return
		}
		
		macHost.ListOfMACAddresses = nil
		
		// Ensure the state will be consistent
		plan.MACAddress = types.StringValue(macHost.MACAddress)
		plan.ListOfMACAddresses = types.StringNull()
	} else if hostType == "MACLIST" {
		macHost.Type = "MACLIST" // Set the exact case the API expects
		
		// Parse MAC addresses from the comma-separated string
		if !plan.ListOfMACAddresses.IsNull() {
			macAddressStr := plan.ListOfMACAddresses.ValueString()
			
			// For empty string, set to empty list
			if macAddressStr == "" {
				macHost.ListOfMACAddresses = []string{}
				plan.ListOfMACAddresses = types.StringValue("")
			} else {
				macAddresses := parseMACList(macAddressStr)
				
				// Validate each MAC address
				for _, mac := range macAddresses {
					if !isValidMACAddress(mac) {
						resp.Diagnostics.AddError("Invalid MAC Address Format", 
							fmt.Sprintf("MAC address '%s' is not in a valid format. Use format 'XX:XX:XX:XX:XX:XX'", mac))
						return
					}
				}
				
				macHost.ListOfMACAddresses = macAddresses
				
				// Update plan to ensure consistent format in state
				if len(macAddresses) > 0 {
					plan.ListOfMACAddresses = types.StringValue(strings.Join(macAddresses, ","))
				} else {
					plan.ListOfMACAddresses = types.StringValue("")
				}
			}
		} else {
			// Empty list is valid but should be consistent
			macHost.ListOfMACAddresses = []string{}
			plan.ListOfMACAddresses = types.StringValue("")
		}
		
		macHost.MACAddress = ""
		plan.MACAddress = types.StringNull()
	} else {
		resp.Diagnostics.AddError("Invalid Type", "Type must be either 'MACAddress' or 'MACLIST'")
		return
	}

	// Create the MAC Host
	err := r.client.CreateMACHost(macHost)
	if err != nil {
		resp.Diagnostics.AddError("Error creating MAC Host", err.Error())
		return
	}

	// Save the normalized type in the state
	plan.Type = types.StringValue(macHost.Type)

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Helper function to validate MAC address format
func isValidMACAddress(mac string) bool {
	// Basic MAC address format validation using regex
	// Format should be XX:XX:XX:XX:XX:XX where X is a hex digit
	macRegex := regexp.MustCompile(`^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$`)
	return macRegex.MatchString(mac)
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
	state.Type = types.StringValue(macHost.Type)
	
	// Set description consistently
	if macHost.Description != "" {
		state.Description = types.StringValue(macHost.Description)
	} else {
		state.Description = types.StringValue("")
	}
	
	// Handle MAC address fields based on type 
	if macHost.Type == "MACAddress" {
		state.MACAddress = types.StringValue(macHost.MACAddress)
		state.ListOfMACAddresses = types.StringNull()
	} else if macHost.Type == "MACLIST" {
		state.MACAddress = types.StringNull()
		
		// Ensure we have the list of MAC addresses from the API response
		if macHost.ListOfMACAddresses != nil && len(macHost.ListOfMACAddresses) > 0 {
			state.ListOfMACAddresses = types.StringValue(strings.Join(macHost.ListOfMACAddresses, ","))
		} else {
			state.ListOfMACAddresses = types.StringValue("")
		}
	} else {
		// Unexpected type - log warning and set fields to null
		resp.Diagnostics.AddWarning(
			"Unexpected MAC Host Type",
			fmt.Sprintf("Unexpected MAC Host type: %s", macHost.Type),
		)
		state.MACAddress = types.StringNull()
		state.ListOfMACAddresses = types.StringNull()
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

	// Normalize the type value to be case-consistent
	hostType := strings.ToUpper(plan.Type.ValueString())
	
	// Map from the terraform model to the API model
	macHost := &MACHost{
		Name:          plan.Name.ValueString(),
		TransactionID: "", // Set empty
	}
	
	// Set description properly (empty string if not provided)
	if !plan.Description.IsNull() {
		macHost.Description = plan.Description.ValueString()
	} else {
		macHost.Description = ""
	}
	
	// Handle field values based on the normalized type
	if hostType == "MACADDRESS" {
		macHost.Type = "MACAddress" // Set the exact case the API expects
		
		if !plan.MACAddress.IsNull() {
			macHost.MACAddress = plan.MACAddress.ValueString()
		} else {
			resp.Diagnostics.AddError("Missing MAC Address", "MACAddress type requires a MAC address")
			return
		}
		
		macHost.ListOfMACAddresses = nil
		
		// Ensure the state will be consistent
		plan.MACAddress = types.StringValue(macHost.MACAddress)
		plan.ListOfMACAddresses = types.StringNull()
	} else if hostType == "MACLIST" {
		macHost.Type = "MACLIST" // Set the exact case the API expects
		
		// Parse MAC addresses from the comma-separated string
		if !plan.ListOfMACAddresses.IsNull() {
			macAddresses := parseMACList(plan.ListOfMACAddresses.ValueString())
			macHost.ListOfMACAddresses = macAddresses
			
			// Update plan to ensure consistent format in state
			if len(macAddresses) > 0 {
				plan.ListOfMACAddresses = types.StringValue(strings.Join(macAddresses, ","))
			} else {
				plan.ListOfMACAddresses = types.StringValue("")
			}
		} else {
			// Empty list is valid but should be consistent
			macHost.ListOfMACAddresses = []string{}
			plan.ListOfMACAddresses = types.StringValue("")
		}
		
		macHost.MACAddress = ""
		plan.MACAddress = types.StringNull()
	} else {
		resp.Diagnostics.AddError("Invalid Type", "Type must be either 'MACAddress' or 'MACLIST'")
		return
	}

	// Update the MAC Host
	err := r.client.UpdateMACHost(macHost)
	if err != nil {
		resp.Diagnostics.AddError("Error updating MAC Host", err.Error())
		return
	}

	// Save the normalized type in the state
	plan.Type = types.StringValue(macHost.Type)

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