//iphost_resource.go
package provider

import (
	"context"
	"fmt"
	"log"
	"slices"


	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/iphostgroup"
)

// Ensure the implementation satisfies the expected interfaces
var _ resource.Resource = &ipHostGroupResource{}
var _ resource.ResourceWithImportState = &ipHostGroupResource{}

// ipHostGroupResource is the resource implementation
type ipHostGroupResource struct {
	client *iphostgroup.Client
}


// ipHostGroupResourceModel maps the resource schema data
type ipHostGroupResourceModel struct {
	Name             types.String   `tfsdk:"name"`
	IPFamily         types.String   `tfsdk:"ip_family"`
	Description      types.String   `tfsdk:"description"`
	Hosts  			[]types.String 	`tfsdk:"host_list"`
}



// NewipHostGroupResource creates a new resource
func NewIPHostGroupResource() resource.Resource {
	return &ipHostGroupResource{}
}

// Metadata returns the resource type name
func (r *ipHostGroupResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_iphostgroup"
}

// Schema defines the schema for the resource
func (r *ipHostGroupResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Sophos Firewall IP Host Group object",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description: "Name of the IP Host Group",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"description": schema.StringAttribute{
				Description: "Description of Host Group",
				Optional:    true,
				Computed:    true,
			},
			"ip_family": schema.StringAttribute{
				Description: "IP Family (IPv4 or IPv6)",
				Optional:    true,
				Computed:    true,
			},
			"host_list": schema.ListAttribute{
				Description: "List of host this Host Group refers to",
				Optional:    true,
				ElementType: types.StringType,
			},
		},
	}
}

// Configure adds the provider configured client to the resource
func (r *ipHostGroupResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*SophosClient)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *iphostgroup.Client, got: %T", req.ProviderData),
		)
		return
	}

	// Create the iphostgroup client from the base client
	r.client = iphostgroup.NewClient(client.BaseClient)
}

// Create creates a new IP Host Group
func (r *ipHostGroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ipHostGroupResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Map from the terraform model to the API model
	ipHostGroup := &iphostgroup.IPHostGroup{
		Name:            plan.Name.ValueString(),
		IPFamily:        plan.IPFamily.ValueString(),
		Description:     plan.Description.ValueString(),
		TransactionID:     "", // Set empty
	}

	// Add host groups if specified
	if len(plan.Hosts) > 0 {
		ipHostGroup.HostList = &iphostgroup.HostList{
			Hosts: make([]string, 0, len(plan.Hosts)),
		}
		for _, hg := range plan.Hosts {
			ipHostGroup.HostList.Hosts = append(ipHostGroup.HostList.Hosts, hg.ValueString())
		}
	}

	// Create the IP Host Group
	err := r.client.CreateIPHostGroup(ipHostGroup)
	if err != nil {
		resp.Diagnostics.AddError("Error creating IP Host Group", err.Error())
		return
	}

	// Set the resource ID to the name
	// Update the plan with any computed values
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Read refreshes the Terraform state with the latest data
// Read refreshes the Terraform state with the latest data
func (r *ipHostGroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ipHostGroupResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the IP Host Group from the API
	ipHostGroup, err := r.client.ReadIPHostGroup(state.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading IP Host", err.Error())
		return
	}

	log.Printf("[DEBUG] Resource Read function - Retrieved IP Host Group: %+v", ipHostGroup) // Log the retrieved object

	if ipHostGroup == nil {
		// Resource no longer exists
		resp.State.RemoveResource(ctx)
		return
	}

	// Update state fields regardless of host type
	state.Name = types.StringValue(ipHostGroup.Name)
	state.IPFamily = types.StringValue(ipHostGroup.IPFamily)
	state.Description = types.StringValue(ipHostGroup.Description)
		
	// Handle host groups consistently
	if ipHostGroup.HostList != nil && len(ipHostGroup.HostList.Hosts) > 0 {
		// Create a slice for sorting to ensure consistent order
		hostStrings := make([]string, 0, len(ipHostGroup.HostList.Hosts))
		for _, hg := range ipHostGroup.HostList.Hosts {
			hostStrings = append(hostStrings, hg)
		}
		
		// Sort the hosts alphabetically
		slices.Sort(hostStrings)
		
		// Convert to types.String array
		hosts := make([]types.String, 0, len(hostStrings))
		for _, hg := range hostStrings {
			hosts = append(hosts, types.StringValue(hg))
		}
		
		// Use the correct field as defined in the struct tag
		state.Hosts = hosts
	} else {
		// Always initialize to empty slice when API returns no host groups
		state.Hosts = []types.String{}
	}

	// Add debug logging to compare state
	var currentHosts []string
	for _, h := range state.Hosts {
		currentHosts = append(currentHosts, h.ValueString())
	}
	log.Printf("[DEBUG] Updated state hosts: %v", currentHosts)

	// Save the updated state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

// Update updates the resource and sets the updated Terraform state
func (r *ipHostGroupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ipHostGroupResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Map from the terraform model to the API model
	ipHostGroup := &iphostgroup.IPHostGroup{
		Name:              plan.Name.ValueString(),
		IPFamily:          plan.IPFamily.ValueString(),
		Description:       plan.Description.ValueString(),
		TransactionID:     "",
	}

	// Add host groups if specified
	if len(plan.Hosts) > 0 {
		ipHostGroup.HostList = &iphostgroup.HostList{
			Hosts: make([]string, 0, len(plan.Hosts)),
		}
		for _, hg := range plan.Hosts {
			ipHostGroup.HostList.Hosts = append(ipHostGroup.HostList.Hosts, hg.ValueString())
		}
	}

	// Update the IP Host
	err := r.client.UpdateIPHostGroup(ipHostGroup)
	if err != nil {
		resp.Diagnostics.AddError("Error updating IP Host Group", err.Error())
		return
	}

	// Update the state with the updated values
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Delete deletes the resource and removes the Terraform state
func (r *ipHostGroupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ipHostGroupResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete the IP Host
	err := r.client.DeleteIPHostGroup(state.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error deleting IP Host Group", err.Error())
		return
	}
}

// ImportState handles resource import
func (r *ipHostGroupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import by name
	resource.ImportStatePassthroughID(ctx, path.Root("name"), req, resp)
}

