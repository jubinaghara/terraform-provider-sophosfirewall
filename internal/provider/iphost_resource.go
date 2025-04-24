// internal/provider/iphost_resource.go
package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/path"
)

// Ensure the implementation satisfies the expected interfaces
var _ resource.Resource = &ipHostResource{}
var _ resource.ResourceWithImportState = &ipHostResource{}

// ipHostResource is the resource implementation
type ipHostResource struct {
	client *SophosClient
}

// ipHostResourceModel maps the resource schema data
type ipHostResourceModel struct {
	Name            types.String `tfsdk:"name"`
	IPFamily        types.String `tfsdk:"ip_family"`
	HostType        types.String `tfsdk:"host_type"`
	IPAddress       types.String `tfsdk:"ip_address"`
	Subnet          types.String `tfsdk:"subnet"`
	StartIPAddress  types.String `tfsdk:"start_ip_address"`
	EndIPAddress    types.String `tfsdk:"end_ip_address"`
	ListOfIPAddresses types.String `tfsdk:"list_of_ip_addresses"`
	HostGroups      []types.String `tfsdk:"host_groups"`
}

// NewIPHostResource creates a new resource
func NewIPHostResource() resource.Resource {
	return &ipHostResource{}
}

// Metadata returns the resource type name
func (r *ipHostResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_iphost"
}

// Schema defines the schema for the resource
func (r *ipHostResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Sophos Firewall IP Host object",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description: "Name of the IP Host",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"ip_family": schema.StringAttribute{
				Description: "IP Family (IPv4 or IPv6)",
				Optional:    true,
				Computed:    true,
			},
			"host_type": schema.StringAttribute{
				Description: "Host Type (IP, Network, IPRange, IPList)",
				Required:    true,
			},
			"ip_address": schema.StringAttribute{
				Description: "IP Address for IP or Network types",
				Optional:    true,
			},
			"subnet": schema.StringAttribute{
				Description: "Subnet mask for Network type",
				Optional:    true,
			},
			"start_ip_address": schema.StringAttribute{
				Description: "Start IP Address for IPRange type",
				Optional:    true,
			},
			"end_ip_address": schema.StringAttribute{
				Description: "End IP Address for IPRange type",
				Optional:    true,
			},
			"list_of_ip_addresses": schema.StringAttribute{
				Description: "Comma-separated list of IP addresses for IPList type",
				Optional:    true,
			},
			"host_groups": schema.ListAttribute{
				Description: "List of host groups this IP Host belongs to",
				Optional:    true,
				ElementType: types.StringType,
			},
		},
	}
}

// Configure adds the provider configured client to the resource
func (r *ipHostResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// Create creates a new IP Host
func (r *ipHostResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ipHostResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Map from the terraform model to the API model
	ipHost := &IPHost{
		Name:           plan.Name.ValueString(),
		IPFamily:       plan.IPFamily.ValueString(),
		HostType:       plan.HostType.ValueString(),
		IPAddress:      plan.IPAddress.ValueString(),
		Subnet:         plan.Subnet.ValueString(),
		StartIPAddress: plan.StartIPAddress.ValueString(),
		EndIPAddress:   plan.EndIPAddress.ValueString(),
		ListOfIPAddresses: plan.ListOfIPAddresses.ValueString(),
	}

	// Add host groups if specified
	if len(plan.HostGroups) > 0 {
		ipHost.HostGroupList = &HostGroupList{
			HostGroups: make([]string, 0, len(plan.HostGroups)),
		}
		for _, hg := range plan.HostGroups {
			ipHost.HostGroupList.HostGroups = append(ipHost.HostGroupList.HostGroups, hg.ValueString())
		}
	}

	// Create the IP Host
	err := r.client.CreateIPHost(ipHost)
	if err != nil {
		resp.Diagnostics.AddError("Error creating IP Host", err.Error())
		return
	}

	// Set the resource ID to the name
	// Update the plan with any computed values
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Read refreshes the Terraform state with the latest data
func (r *ipHostResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ipHostResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the IP Host from the API
	ipHost, err := r.client.ReadIPHost(state.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading IP Host", err.Error())
		return
	}

	if ipHost == nil {
		// Resource no longer exists
		resp.State.RemoveResource(ctx)
		return
	}

	// Map from the API model to the terraform model
	state.IPFamily = types.StringValue(ipHost.IPFamily)
	state.HostType = types.StringValue(ipHost.HostType)
	state.IPAddress = types.StringValue(ipHost.IPAddress)
	state.Subnet = types.StringValue(ipHost.Subnet)
	state.StartIPAddress = types.StringValue(ipHost.StartIPAddress)
	state.EndIPAddress = types.StringValue(ipHost.EndIPAddress)
	state.ListOfIPAddresses = types.StringValue(ipHost.ListOfIPAddresses)

	// Map host groups
	if ipHost.HostGroupList != nil && len(ipHost.HostGroupList.HostGroups) > 0 {
		hostGroups := make([]types.String, 0, len(ipHost.HostGroupList.HostGroups))
		for _, hg := range ipHost.HostGroupList.HostGroups {
			hostGroups = append(hostGroups, types.StringValue(hg))
		}
		state.HostGroups = hostGroups
	} else {
		state.HostGroups = []types.String{}
	}

	// Save the updated state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

// Update updates the resource and sets the updated Terraform state
func (r *ipHostResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ipHostResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Map from the terraform model to the API model
	ipHost := &IPHost{
		Name:           plan.Name.ValueString(),
		IPFamily:       plan.IPFamily.ValueString(),
		HostType:       plan.HostType.ValueString(),
		IPAddress:      plan.IPAddress.ValueString(),
		Subnet:         plan.Subnet.ValueString(),
		StartIPAddress: plan.StartIPAddress.ValueString(),
		EndIPAddress:   plan.EndIPAddress.ValueString(),
		ListOfIPAddresses: plan.ListOfIPAddresses.ValueString(),
	}

	// Add host groups if specified
	if len(plan.HostGroups) > 0 {
		ipHost.HostGroupList = &HostGroupList{
			HostGroups: make([]string, 0, len(plan.HostGroups)),
		}
		for _, hg := range plan.HostGroups {
			ipHost.HostGroupList.HostGroups = append(ipHost.HostGroupList.HostGroups, hg.ValueString())
		}
	}

	// Update the IP Host
	err := r.client.UpdateIPHost(ipHost)
	if err != nil {
		resp.Diagnostics.AddError("Error updating IP Host", err.Error())
		return
	}

	// Update the state with the updated values
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Delete deletes the resource and removes the Terraform state
func (r *ipHostResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ipHostResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete the IP Host
	err := r.client.DeleteIPHost(state.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error deleting IP Host", err.Error())
		return
	}
}

// ImportState handles resource import
func (r *ipHostResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import by name
	resource.ImportStatePassthroughID(ctx, path.Root("name"), req, resp)
}