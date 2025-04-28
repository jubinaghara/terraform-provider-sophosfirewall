// internal/provider/firewall_rule.go
package provider

import (
	"context"
	"encoding/xml"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// FirewallRule represents a Sophos firewall rule
type FirewallRule struct {
	XMLName           xml.Name        `xml:"FirewallRule"`
	Name              string          `xml:"Name"`
	Description       string          `xml:"Description"`
	IPFamily          string          `xml:"IPFamily"`
	Status            string          `xml:"Status"`
	Position          string          `xml:"Position"`
	PolicyType        string          `xml:"PolicyType"`
	After             *RulePosition   `xml:"After,omitempty"`
	Before            *RulePosition   `xml:"Before,omitempty"`
	NetworkPolicy     *NetworkPolicy  `xml:"NetworkPolicy,omitempty"`
	TransactionID     string          `xml:"transactionid,attr,omitempty"`
}

// RulePosition specifies the position relative to another rule
type RulePosition struct {
	Name string `xml:"Name"`
}

// NetworkPolicy contains network policy settings
type NetworkPolicy struct {
	Action             string            `xml:"Action"`
	LogTraffic         string            `xml:"LogTraffic"`
	SkipLocalDestined  string            `xml:"SkipLocalDestined"`
	SourceZones        *ZoneList         `xml:"SourceZones"`
	DestinationZones   *ZoneList         `xml:"DestinationZones"`
	Schedule           string            `xml:"Schedule"`
	SourceNetworks     *NetworkList      `xml:"SourceNetworks,omitempty"`
	DestinationNetworks *NetworkList     `xml:"DestinationNetworks,omitempty"`
}

// ZoneList contains a list of zones
type ZoneList struct {
	Zones []string `xml:"Zone"`
}

// NetworkList contains a list of networks
type NetworkList struct {
	Networks []string `xml:"Network"`
}

// XML API firewall rule request structures
type firewallRuleRequestXML struct {
	XMLName xml.Name  `xml:"Request"`
	Login   loginXML  `xml:"Login"`
	Set     firewallRuleSetXML `xml:"Set"`
}

type firewallRuleSetXML struct {
	Operation    string         `xml:"operation,attr"`
	FirewallRules []*FirewallRule `xml:"FirewallRule"`
}

// Ensure the implementation satisfies the expected interfaces
var _ resource.Resource = &firewallRuleResource{}
var _ resource.ResourceWithImportState = &firewallRuleResource{}

// firewallRuleResource is the resource implementation
type firewallRuleResource struct {
	client *SophosClient
}

// firewallRuleResourceModel maps the resource schema data
type firewallRuleResourceModel struct {
	Name               types.String   `tfsdk:"name"`
	Description        types.String   `tfsdk:"description"`
	IPFamily           types.String   `tfsdk:"ip_family"`
	Status             types.String   `tfsdk:"status"`
	Position           types.String   `tfsdk:"position"`
	PolicyType         types.String   `tfsdk:"policy_type"`
	AfterRule          types.String   `tfsdk:"after_rule"`
	BeforeRule         types.String   `tfsdk:"before_rule"`
	Action             types.String   `tfsdk:"action"`
	LogTraffic         types.String   `tfsdk:"log_traffic"`
	SkipLocalDestined  types.String   `tfsdk:"skip_local_destined"`
	SourceZones        []types.String `tfsdk:"source_zones"`
	DestinationZones   []types.String `tfsdk:"destination_zones"`
	Schedule           types.String   `tfsdk:"schedule"`
	SourceNetworks     []types.String `tfsdk:"source_networks"`
	DestinationNetworks []types.String `tfsdk:"destination_networks"`
}

// NewFirewallRuleResource creates a new resource
func NewFirewallRuleResource() resource.Resource {
	return &firewallRuleResource{}
}

// Metadata returns the resource type name
func (r *firewallRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_firewall_rule"
}

// Schema defines the schema for the resource
func (r *firewallRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Sophos Firewall rule",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description: "Name of the firewall rule",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"description": schema.StringAttribute{
				Description: "Description of the rule",
				Optional:    true,
			},
			"ip_family": schema.StringAttribute{
				Description: "IP Family (IPv4 or IPv6)",
				Optional:    true,
				Computed:    true,
			},
			"status": schema.StringAttribute{
				Description: "Status (Enable or Disable)",
				Optional:    true,
				Computed:    true,
			},
			"position": schema.StringAttribute{
				Description: "Position (Top, Bottom, After, Before)",
				Optional:    true,
				Computed:    true,
			},
			"policy_type": schema.StringAttribute{
				Description: "Policy Type (Network)",
				Required:    true,
			},
			"after_rule": schema.StringAttribute{
				Description: "Rule to position after (used when position is 'After')",
				Optional:    true,
			},
			"before_rule": schema.StringAttribute{
				Description: "Rule to position before (used when position is 'Before')",
				Optional:    true,
			},
			"action": schema.StringAttribute{
				Description: "Action (Accept, Reject, Drop)",
				Required:    true,
			},
			"log_traffic": schema.StringAttribute{
				Description: "Log traffic (Enable or Disable)",
				Optional:    true,
				Computed:    true,
			},
			"skip_local_destined": schema.StringAttribute{
				Description: "Skip local destined (Enable or Disable)",
				Optional:    true,
				Computed:    true,
			},
			"source_zones": schema.ListAttribute{
				Description: "List of source zones",
				Required:    true,
				ElementType: types.StringType,
			},
			"destination_zones": schema.ListAttribute{
				Description: "List of destination zones",
				Required:    true,
				ElementType: types.StringType,
			},
			"schedule": schema.StringAttribute{
				Description: "Schedule name",
				Optional:    true,
				Computed:    true,
			},
			"source_networks": schema.ListAttribute{
				Description: "List of source networks",
				Optional:    true,
				ElementType: types.StringType,
			},
			"destination_networks": schema.ListAttribute{
				Description: "List of destination networks",
				Optional:    true,
				ElementType: types.StringType,
			},
		},
	}
}

// Configure adds the provider configured client to the resource
func (r *firewallRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// Create creates a new firewall rule
func (r *firewallRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan firewallRuleResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert the model to API structure
	rule := r.modelToAPIFirewallRule(plan)

	// Create the firewall rule
	err := r.client.CreateFirewallRule(rule)
	if err != nil {
		resp.Diagnostics.AddError("Error creating firewall rule", err.Error())
		return
	}

	// Save the resource state
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Read refreshes the Terraform state with the latest data
func (r *firewallRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state firewallRuleResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the firewall rule from the API
	rule, err := r.client.ReadFirewallRule(state.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading firewall rule", err.Error())
		return
	}

	if rule == nil {
		// Resource no longer exists
		resp.State.RemoveResource(ctx)
		return
	}

	// Update the Terraform state
	state = r.apiToModelFirewallRule(*rule)
	
	// Save the updated state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

// Update updates the resource and sets the updated Terraform state
func (r *firewallRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan firewallRuleResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert the model to API structure
	rule := r.modelToAPIFirewallRule(plan)

	// Update the firewall rule
	err := r.client.UpdateFirewallRule(rule)
	if err != nil {
		resp.Diagnostics.AddError("Error updating firewall rule", err.Error())
		return
	}

	// Save the updated state
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Delete deletes the resource and removes the Terraform state
func (r *firewallRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state firewallRuleResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete the firewall rule
	err := r.client.DeleteFirewallRule(state.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error deleting firewall rule", err.Error())
		return
	}
}

// ImportState handles resource import
func (r *firewallRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import by name
	resource.ImportStatePassthroughID(ctx, path.Root("name"), req, resp)
}

// Helper method to convert from Terraform model to API structure
func (r *firewallRuleResource) modelToAPIFirewallRule(model firewallRuleResourceModel) *FirewallRule {
	rule := &FirewallRule{
		Name:         model.Name.ValueString(),
		Description:  model.Description.ValueString(),
		IPFamily:     model.IPFamily.ValueString(),
		Status:       model.Status.ValueString(),
		Position:     model.Position.ValueString(),
		PolicyType:   model.PolicyType.ValueString(),
		TransactionID: "",
	}

	// Set positioning (After or Before)
	if !model.AfterRule.IsNull() && model.AfterRule.ValueString() != "" {
		rule.After = &RulePosition{
			Name: model.AfterRule.ValueString(),
		}
	}

	if !model.BeforeRule.IsNull() && model.BeforeRule.ValueString() != "" {
		rule.Before = &RulePosition{
			Name: model.BeforeRule.ValueString(),
		}
	}

	// Set Network Policy
	rule.NetworkPolicy = &NetworkPolicy{
		Action:            model.Action.ValueString(),
		LogTraffic:        model.LogTraffic.ValueString(),
		SkipLocalDestined: model.SkipLocalDestined.ValueString(),
		Schedule:          model.Schedule.ValueString(),
	}

	// Source Zones
	if len(model.SourceZones) > 0 {
		rule.NetworkPolicy.SourceZones = &ZoneList{
			Zones: make([]string, 0, len(model.SourceZones)),
		}
		for _, zone := range model.SourceZones {
			rule.NetworkPolicy.SourceZones.Zones = append(rule.NetworkPolicy.SourceZones.Zones, zone.ValueString())
		}
	}

	// Destination Zones
	if len(model.DestinationZones) > 0 {
		rule.NetworkPolicy.DestinationZones = &ZoneList{
			Zones: make([]string, 0, len(model.DestinationZones)),
		}
		for _, zone := range model.DestinationZones {
			rule.NetworkPolicy.DestinationZones.Zones = append(rule.NetworkPolicy.DestinationZones.Zones, zone.ValueString())
		}
	}

	// Source Networks
	if len(model.SourceNetworks) > 0 {
		rule.NetworkPolicy.SourceNetworks = &NetworkList{
			Networks: make([]string, 0, len(model.SourceNetworks)),
		}
		for _, network := range model.SourceNetworks {
			rule.NetworkPolicy.SourceNetworks.Networks = append(rule.NetworkPolicy.SourceNetworks.Networks, network.ValueString())
		}
	}

	// Destination Networks
	if len(model.DestinationNetworks) > 0 {
		rule.NetworkPolicy.DestinationNetworks = &NetworkList{
			Networks: make([]string, 0, len(model.DestinationNetworks)),
		}
		for _, network := range model.DestinationNetworks {
			rule.NetworkPolicy.DestinationNetworks.Networks = append(rule.NetworkPolicy.DestinationNetworks.Networks, network.ValueString())
		}
	}

	return rule
}

// Helper method to convert from API structure to Terraform model
func (r *firewallRuleResource) apiToModelFirewallRule(rule FirewallRule) firewallRuleResourceModel {
	model := firewallRuleResourceModel{
		Name:        types.StringValue(rule.Name),
		Description: types.StringValue(rule.Description),
		IPFamily:    types.StringValue(rule.IPFamily),
		Status:      types.StringValue(rule.Status),
		Position:    types.StringValue(rule.Position),
		PolicyType:  types.StringValue(rule.PolicyType),
	}

	// Set position references
	if rule.After != nil {
		model.AfterRule = types.StringValue(rule.After.Name)
	}
	
	if rule.Before != nil {
		model.BeforeRule = types.StringValue(rule.Before.Name)
	}

	// Set network policy attributes
	if rule.NetworkPolicy != nil {
		model.Action = types.StringValue(rule.NetworkPolicy.Action)
		model.LogTraffic = types.StringValue(rule.NetworkPolicy.LogTraffic)
		model.SkipLocalDestined = types.StringValue(rule.NetworkPolicy.SkipLocalDestined)
		model.Schedule = types.StringValue(rule.NetworkPolicy.Schedule)

		// Source Zones
		if rule.NetworkPolicy.SourceZones != nil {
			zones := make([]types.String, 0, len(rule.NetworkPolicy.SourceZones.Zones))
			for _, zone := range rule.NetworkPolicy.SourceZones.Zones {
				zones = append(zones, types.StringValue(zone))
			}
			model.SourceZones = zones
		}

		// Destination Zones
		if rule.NetworkPolicy.DestinationZones != nil {
			zones := make([]types.String, 0, len(rule.NetworkPolicy.DestinationZones.Zones))
			for _, zone := range rule.NetworkPolicy.DestinationZones.Zones {
				zones = append(zones, types.StringValue(zone))
			}
			model.DestinationZones = zones
		}

		// Source Networks
		if rule.NetworkPolicy.SourceNetworks != nil {
			networks := make([]types.String, 0, len(rule.NetworkPolicy.SourceNetworks.Networks))
			for _, network := range rule.NetworkPolicy.SourceNetworks.Networks {
				networks = append(networks, types.StringValue(network))
			}
			model.SourceNetworks = networks
		}

		// Destination Networks
		if rule.NetworkPolicy.DestinationNetworks != nil {
			networks := make([]types.String, 0, len(rule.NetworkPolicy.DestinationNetworks.Networks))
			for _, network := range rule.NetworkPolicy.DestinationNetworks.Networks {
				networks = append(networks, types.StringValue(network))
			}
			model.DestinationNetworks = networks
		}
	}

	return model
}