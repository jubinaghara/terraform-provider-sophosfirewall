package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces
var _ datasource.DataSource = &firewallRuleDataSource{}

// firewallRuleDataSource is the data source implementation
type firewallRuleDataSource struct {
	client *SophosClient
}

// NewFirewallRuleDataSource creates a new data source
func NewFirewallRuleDataSource() datasource.DataSource {
	return &firewallRuleDataSource{}
}

// Metadata returns the data source type name
func (d *firewallRuleDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_firewall_rule"
}

// Schema defines the schema for the data source
func (d *firewallRuleDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Fetches a Sophos Firewall rule by name.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description: "Name of the firewall rule",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "Description of the rule",
				Computed:    true,
			},
			"ip_family": schema.StringAttribute{
				Description: "IP Family (IPv4 or IPv6)",
				Computed:    true,
			},
			"status": schema.StringAttribute{
				Description: "Status (Enable or Disable)",
				Computed:    true,
			},
			"position": schema.StringAttribute{
				Description: "Position (Top, Bottom, After, Before)",
				Computed:    true,
			},
			"policy_type": schema.StringAttribute{
				Description: "Policy Type (Network)",
				Computed:    true,
			},
			"after_rule": schema.StringAttribute{
				Description: "Rule positioned after",
				Computed:    true,
			},
			"before_rule": schema.StringAttribute{
				Description: "Rule positioned before",
				Computed:    true,
			},
			"action": schema.StringAttribute{
				Description: "Action (Accept, Reject, Drop)",
				Computed:    true,
			},
			"log_traffic": schema.StringAttribute{
				Description: "Log traffic (Enable or Disable)",
				Computed:    true,
			},
			"skip_local_destined": schema.StringAttribute{
				Description: "Skip local destined (Enable or Disable)",
				Computed:    true,
			},
			"source_zones": schema.ListAttribute{
				Description: "List of source zones",
				Computed:    true,
				ElementType: types.StringType,
			},
			"destination_zones": schema.ListAttribute{
				Description: "List of destination zones",
				Computed:    true,
				ElementType: types.StringType,
			},
			"schedule": schema.StringAttribute{
				Description: "Schedule name",
				Computed:    true,
			},
			"source_networks": schema.ListAttribute{
				Description: "List of source networks",
				Computed:    true,
				ElementType: types.StringType,
			},
			"destination_networks": schema.ListAttribute{
				Description: "List of destination networks",
				Computed:    true,
				ElementType: types.StringType,
			},
		},
	}
}

// Configure adds the provider configured client to the data source
func (d *firewallRuleDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

// Read refreshes the Terraform state with the latest data
func (d *firewallRuleDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state firewallRuleResourceModel

	diags := req.Config.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the name of the rule to fetch
	ruleName := state.Name.ValueString()

	// Call the API to get the firewall rule
	// Using ReadFirewallRule which should already exist from your resource implementation
	rule, err := d.client.ReadFirewallRule(ruleName)
	if err != nil {
		resp.Diagnostics.AddError("Error reading firewall rule", err.Error())
		return
	}
	if rule == nil {
		resp.Diagnostics.AddError(
			"Firewall rule not found",
			fmt.Sprintf("Firewall rule with name %s not found", ruleName),
		)
		return
	}

	// Use the existing converter from your resource implementation
	fireRuleResource := &firewallRuleResource{client: d.client}
	state = fireRuleResource.apiToModelFirewallRule(*rule)

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}