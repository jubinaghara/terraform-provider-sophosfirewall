package provider

import (
	"context"
	"fmt"
	"log"
	"github.com/hashicorp/terraform-plugin-framework/datasource"  // Required for datasource functions
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types" 
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/firewallrule"
	// Required for types.String and other type functions
)

// Ensure the implementation satisfies the expected interfaces
var _ datasource.DataSource = &firewallRuleDataSource{}

// firewallRuleDataSource is the data source implementation
type firewallRuleDataSource struct {
	client *firewallrule.Client
}

// NewFirewallRuleDataSource creates a new data source
func NewFirewallRuleDataSource() datasource.DataSource {
	return &firewallRuleDataSource{}
}

// Metadata returns the data source type name
func (d *firewallRuleDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_firewallrule"
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
			"dscp_marking": schema.StringAttribute{
				Description: "DSCP Marking value",
				Optional:    true,
				Computed:    true,
			},
			"web_filter": schema.StringAttribute{
				Description: "Web Filter policy",
				Optional:    true,
				Computed:    true,
			},
			"web_category_base_qos_policy": schema.StringAttribute{
				Description: "Web Category Base QoS Policy",
				Optional:    true,
				Computed:    true,
			},
			"block_quick_quic": schema.StringAttribute{
				Description: "Block Quick/QUIC protocol (Enable or Disable)",
				Optional:    true,
				Computed:    true,
			},
			"scan_virus": schema.StringAttribute{
				Description: "Scan for viruses (Enable or Disable)",
				Optional:    true,
				Computed:    true,
			},
			"zero_day_protection": schema.StringAttribute{
				Description: "Zero Day Protection (Enable or Disable)",
				Optional:    true,
				Computed:    true,
			},
			"proxy_mode": schema.StringAttribute{
				Description: "Proxy Mode (Enable or Disable)",
				Optional:    true,
				Computed:    true,
			},
			"decrypt_https": schema.StringAttribute{
				Description: "Decrypt HTTPS (Enable or Disable)",
				Optional:    true,
				Computed:    true,
			},
			"application_control": schema.StringAttribute{
				Description: "Application Control policy",
				Optional:    true,
				Computed:    true,
			},
			"application_base_qos_policy": schema.StringAttribute{
				Description: "Application Base QoS Policy",
				Optional:    true,
				Computed:    true,
			},
			"intrusion_prevention": schema.StringAttribute{
				Description: "Intrusion Prevention policy",
				Optional:    true,
				Computed:    true,
			},
			"traffic_shapping_policy": schema.StringAttribute{
				Description: "Traffic Shaping Policy",
				Optional:    true,
				Computed:    true,
			},
			"scan_smtp": schema.StringAttribute{
				Description: "Scan SMTP (Enable or Disable)",
				Optional:    true,
				Computed:    true,
			},
			"scan_smtps": schema.StringAttribute{
				Description: "Scan SMTPS (Enable or Disable)",
				Optional:    true,
				Computed:    true,
			},
			"scan_imap": schema.StringAttribute{
				Description: "Scan IMAP (Enable or Disable)",
				Optional:    true,
				Computed:    true,
			},
			"scan_imaps": schema.StringAttribute{
				Description: "Scan IMAPS (Enable or Disable)",
				Optional:    true,
				Computed:    true,
			},
			"scan_pop3": schema.StringAttribute{
				Description: "Scan POP3 (Enable or Disable)",
				Optional:    true,
				Computed:    true,
			},
			"scan_pop3s": schema.StringAttribute{
				Description: "Scan POP3S (Enable or Disable)",
				Optional:    true,
				Computed:    true,
			},
			"scan_ftp": schema.StringAttribute{
				Description: "Scan FTP (Enable or Disable)",
				Optional:    true,
				Computed:    true,
			},
			"source_security_heartbeat": schema.StringAttribute{
				Description: "Source Security Heartbeat (Enable or Disable)",
				Optional:    true,
				Computed:    true,
			},
			"minimum_source_hb_permitted": schema.StringAttribute{
				Description: "Minimum Source HB Permitted",
				Optional:    true,
				Computed:    true,
			},
			"dest_security_heartbeat": schema.StringAttribute{
				Description: "Destination Security Heartbeat (Enable or Disable)",
				Optional:    true,
				Computed:    true,
			},
			"minimum_destination_hb_permitted": schema.StringAttribute{
				Description: "Minimum Destination HB Permitted",
				Optional:    true,
				Computed:    true,
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

	d.client = firewallrule.NewClient(client.BaseClient)
}


// Read refreshes the Terraform state with the latest data
func (d *firewallRuleDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state firewallRuleResourceModel

	// Get current state
	diags := req.Config.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the name of the rule to fetch
	ruleName := state.Name.ValueString()
	if ruleName == "" {
		resp.Diagnostics.AddError(
			"Missing required parameter",
			"The 'name' attribute is required to fetch a firewall rule",
		)
		return
	}

	
	// Call the API to get the firewall rule
	rule, err := d.client.ReadFirewallRule(ruleName)
	if err != nil {
		resp.Diagnostics.AddError("Error reading firewall rule", err.Error())
		return
	}

	log.Printf("[DEBUG] Data Source Read function FW RULE 30-500- Retrieved FW rule: %+v", ruleName) // Log the retrieved object


	if rule == nil {
		resp.Diagnostics.AddError(
			"Firewall rule not found",
			fmt.Sprintf("Firewall rule with name %s not found", ruleName),
		)
		return
	}

	// Map the API response to the data source schema
	state = mapFirewallRuleToModel(rule)

	// Set state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

// mapFirewallRuleToModel converts an API firewall rule to the resource model
func mapFirewallRuleToModel(rule *firewallrule.FirewallRule) firewallRuleResourceModel {
	model := firewallRuleResourceModel{
		Name:        types.StringValue(rule.Name),
		PolicyType:  types.StringValue(rule.PolicyType),
		IPFamily:    types.StringValue(rule.IPFamily),
		Status:      types.StringValue(rule.Status),
		Position:    types.StringValue(rule.Position),
	}

	// Handle optional string fields
	if rule.Description != "" {
		model.Description = types.StringValue(rule.Description)
	} else {
		model.Description = types.StringNull()
	}

	// Handle After/Before rule if specified
	if rule.After != nil && rule.After.Name != "" {
		model.AfterRule = types.StringValue(rule.After.Name)
	} else {
		model.AfterRule = types.StringNull()
	}

	if rule.Before != nil && rule.Before.Name != "" {
		model.BeforeRule = types.StringValue(rule.Before.Name)
	} else {
		model.BeforeRule = types.StringNull()
	}

	// Network Policy settings
	if rule.NetworkPolicy != nil {
		model.Action = types.StringValue(rule.NetworkPolicy.Action)
		model.LogTraffic = types.StringValue(rule.NetworkPolicy.LogTraffic)
		model.SkipLocalDestined = types.StringValue(rule.NetworkPolicy.SkipLocalDestined)
		model.Schedule = types.StringValue(rule.NetworkPolicy.Schedule)
		model.DSCPMarking = types.StringValue(rule.NetworkPolicy.DSCPMarking)
		model.WebFilter = types.StringValue(rule.NetworkPolicy.WebFilter)
		model.WebCategoryBaseQoSPolicy = types.StringValue(rule.NetworkPolicy.WebCategoryBaseQoSPolicy)
		model.BlockQuickQuic = types.StringValue(rule.NetworkPolicy.BlockQuickQuic)
		model.ScanVirus = types.StringValue(rule.NetworkPolicy.ScanVirus)
		model.ZeroDayProtection = types.StringValue(rule.NetworkPolicy.ZeroDayProtection)
		model.ProxyMode = types.StringValue(rule.NetworkPolicy.ProxyMode)
		model.DecryptHTTPS = types.StringValue(rule.NetworkPolicy.DecryptHTTPS)
		model.ApplicationControl = types.StringValue(rule.NetworkPolicy.ApplicationControl)
		model.ApplicationBaseQoSPolicy = types.StringValue(rule.NetworkPolicy.ApplicationBaseQoSPolicy)
		model.IntrusionPrevention = types.StringValue(rule.NetworkPolicy.IntrusionPrevention)
		model.TrafficShappingPolicy = types.StringValue(rule.NetworkPolicy.TrafficShappingPolicy)
		model.ScanSMTP = types.StringValue(rule.NetworkPolicy.ScanSMTP)
		model.ScanSMTPS = types.StringValue(rule.NetworkPolicy.ScanSMTPS)
		model.ScanIMAP = types.StringValue(rule.NetworkPolicy.ScanIMAP)
		model.ScanIMAPS = types.StringValue(rule.NetworkPolicy.ScanIMAPS)
		model.ScanPOP3 = types.StringValue(rule.NetworkPolicy.ScanPOP3)
		model.ScanPOP3S = types.StringValue(rule.NetworkPolicy.ScanPOP3S)
		model.ScanFTP = types.StringValue(rule.NetworkPolicy.ScanFTP)
		model.SourceSecurityHeartbeat = types.StringValue(rule.NetworkPolicy.SourceSecurityHeartbeat)
		model.MinimumSourceHBPermitted = types.StringValue(rule.NetworkPolicy.MinimumSourceHBPermitted)
		model.DestSecurityHeartbeat = types.StringValue(rule.NetworkPolicy.DestSecurityHeartbeat)
		model.MinimumDestinationHBPermitted = types.StringValue(rule.NetworkPolicy.MinimumDestinationHBPermitted)

		// Handle source zones
		if rule.NetworkPolicy.SourceZones != nil && len(rule.NetworkPolicy.SourceZones.Zones) > 0 {
			sourceZones := make([]types.String, len(rule.NetworkPolicy.SourceZones.Zones))
			for i, zone := range rule.NetworkPolicy.SourceZones.Zones {
				sourceZones[i] = types.StringValue(zone)
			}
			model.SourceZones = sourceZones
		}

		// Handle destination zones
		if rule.NetworkPolicy.DestinationZones != nil && len(rule.NetworkPolicy.DestinationZones.Zones) > 0 {
			destZones := make([]types.String, len(rule.NetworkPolicy.DestinationZones.Zones))
			for i, zone := range rule.NetworkPolicy.DestinationZones.Zones {
				destZones[i] = types.StringValue(zone)
			}
			model.DestinationZones = destZones
		}

		// Handle source networks
		if rule.NetworkPolicy.SourceNetworks != nil && len(rule.NetworkPolicy.SourceNetworks.Networks) > 0 {
			sourceNetworks := make([]types.String, len(rule.NetworkPolicy.SourceNetworks.Networks))
			for i, network := range rule.NetworkPolicy.SourceNetworks.Networks {
				sourceNetworks[i] = types.StringValue(network)
			}
			model.SourceNetworks = sourceNetworks
		}

		// Handle destination networks
		if rule.NetworkPolicy.DestinationNetworks != nil && len(rule.NetworkPolicy.DestinationNetworks.Networks) > 0 {
			destNetworks := make([]types.String, len(rule.NetworkPolicy.DestinationNetworks.Networks))
			for i, network := range rule.NetworkPolicy.DestinationNetworks.Networks {
				destNetworks[i] = types.StringValue(network)
			}
			model.DestinationNetworks = destNetworks
		}
	}

	return model
}