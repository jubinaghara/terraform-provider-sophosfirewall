// Updated FirewallRule struct with all available fields
package provider

import (
	"context"
	"encoding/xml"
	"fmt"
	// "os"
	// "os/exec"
	// "bytes"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/firewallrule"
)

// FirewallRule represents a Sophos firewall rule with all available fields
type FirewallRule struct {
	XMLName             xml.Name        `xml:"FirewallRule"`
	Name                string          `xml:"Name"`
	Description         string          `xml:"Description"`
	IPFamily            string          `xml:"IPFamily"`
	Status              string          `xml:"Status"`
	Position            string          `xml:"Position"`
	PolicyType          string          `xml:"PolicyType"`
	After               *RulePosition   `xml:"After,omitempty"`
	Before              *RulePosition   `xml:"Before,omitempty"`
	NetworkPolicy       *NetworkPolicy  `xml:"NetworkPolicy,omitempty"`
	TransactionID       string          `xml:"transactionid,attr,omitempty"`
}

// RulePosition specifies the position relative to another rule
type RulePosition struct {
	Name string `xml:"Name"`
}

// NetworkPolicy contains network policy settings with all available fields
type NetworkPolicy struct {
	Action                       string            `xml:"Action"`
	LogTraffic                   string            `xml:"LogTraffic"`
	SkipLocalDestined            string            `xml:"SkipLocalDestined"`
	Schedule                     string            `xml:"Schedule"`
	SourceZones                  *ZoneList         `xml:"SourceZones"`
	DestinationZones             *ZoneList         `xml:"DestinationZones"`
	SourceNetworks               *NetworkList      `xml:"SourceNetworks,omitempty"`
	DestinationNetworks          *NetworkList      `xml:"DestinationNetworks,omitempty"`
	DSCPMarking                  string            `xml:"DSCPMarking,omitempty"`
	WebFilter                    string            `xml:"WebFilter,omitempty"`
	WebCategoryBaseQoSPolicy     string            `xml:"WebCategoryBaseQoSPolicy,omitempty"`
	BlockQuickQuic               string            `xml:"BlockQuickQuic,omitempty"`
	ScanVirus                    string            `xml:"ScanVirus,omitempty"`
	ZeroDayProtection            string            `xml:"ZeroDayProtection,omitempty"`
	ProxyMode                    string            `xml:"ProxyMode,omitempty"`
	DecryptHTTPS                 string            `xml:"DecryptHTTPS,omitempty"`
	ApplicationControl           string            `xml:"ApplicationControl,omitempty"`
	ApplicationBaseQoSPolicy     string            `xml:"ApplicationBaseQoSPolicy,omitempty"`
	IntrusionPrevention          string            `xml:"IntrusionPrevention,omitempty"`
	TrafficShappingPolicy        string            `xml:"TrafficShappingPolicy,omitempty"`
	ScanSMTP                     string            `xml:"ScanSMTP,omitempty"`
	ScanSMTPS                    string            `xml:"ScanSMTPS,omitempty"`
	ScanIMAP                     string            `xml:"ScanIMAP,omitempty"`
	ScanIMAPS                    string            `xml:"ScanIMAPS,omitempty"`
	ScanPOP3                     string            `xml:"ScanPOP3,omitempty"`
	ScanPOP3S                    string            `xml:"ScanPOP3S,omitempty"`
	ScanFTP                      string            `xml:"ScanFTP,omitempty"`
	SourceSecurityHeartbeat      string            `xml:"SourceSecurityHeartbeat,omitempty"`
	MinimumSourceHBPermitted     string            `xml:"MinimumSourceHBPermitted,omitempty"`
	DestSecurityHeartbeat        string            `xml:"DestSecurityHeartbeat,omitempty"`
	MinimumDestinationHBPermitted string           `xml:"MinimumDestinationHBPermitted,omitempty"`
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
	Login   LoginXML  `xml:"Login"`
	Set     firewallRuleSetXML `xml:"Set"`
}

type LoginXML struct {
	Username string `xml:"Username"`
	Password string `xml:"Password"`
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
	client *firewallrule.Client
}

// Updated resource model with all available fields
type firewallRuleResourceModel struct {
	Name                          types.String   `tfsdk:"name"`
	Description                   types.String   `tfsdk:"description"`
	IPFamily                      types.String   `tfsdk:"ip_family"`
	Status                        types.String   `tfsdk:"status"`
	Position                      types.String   `tfsdk:"position"`
	PolicyType                    types.String   `tfsdk:"policy_type"`
	AfterRule                     types.String   `tfsdk:"after_rule"`
	BeforeRule                    types.String   `tfsdk:"before_rule"`
	Action                        types.String   `tfsdk:"action"`
	LogTraffic                    types.String   `tfsdk:"log_traffic"`
	SkipLocalDestined             types.String   `tfsdk:"skip_local_destined"`
	SourceZones                   []types.String `tfsdk:"source_zones"`
	DestinationZones              []types.String `tfsdk:"destination_zones"`
	Schedule                      types.String   `tfsdk:"schedule"`
	SourceNetworks                []types.String `tfsdk:"source_networks"`
	DestinationNetworks           []types.String `tfsdk:"destination_networks"`
	DSCPMarking                   types.String   `tfsdk:"dscp_marking"`
	WebFilter                     types.String   `tfsdk:"web_filter"`
	WebCategoryBaseQoSPolicy      types.String   `tfsdk:"web_category_base_qos_policy"`
	BlockQuickQuic                types.String   `tfsdk:"block_quick_quic"`
	ScanVirus                     types.String   `tfsdk:"scan_virus"`
	ZeroDayProtection             types.String   `tfsdk:"zero_day_protection"`
	ProxyMode                     types.String   `tfsdk:"proxy_mode"`
	DecryptHTTPS                  types.String   `tfsdk:"decrypt_https"`
	ApplicationControl            types.String   `tfsdk:"application_control"`
	ApplicationBaseQoSPolicy      types.String   `tfsdk:"application_base_qos_policy"`
	IntrusionPrevention           types.String   `tfsdk:"intrusion_prevention"`
	TrafficShappingPolicy         types.String   `tfsdk:"traffic_shapping_policy"`
	ScanSMTP                      types.String   `tfsdk:"scan_smtp"`
	ScanSMTPS                     types.String   `tfsdk:"scan_smtps"`
	ScanIMAP                      types.String   `tfsdk:"scan_imap"`
	ScanIMAPS                     types.String   `tfsdk:"scan_imaps"`
	ScanPOP3                      types.String   `tfsdk:"scan_pop3"`
	ScanPOP3S                     types.String   `tfsdk:"scan_pop3s"`
	ScanFTP                       types.String   `tfsdk:"scan_ftp"`
	SourceSecurityHeartbeat       types.String   `tfsdk:"source_security_heartbeat"`
	MinimumSourceHBPermitted      types.String   `tfsdk:"minimum_source_hb_permitted"`
	DestSecurityHeartbeat         types.String   `tfsdk:"dest_security_heartbeat"`
	MinimumDestinationHBPermitted types.String   `tfsdk:"minimum_destination_hb_permitted"`
}

// NewFirewallRuleResource creates a new resource
func NewFirewallRuleResource() resource.Resource {
	return &firewallRuleResource{}
}

// Metadata returns the resource type name
func (r *firewallRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_firewallrule"
}

// Schema defines the schema for the resource with all available fields
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

	r.client = firewallrule.NewClient(client.BaseClient)
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

	// Read the created rule to ensure state is up-to-date
	createdRule, err := r.client.ReadFirewallRule(plan.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading created firewall rule", err.Error())
		return
	}

	if createdRule == nil {
		resp.Diagnostics.AddError("Error after creation", "Firewall rule was not found after creation")
		return
	}

	// Update the state with the actual created rule
	state := r.apiToModelFirewallRule(*createdRule)
	diags = resp.State.Set(ctx, state)
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

	// Read the updated rule to ensure state is up-to-date
	updatedRule, err := r.client.ReadFirewallRule(plan.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading updated firewall rule", err.Error())
		return
	}

	if updatedRule == nil {
		resp.Diagnostics.AddError("Error after update", "Firewall rule was not found after update")
		return
	}

	// Update the state with the actual updated rule
	state := r.apiToModelFirewallRule(*updatedRule)
	diags = resp.State.Set(ctx, &state)
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
func (r *firewallRuleResource) modelToAPIFirewallRule(model firewallRuleResourceModel) *firewallrule.FirewallRule {
	rule := &firewallrule.FirewallRule{
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
		rule.After = &firewallrule.RulePosition{
			Name: model.AfterRule.ValueString(),
		}
	}

	if !model.BeforeRule.IsNull() && model.BeforeRule.ValueString() != "" {
		rule.Before = &firewallrule.RulePosition{
			Name: model.BeforeRule.ValueString(),
		}
	}

	// Set Network Policy
	rule.NetworkPolicy = &firewallrule.NetworkPolicy{
		Action:            model.Action.ValueString(),
		LogTraffic:        model.LogTraffic.ValueString(),
		SkipLocalDestined: model.SkipLocalDestined.ValueString(),
		Schedule:          model.Schedule.ValueString(),
	}

	// Add all the extra fields
	if !model.DSCPMarking.IsNull() {
		rule.NetworkPolicy.DSCPMarking = model.DSCPMarking.ValueString()
	}
	
	if !model.WebFilter.IsNull() {
		rule.NetworkPolicy.WebFilter = model.WebFilter.ValueString()
	}
	
	if !model.WebCategoryBaseQoSPolicy.IsNull() {
		rule.NetworkPolicy.WebCategoryBaseQoSPolicy = model.WebCategoryBaseQoSPolicy.ValueString()
	}
	
	if !model.BlockQuickQuic.IsNull() {
		rule.NetworkPolicy.BlockQuickQuic = model.BlockQuickQuic.ValueString()
	}
	
	if !model.ScanVirus.IsNull() {
		rule.NetworkPolicy.ScanVirus = model.ScanVirus.ValueString()
	}
	
	if !model.ZeroDayProtection.IsNull() {
		rule.NetworkPolicy.ZeroDayProtection = model.ZeroDayProtection.ValueString()
	}
	
	if !model.ProxyMode.IsNull() {
		rule.NetworkPolicy.ProxyMode = model.ProxyMode.ValueString()
	}
	
	if !model.DecryptHTTPS.IsNull() {
		rule.NetworkPolicy.DecryptHTTPS = model.DecryptHTTPS.ValueString()
	}
	
	if !model.ApplicationControl.IsNull() {
		rule.NetworkPolicy.ApplicationControl = model.ApplicationControl.ValueString()
	}
	
	if !model.ApplicationBaseQoSPolicy.IsNull() {
		rule.NetworkPolicy.ApplicationBaseQoSPolicy = model.ApplicationBaseQoSPolicy.ValueString()
	}
	
	if !model.IntrusionPrevention.IsNull() {
		rule.NetworkPolicy.IntrusionPrevention = model.IntrusionPrevention.ValueString()
	}
	
	if !model.TrafficShappingPolicy.IsNull() {
		rule.NetworkPolicy.TrafficShappingPolicy = model.TrafficShappingPolicy.ValueString()
	}
	
	if !model.ScanSMTP.IsNull() {
		rule.NetworkPolicy.ScanSMTP = model.ScanSMTP.ValueString()
	}
	
	if !model.ScanSMTPS.IsNull() {
		rule.NetworkPolicy.ScanSMTPS = model.ScanSMTPS.ValueString()
	}
	
	if !model.ScanIMAP.IsNull() {
		rule.NetworkPolicy.ScanIMAP = model.ScanIMAP.ValueString()
	}
	
	if !model.ScanIMAPS.IsNull() {
		rule.NetworkPolicy.ScanIMAPS = model.ScanIMAPS.ValueString()
	}
	
	if !model.ScanPOP3.IsNull() {
		rule.NetworkPolicy.ScanPOP3 = model.ScanPOP3.ValueString()
	}
	
	if !model.ScanPOP3S.IsNull() {
		rule.NetworkPolicy.ScanPOP3S = model.ScanPOP3S.ValueString()
	}
	
	if !model.ScanFTP.IsNull() {
		rule.NetworkPolicy.ScanFTP = model.ScanFTP.ValueString()
	}
	
	if !model.SourceSecurityHeartbeat.IsNull() {
		rule.NetworkPolicy.SourceSecurityHeartbeat = model.SourceSecurityHeartbeat.ValueString()
	}
	
	if !model.MinimumSourceHBPermitted.IsNull() {
		rule.NetworkPolicy.MinimumSourceHBPermitted = model.MinimumSourceHBPermitted.ValueString()
	}
	
	if !model.DestSecurityHeartbeat.IsNull() {
		rule.NetworkPolicy.DestSecurityHeartbeat = model.DestSecurityHeartbeat.ValueString()
	}
	
	if !model.MinimumDestinationHBPermitted.IsNull() {
		rule.NetworkPolicy.MinimumDestinationHBPermitted = model.MinimumDestinationHBPermitted.ValueString()
	}

	// Source Zones
	if len(model.SourceZones) > 0 {
		rule.NetworkPolicy.SourceZones = &firewallrule.ZoneList{
			Zones: make([]string, 0, len(model.SourceZones)),
		}
		for _, zone := range model.SourceZones {
			rule.NetworkPolicy.SourceZones.Zones = append(rule.NetworkPolicy.SourceZones.Zones, zone.ValueString())
		}
	}

	// Destination Zones
	if len(model.DestinationZones) > 0 {
		rule.NetworkPolicy.DestinationZones = &firewallrule.ZoneList{
			Zones: make([]string, 0, len(model.DestinationZones)),
		}
		for _, zone := range model.DestinationZones {
			rule.NetworkPolicy.DestinationZones.Zones = append(rule.NetworkPolicy.DestinationZones.Zones, zone.ValueString())
		}
	}

	// Source Networks
	if len(model.SourceNetworks) > 0 {
		rule.NetworkPolicy.SourceNetworks = &firewallrule.NetworkList{
			Networks: make([]string, 0, len(model.SourceNetworks)),
		}
		for _, network := range model.SourceNetworks {
			rule.NetworkPolicy.SourceNetworks.Networks = append(rule.NetworkPolicy.SourceNetworks.Networks, network.ValueString())
		}
	}

	// Destination Networks
	if len(model.DestinationNetworks) > 0 {
		rule.NetworkPolicy.DestinationNetworks = &firewallrule.NetworkList{
			Networks: make([]string, 0, len(model.DestinationNetworks)),
		}
		for _, network := range model.DestinationNetworks {
			rule.NetworkPolicy.DestinationNetworks.Networks = append(rule.NetworkPolicy.DestinationNetworks.Networks, network.ValueString())
		}
	}

	return rule
}

// Helper method to convert from API structure to Terraform model
func (r *firewallRuleResource) apiToModelFirewallRule(rule firewallrule.FirewallRule) firewallRuleResourceModel {
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
    } else {
        model.AfterRule = types.StringNull()
    }

    if rule.Before != nil {
        model.BeforeRule = types.StringValue(rule.Before.Name)
    } else {
        model.BeforeRule = types.StringNull()
    }

    // Set network policy attributes
    if rule.NetworkPolicy != nil {
        model.Action = types.StringValue(rule.NetworkPolicy.Action)
        model.LogTraffic = types.StringValue(rule.NetworkPolicy.LogTraffic)
        model.SkipLocalDestined = types.StringValue(rule.NetworkPolicy.SkipLocalDestined)
        model.Schedule = types.StringValue(rule.NetworkPolicy.Schedule)

        // Map all additional fields from NetworkPolicy
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
        model.TrafficShappingPolicy = types.StringValue(rule.NetworkPolicy.TrafficShappingPolicy) // Corrected typo: TrafficShapingPolicy
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

        // Source Zones
        if rule.NetworkPolicy.SourceZones != nil {
            model.SourceZones = make([]types.String, 0, len(rule.NetworkPolicy.SourceZones.Zones))
            for _, zone := range rule.NetworkPolicy.SourceZones.Zones {
                model.SourceZones = append(model.SourceZones, types.StringValue(zone))
            }
        } else {
            model.SourceZones = nil // Or []types.String{} depending on desired null/empty representation
        }

        // Destination Zones
        if rule.NetworkPolicy.DestinationZones != nil {
            model.DestinationZones = make([]types.String, 0, len(rule.NetworkPolicy.DestinationZones.Zones))
            for _, zone := range rule.NetworkPolicy.DestinationZones.Zones {
                model.DestinationZones = append(model.DestinationZones, types.StringValue(zone))
            }
        } else {
            model.DestinationZones = nil
        }

        // Source Networks
        if rule.NetworkPolicy.SourceNetworks != nil {
            model.SourceNetworks = make([]types.String, 0, len(rule.NetworkPolicy.SourceNetworks.Networks))
            for _, network := range rule.NetworkPolicy.SourceNetworks.Networks {
                model.SourceNetworks = append(model.SourceNetworks, types.StringValue(network))
            }
        } else {
            model.SourceNetworks = nil
        }

        // Destination Networks
        if rule.NetworkPolicy.DestinationNetworks != nil {
            model.DestinationNetworks = make([]types.String, 0, len(rule.NetworkPolicy.DestinationNetworks.Networks))
            for _, network := range rule.NetworkPolicy.DestinationNetworks.Networks {
                model.DestinationNetworks = append(model.DestinationNetworks, types.StringValue(network))
            }
        } else {
            model.DestinationNetworks = nil
        }

    } else {
        // Handle case where NetworkPolicy is nil (e.g., set defaults or nulls)
        model.Action = types.StringNull()
        model.LogTraffic = types.StringNull() // Or default value like types.StringValue("Disable")
        model.SkipLocalDestined = types.StringNull() // Or default
        model.Schedule = types.StringNull() // Or default like types.StringValue("AllTheTime")
        model.DSCPMarking = types.StringNull()
        model.WebFilter = types.StringNull() // Or default like types.StringValue("None")
        model.WebCategoryBaseQoSPolicy = types.StringNull() // Or default
        model.BlockQuickQuic = types.StringNull() // Or default
        model.ScanVirus = types.StringNull() // Or default
        model.ZeroDayProtection = types.StringNull() // Or default
        model.ProxyMode = types.StringNull() // Or default
        model.DecryptHTTPS = types.StringNull() // Or default
        model.ApplicationControl = types.StringNull() // Or default
        model.ApplicationBaseQoSPolicy = types.StringNull() // Or default
        model.IntrusionPrevention = types.StringNull() // Or default
        model.TrafficShappingPolicy = types.StringNull() // Or default
        model.ScanSMTP = types.StringNull() // Or default
        model.ScanSMTPS = types.StringNull() // Or default
        model.ScanIMAP = types.StringNull() // Or default
        model.ScanIMAPS = types.StringNull() // Or default
        model.ScanPOP3 = types.StringNull() // Or default
        model.ScanPOP3S = types.StringNull() // Or default
        model.ScanFTP = types.StringNull() // Or default
        model.SourceSecurityHeartbeat = types.StringNull() // Or default
        model.MinimumSourceHBPermitted = types.StringNull() // Or default
        model.DestSecurityHeartbeat = types.StringNull() // Or default
        model.MinimumDestinationHBPermitted = types.StringNull() // Or default
        model.SourceZones = nil
        model.DestinationZones = nil
        model.SourceNetworks = nil
        model.DestinationNetworks = nil
    }

    return model
}