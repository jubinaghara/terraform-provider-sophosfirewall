package provider

import (
    "github.com/jubinaghara/terraform-provider-sophosfirewall/internal/common"
    "github.com/jubinaghara/terraform-provider-sophosfirewall/internal/iphost"
    "github.com/jubinaghara/terraform-provider-sophosfirewall/internal/machost"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/firewallrule"
)

// SophosClient handles communication with the Sophos XML API
type SophosClient struct {
	*common.BaseClient
	IPHost      *iphost.Client
	MACHost     *machost.Client
	FirewallRule *firewallrule.Client
}

// NewSophosClient creates a new API client
func NewSophosClient(endpoint, username, password string, insecure bool) *SophosClient {
	// Create the base client
	baseClient := common.NewBaseClient(endpoint, username, password, insecure)
	
	// Create the main client
	client := &SophosClient{
		BaseClient: baseClient,
	}
	
	// Initialize specialized clients
	client.IPHost = iphost.NewClient(baseClient)
	client.MACHost = machost.NewClient(baseClient)
	client.FirewallRule = firewallrule.NewClient(baseClient)
	
	return client
}