package provider

import (
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/services/addresses"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/services/addressgroups"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/services/firewall"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/services/interfaces"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/services/nat"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/services/zones"
)

// registry lists every object type exposed by the provider. Each entry
// yields a resource and, unless disabled, a data source of the same name.
//
// To add a new object type, describe it with a framework.Resource in the
// matching package under internal/services and append it here.
var registry = []framework.Registration{
	// Objects > Hosts and services
	addresses.IPv4Address,
	addresses.IPv6Address,
	addresses.MACAddress,
	addresses.FQDNAddress,
	addressgroups.CountryGroup,

	// Configure > Network
	zones.Zone,
	interfaces.Interface,
	interfaces.PhysicalInterface,

	// Protect > Rules and policies
	firewall.RuleIPv4,
	nat.RuleIPv4,
}
