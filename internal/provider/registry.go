package provider

import (
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/services/addresses"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/services/addressgroups"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/services/administration"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/services/authentication"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/services/dhcp"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/services/dns"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/services/firewall"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/services/interfaces"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/services/nat"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/services/routing"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/services/servicesobj"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/services/web"
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
	addressgroups.IPv4Group,
	addressgroups.IPv6Group,
	addressgroups.FQDNGroup,
	servicesobj.Service,
	servicesobj.ServiceGroup,

	// Configure > Network
	zones.Zone,
	interfaces.Interface,
	interfaces.PhysicalInterface,

	// Protect > Rules and policies
	firewall.RuleIPv4,
	nat.RuleIPv4,

	// Configure > Network > DHCP
	dhcp.Server,

	// Configure > Authentication
	authentication.UserGroup,

	// Configure > Routing
	routing.StaticRouteIPv4,
	routing.GatewayIPv4,
	routing.SDWANRouteIPv4,

	// Configure > Network > DNS
	dns.HostEntry,

	// Protect > Web
	web.URLGroup,

	// System > Profiles
	administration.Schedule,
}
