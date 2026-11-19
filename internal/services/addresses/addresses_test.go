package addresses_test

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/acctest"
)

func TestIPv4Address(t *testing.T) {
	env := acctest.New(t)
	const addr = "sophosfirewall_ipv4_address.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_ipv4_address" "test" {
  name       = "web-server"
  ip_address = "203.0.113.10"
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(addr, "id"),
					resource.TestCheckResourceAttr(addr, "ip_address", "203.0.113.10"),
					resource.TestCheckResourceAttr(addr, "description", ""),
				),
			},
			{
				// In-place update of the address and description.
				Config: env.Config(`
resource "sophosfirewall_ipv4_address" "test" {
  name        = "web-server"
  description = "Web server"
  ip_address  = "203.0.113.11"
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)},
				},
				Check: resource.TestCheckResourceAttr(addr, "ip_address", "203.0.113.11"),
			},
			{
				// Changing the kind of address recreates the object.
				Config: env.Config(`
resource "sophosfirewall_ipv4_address" "test" {
  name    = "web-server"
  network = "192.0.2.0/24"
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionDestroyBeforeCreate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "network", "192.0.2.0/24"),
					resource.TestCheckNoResourceAttr(addr, "ip_address"),
				),
			},
			{ResourceName: addr, ImportState: true, ImportStateVerify: true},
			{
				// Import by name works as well.
				ResourceName: addr, ImportState: true, ImportStateId: "web-server", ImportStateVerify: true,
			},
		},
	})
}

func TestIPv4AddressRangeAndList(t *testing.T) {
	env := acctest.New(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_ipv4_address" "range" {
  name        = "dhcp-pool"
  range_start = "192.0.2.100"
  range_end   = "192.0.2.200"
}
resource "sophosfirewall_ipv4_address" "list" {
  name         = "dns-servers"
  ip_addresses = ["192.0.2.53", "198.51.100.53"]
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("sophosfirewall_ipv4_address.range", "range_end", "192.0.2.200"),
					resource.TestCheckResourceAttr("sophosfirewall_ipv4_address.list", "ip_addresses.#", "2"),
				),
			},
			{ResourceName: "sophosfirewall_ipv4_address.list", ImportState: true, ImportStateVerify: true},
		},
	})
}

func TestIPv4AddressValidation(t *testing.T) {
	env := acctest.New(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config:      env.Config(`resource "sophosfirewall_ipv4_address" "t" { name = "x" }`),
				ExpectError: regexp.MustCompile(`one \(and only one\) of\s+\[network,range_start,ip_addresses\]`),
			},
			{
				Config: env.Config(`
resource "sophosfirewall_ipv4_address" "t" {
  name    = "x"
  network = "192.0.2.5/24"
}`),
				ExpectError: regexp.MustCompile(`canonical network address "192.0.2.0/24"`),
			},
			{
				Config: env.Config(`
resource "sophosfirewall_ipv4_address" "t" {
  name       = "a,b"
  ip_address = "192.0.2.1"
}`),
				ExpectError: regexp.MustCompile(`not a valid SFOS object name`),
			},
		},
	})
}

func TestIPv6Address(t *testing.T) {
	env := acctest.New(t)
	const addr = "sophosfirewall_ipv6_address.test"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_ipv6_address" "test" {
  name    = "corp-v6"
  network = "2001:db8:10::/64"
}`),
				Check: resource.TestCheckResourceAttr(addr, "network", "2001:db8:10::/64"),
			},
			{ResourceName: addr, ImportState: true, ImportStateVerify: true},
		},
	})
	if got := env.Server.Get("/network/addresses/ipv6", "corp-v6"); got != nil {
		t.Fatalf("object not deleted after destroy: %v", got)
	}
}

func TestMACAddress(t *testing.T) {
	env := acctest.New(t)
	const addr = "sophosfirewall_mac_address.test"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_mac_address" "test" {
  name        = "printer"
  mac_address = "00:1a:2b:3c:4d:5e"
}`),
				Check: resource.TestCheckResourceAttr(addr, "mac_address", "00:1a:2b:3c:4d:5e"),
			},
			{
				Config: env.Config(`
resource "sophosfirewall_mac_address" "test" {
  name          = "printer"
  mac_addresses = ["00:1a:2b:3c:4d:5e", "00:1a:2b:3c:4d:5f"]
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionDestroyBeforeCreate)},
				},
				Check: resource.TestCheckResourceAttr(addr, "mac_addresses.#", "2"),
			},
			{ResourceName: addr, ImportState: true, ImportStateVerify: true},
		},
	})
}

func TestFQDNAddressAndDataSource(t *testing.T) {
	env := acctest.New(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_fqdn_address" "test" {
  name        = "sophos"
  description = "Sophos website"
  fqdn        = "www.sophos.com"
}
data "sophosfirewall_fqdn_address" "test" {
  name = sophosfirewall_fqdn_address.test.name
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("sophosfirewall_fqdn_address.test", "fqdn", "www.sophos.com"),
					resource.TestCheckResourceAttrPair("data.sophosfirewall_fqdn_address.test", "id", "sophosfirewall_fqdn_address.test", "id"),
					resource.TestCheckResourceAttr("data.sophosfirewall_fqdn_address.test", "description", "Sophos website"),
				),
			},
			{
				Config: env.Config(`
resource "sophosfirewall_fqdn_address" "test" {
  name = "sophos"
  fqdn = "*.sophos.com"
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("sophosfirewall_fqdn_address.test", "fqdn", "*.sophos.com"),
					resource.TestCheckResourceAttr("sophosfirewall_fqdn_address.test", "description", ""),
				),
			},
		},
	})
}
