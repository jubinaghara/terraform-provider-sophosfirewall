package dns_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/acctest"
)

const hostEntriesPath = "/network/dns/host-entries"

func TestDNSHostEntry(t *testing.T) {
	env := acctest.New(t)
	const addr = "sophosfirewall_dns_host_entry.intranet"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_dns_host_entry" "intranet" {
  name   = "intranet"
  domain = "intranet.example.com"
  addresses = [
    { ipv4_address = "192.0.2.10" },
    { ipv6_address = "2001:db8::10", ttl = 60, weight = 100, publish_on_wan = true },
  ]
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(addr, "id"),
					resource.TestCheckResourceAttr(addr, "enable_reverse_resolution", "false"),
					resource.TestCheckResourceAttr(addr, "addresses.#", "2"),
					resource.TestCheckResourceAttr(addr, "addresses.0.ttl", "3600"),
					resource.TestCheckResourceAttr(addr, "addresses.0.weight", "1"),
					resource.TestCheckResourceAttr(addr, "addresses.0.publish_on_wan", "false"),
					resource.TestCheckResourceAttr(addr, "addresses.1.ttl", "60"),
					resource.TestCheckNoResourceAttr(addr, "addresses.1.ipv4_address"),
					func(*terraform.State) error {
						o := env.Server.Get(hostEntriesPath, "intranet")
						entries, _ := o["hostEntries"].([]any)
						if len(entries) != 2 {
							return fmt.Errorf("hostEntries on server = %v", o["hostEntries"])
						}
						first := entries[0].(map[string]any)
						if fmt.Sprint(first["ipv4"]) != "map[ipv4Address:192.0.2.10]" || first["publishOnWan"] != false || first["ttl"] != float64(3600) {
							return fmt.Errorf("first host entry on server = %v", first)
						}
						return nil
					},
				),
			},
			{
				// Rename and switch answers to interface addresses in place.
				Config: env.Config(`
resource "sophosfirewall_dns_host_entry" "intranet" {
  name                      = "intranet-portal"
  domain                    = "intranet.example.com"
  enable_reverse_resolution = true
  addresses = [
    { ipv4_interface = "Port1", weight = 10 },
    { ipv6_interface = "Port2" },
  ]
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "name", "intranet-portal"),
					resource.TestCheckResourceAttr(addr, "enable_reverse_resolution", "true"),
					resource.TestCheckResourceAttr(addr, "addresses.0.ipv4_interface", "Port1"),
					resource.TestCheckNoResourceAttr(addr, "addresses.0.ipv4_address"),
					resource.TestCheckResourceAttr(addr, "addresses.1.ipv6_interface", "Port2"),
					resource.TestCheckResourceAttr(addr, "addresses.1.ttl", "3600"),
				),
			},
			{ResourceName: addr, ImportState: true, ImportStateVerify: true},
			{ResourceName: addr, ImportState: true, ImportStateId: "intranet-portal", ImportStateVerify: true},
			{
				// The domain is read-only after creation.
				Config: env.Config(`
resource "sophosfirewall_dns_host_entry" "intranet" {
  name      = "intranet-portal"
  domain    = "portal.example.com"
  addresses = [{ ipv4_address = "192.0.2.20" }]
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionDestroyBeforeCreate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "domain", "portal.example.com"),
					resource.TestCheckResourceAttr(addr, "enable_reverse_resolution", "false"),
				),
			},
		},
	})
}

func TestDNSHostEntryDataSource(t *testing.T) {
	env := acctest.New(t)
	env.Server.Seed(hostEntriesPath, map[string]any{
		"name": "mail", "domain": "mail.example.com", "enableReverseResolution": true,
		"hostEntries": []any{
			map[string]any{"ttl": 60, "weight": 100, "publishOnWan": false, "ipv4": map[string]any{"ipv4Address": "192.0.2.25"}},
			map[string]any{"ttl": 45, "weight": 70, "publishOnWan": true, "ipv4": map[string]any{"ipv4Interface": map[string]any{"name": "Port1"}}},
		},
	})
	const ds = "data.sophosfirewall_dns_host_entry.mail"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{{
			Config: env.Config(`data "sophosfirewall_dns_host_entry" "mail" { name = "mail" }`),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet(ds, "id"),
				resource.TestCheckResourceAttr(ds, "domain", "mail.example.com"),
				resource.TestCheckResourceAttr(ds, "enable_reverse_resolution", "true"),
				resource.TestCheckResourceAttr(ds, "addresses.#", "2"),
				resource.TestCheckResourceAttr(ds, "addresses.0.ipv4_address", "192.0.2.25"),
				resource.TestCheckResourceAttr(ds, "addresses.1.ipv4_interface", "Port1"),
				resource.TestCheckResourceAttr(ds, "addresses.1.publish_on_wan", "true"),
			),
		}},
	})
}

func TestDNSHostEntryValidation(t *testing.T) {
	env := acctest.New(t)
	cfg := func(domain, addresses string) string {
		return env.Config(fmt.Sprintf(`
resource "sophosfirewall_dns_host_entry" "t" {
  name      = "t"
  domain    = %q
  addresses = %s
}`, domain, addresses))
	}
	steps := []struct{ domain, addresses, err string }{
		{"host.example.com", `[{ ttl = 60 }]`, `Exactly one of ipv4_address, ipv4_interface, ipv6_address, ipv6_interface\s+must be set, got 0`},
		{"host.example.com", `[{ ipv4_address = "192.0.2.1", ipv6_address = "2001:db8::1" }]`, `got 2`},
		{"host.example.com", `[{ ipv4_address = "2001:db8::1" }]`, `not a valid IPv4 address`},
		{"host.example.com", `[{ ipv6_address = "2001:DB8::1" }]`, `canonical form`},
		{"host.example.com", `[{ ipv4_address = "192.0.2.1", ttl = 0 }]`, `between 1 and 604800`},
		{"host.example.com", `[{ ipv4_address = "192.0.2.1", weight = 256 }]`, `between 1 and 255`},
		{"host.example.com", `[]`, `at least 1`},
		{"host.example.com", `[` + nineAddresses() + `]`, `at most 8`},
		{"http://host.example.com", `[{ ipv4_address = "192.0.2.1" }]`, `must be a host name`},
	}
	var ts []resource.TestStep
	for _, s := range steps {
		ts = append(ts, resource.TestStep{Config: cfg(s.domain, s.addresses), ExpectError: regexp.MustCompile(s.err), PlanOnly: true})
	}
	resource.UnitTest(t, resource.TestCase{ProtoV6ProviderFactories: env.Factories, Steps: ts})
}

func nineAddresses() string {
	s := ""
	for i := 1; i <= 9; i++ {
		s += fmt.Sprintf(`{ ipv4_address = "192.0.2.%d" },`, i)
	}
	return s
}
