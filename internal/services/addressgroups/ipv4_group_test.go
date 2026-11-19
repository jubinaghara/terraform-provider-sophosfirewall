package addressgroups_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/acctest"
)

func TestIPv4GroupAndDataSource(t *testing.T) {
	env := acctest.New(t)
	const addr = "sophosfirewall_ipv4_group.test"
	const hosts = `
resource "sophosfirewall_ipv4_address" "a" {
  name       = "web-01"
  ip_address = "203.0.113.10"
}
resource "sophosfirewall_ipv4_address" "b" {
  name       = "web-02"
  ip_address = "203.0.113.11"
}
resource "sophosfirewall_ipv4_address" "c" {
  name       = "web-03"
  ip_address = "203.0.113.12"
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(hosts + `
resource "sophosfirewall_ipv4_group" "test" {
  name      = "web-servers"
  addresses = [sophosfirewall_ipv4_address.a.name, sophosfirewall_ipv4_address.b.name]
}
data "sophosfirewall_ipv4_group" "test" {
  name = sophosfirewall_ipv4_group.test.name
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(addr, "id"),
					resource.TestCheckResourceAttr(addr, "description", ""),
					resource.TestCheckResourceAttr(addr, "addresses.#", "2"),
					resource.TestCheckTypeSetElemAttr(addr, "addresses.*", "web-01"),
					resource.TestCheckTypeSetElemAttr(addr, "addresses.*", "web-02"),
					resource.TestCheckResourceAttrPair("data.sophosfirewall_ipv4_group.test", "id", addr, "id"),
					resource.TestCheckResourceAttr("data.sophosfirewall_ipv4_group.test", "addresses.#", "2"),
				),
			},
			{
				// Membership, description and name all change in place.
				Config: env.Config(hosts + `
resource "sophosfirewall_ipv4_group" "test" {
  name        = "web-servers-dmz"
  description = "DMZ web servers"
  addresses   = [sophosfirewall_ipv4_address.c.name, sophosfirewall_ipv4_address.b.name]
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "name", "web-servers-dmz"),
					resource.TestCheckResourceAttr(addr, "description", "DMZ web servers"),
					resource.TestCheckResourceAttr(addr, "addresses.#", "2"),
					resource.TestCheckTypeSetElemAttr(addr, "addresses.*", "web-02"),
					resource.TestCheckTypeSetElemAttr(addr, "addresses.*", "web-03"),
				),
			},
			{ResourceName: addr, ImportState: true, ImportStateVerify: true},
			{
				// Removing every member sends an empty list.
				Config: env.Config(hosts + `
resource "sophosfirewall_ipv4_group" "test" {
  name = "web-servers-dmz"
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr(addr, "addresses"),
					resource.TestCheckResourceAttr(addr, "description", ""),
					func(*terraform.State) error {
						got := env.Server.Get("/network/address-groups/ipv4", "web-servers-dmz")
						if members, ok := got["ipv4Addresses"].([]any); !ok || len(members) != 0 {
							return fmt.Errorf("ipv4Addresses = %#v, want []", got["ipv4Addresses"])
						}
						return nil
					},
				),
			},
		},
	})
}
