package addressgroups_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/acctest"
)

func TestIPv6GroupAndDataSource(t *testing.T) {
	env := acctest.New(t)
	const addr = "sophosfirewall_ipv6_group.test"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_ipv6_address" "a" {
  name       = "dc-v6-01"
  ip_address = "2001:db8::10"
}
resource "sophosfirewall_ipv6_group" "test" {
  name        = "dc-v6"
  description = "Datacenter IPv6 hosts"
  addresses   = [sophosfirewall_ipv6_address.a.name, "dc-v6-02"]
}
data "sophosfirewall_ipv6_group" "test" {
  name = sophosfirewall_ipv6_group.test.name
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "addresses.#", "2"),
					resource.TestCheckResourceAttrPair("data.sophosfirewall_ipv6_group.test", "id", addr, "id"),
					resource.TestCheckResourceAttr("data.sophosfirewall_ipv6_group.test", "description", "Datacenter IPv6 hosts"),
					resource.TestCheckTypeSetElemAttr("data.sophosfirewall_ipv6_group.test", "addresses.*", "dc-v6-02"),
				),
			},
			{
				Config: env.Config(`
resource "sophosfirewall_ipv6_address" "a" {
  name       = "dc-v6-01"
  ip_address = "2001:db8::10"
}
resource "sophosfirewall_ipv6_group" "test" {
  name      = "dc-v6"
  addresses = ["dc-v6-03"]
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "description", ""),
					resource.TestCheckResourceAttr(addr, "addresses.#", "1"),
					resource.TestCheckTypeSetElemAttr(addr, "addresses.*", "dc-v6-03"),
				),
			},
			{ResourceName: addr, ImportState: true, ImportStateVerify: true},
		},
	})
}
