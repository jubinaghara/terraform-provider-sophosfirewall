package addressgroups_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/acctest"
)

func TestFQDNGroupAndDataSource(t *testing.T) {
	env := acctest.New(t)
	const addr = "sophosfirewall_fqdn_group.test"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				// An FQDN group may be created without members.
				Config: env.Config(`
resource "sophosfirewall_fqdn_group" "test" {
  name = "saas"
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(addr, "id"),
					resource.TestCheckNoResourceAttr(addr, "addresses"),
				),
			},
			{
				Config: env.Config(`
resource "sophosfirewall_fqdn_address" "a" {
  name = "office365"
  fqdn = "*.office365.com"
}
resource "sophosfirewall_fqdn_group" "test" {
  name      = "saas"
  addresses = [sophosfirewall_fqdn_address.a.name, "salesforce"]
}
data "sophosfirewall_fqdn_group" "test" {
  name = sophosfirewall_fqdn_group.test.name
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "addresses.#", "2"),
					resource.TestCheckTypeSetElemAttr(addr, "addresses.*", "office365"),
					resource.TestCheckResourceAttrPair("data.sophosfirewall_fqdn_group.test", "id", addr, "id"),
					resource.TestCheckResourceAttr("data.sophosfirewall_fqdn_group.test", "addresses.#", "2"),
				),
			},
			{ResourceName: addr, ImportState: true, ImportStateVerify: true},
		},
	})
}

// Groups on real firewalls hold thousands of members; membership is a set,
// so reordering is not a change and large lists round-trip intact.
//
// Set handling in Terraform core and terraform-plugin-framework is quadratic
// in the number of elements (1,000 members take ~50s here, 3,000 ~8 minutes),
// so the test stays at 1,000 members. The provider itself adds only linear work.
func TestHostGroupLargeMembership(t *testing.T) {
	env := acctest.New(t)
	const addr = "sophosfirewall_ipv4_group.big"
	// range() is capped at 1024 values.
	const hosts = `
locals {
  hosts = [for i in range(1000) : format("host-%04d", i)]
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(hosts + `
resource "sophosfirewall_ipv4_group" "big" {
  name      = "big"
  addresses = local.hosts
}`),
				Check: resource.TestCheckResourceAttr(addr, "addresses.#", "1000"),
			},
			{
				// Same members in reverse order: no diff.
				Config: env.Config(hosts + `
resource "sophosfirewall_ipv4_group" "big" {
  name      = "big"
  addresses = reverse(local.hosts)
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				// Drop one member, add another.
				Config: env.Config(hosts + `
resource "sophosfirewall_ipv4_group" "big" {
  name      = "big"
  addresses = setunion(setsubtract(local.hosts, ["host-0000"]), ["host-9999"])
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "addresses.#", "1000"),
					resource.TestCheckTypeSetElemAttr(addr, "addresses.*", "host-9999"),
				),
			},
		},
	})
}
