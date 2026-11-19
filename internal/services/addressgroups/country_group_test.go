package addressgroups_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/acctest"
)

func TestCountryGroup(t *testing.T) {
	env := acctest.New(t)
	const addr = "sophosfirewall_country_group.blocked"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_country_group" "blocked" {
  name      = "blocked-countries"
  countries = ["North Korea", "Iran"]
}`),
				Check: resource.TestCheckResourceAttr(addr, "countries.#", "2"),
			},
			{
				// Removing all countries sends an empty list.
				Config: env.Config(`
resource "sophosfirewall_country_group" "blocked" {
  name        = "blocked-countries"
  description = "Empty for now"
}`),
				Check: resource.TestCheckNoResourceAttr(addr, "countries"),
			},
			{ResourceName: addr, ImportState: true, ImportStateVerify: true},
		},
	})
}
