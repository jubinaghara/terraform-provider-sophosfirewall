package zones_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/acctest"
)

func TestZone(t *testing.T) {
	env := acctest.New(t)
	const addr = "sophosfirewall_zone.guest"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_zone" "guest" {
  name        = "GuestWiFi"
  type        = "lan"
  description = "Guest wireless users"
  services    = ["ping", "dns"]
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "services.#", "2"),
					resource.TestCheckResourceAttr(addr, "type", "lan"),
				),
			},
			{
				Config: env.Config(`
resource "sophosfirewall_zone" "guest" {
  name     = "GuestWiFi"
  type     = "lan"
  services = ["ping"]
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "services.#", "1"),
					resource.TestCheckResourceAttr(addr, "description", ""),
				),
			},
			{
				// The type cannot be patched, so changing it recreates the zone.
				Config: env.Config(`
resource "sophosfirewall_zone" "guest" {
  name = "GuestWiFi"
  type = "dmz"
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionDestroyBeforeCreate)},
				},
				Check: resource.TestCheckNoResourceAttr(addr, "services"),
			},
			{ResourceName: addr, ImportState: true, ImportStateVerify: true},
		},
	})
}

func TestZoneDataSourceBuiltIn(t *testing.T) {
	env := acctest.New(t)
	env.Server.Seed("/network/zones", map[string]any{
		"name": "LAN", "type": "lan", "services": []any{map[string]any{"name": "https"}, map[string]any{"name": "ssh"}},
	})
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{{
			Config: env.Config(`data "sophosfirewall_zone" "lan" { name = "LAN" }`),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("data.sophosfirewall_zone.lan", "type", "lan"),
				resource.TestCheckResourceAttr("data.sophosfirewall_zone.lan", "services.#", "2"),
				resource.TestCheckResourceAttrSet("data.sophosfirewall_zone.lan", "id"),
			),
		}},
	})
}
