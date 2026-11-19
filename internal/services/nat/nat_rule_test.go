package nat_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/acctest"
)

func TestNATRuleMasquerade(t *testing.T) {
	env := acctest.New(t)
	const addr = "sophosfirewall_nat_rule.masq"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_nat_rule" "masq" {
  name                = "outbound-masq"
  outbound_interfaces = ["Port2"]
  original_source_networks = {
    ipv4_groups = ["lan-subnets"]
  }
  translated_source = { masquerade = true }
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "translated_source.masquerade", "true"),
					resource.TestCheckNoResourceAttr(addr, "inbound_interfaces"),
					resource.TestCheckNoResourceAttr(addr, "linked_firewall_rule"),
					resource.TestCheckResourceAttr(addr, "load_balancing_method", "roundRobin"),
				),
			},
			{
				// Switch from MASQ to a specific address object.
				Config: env.Config(`
resource "sophosfirewall_nat_rule" "masq" {
  name                = "outbound-masq"
  outbound_interfaces = ["Port2"]
  original_source_networks = {
    ipv4_groups = ["lan-subnets"]
  }
  translated_source = { ipv4_address = "public-ip" }
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "translated_source.ipv4_address", "public-ip"),
					func(*terraform.State) error {
						ts := env.Server.Get("/nat/rules/ipv4", "outbound-masq")["translatedSource"].(map[string]any)
						if _, masq := ts["masq"]; masq || len(ts) != 1 {
							return fmt.Errorf("translatedSource = %v, want only ipv4Address", ts)
						}
						return nil
					},
				),
			},
			{ResourceName: addr, ImportState: true, ImportStateVerify: true},
		},
	})
}

func TestNATRulePortForward(t *testing.T) {
	env := acctest.New(t)
	const addr = "sophosfirewall_nat_rule.dnat"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_nat_rule" "dnat" {
  name               = "web-port-forward"
  position           = "top"
  inbound_interfaces = ["Port2"]
  original_destination_networks = {
    ipv4_addresses = ["wan-ip"]
  }
  original_services      = ["HTTPS"]
  translated_destination = { ipv4_address = "web-server" }
  translated_service     = "HTTPS-8443"

  source_nat_overrides = [{
    interface         = "Port3"
    translated_source = { masquerade = true }
  }]
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "translated_destination.ipv4_address", "web-server"),
					resource.TestCheckResourceAttr(addr, "source_nat_overrides.#", "1"),
					resource.TestCheckResourceAttr(addr, "position", "top"),
				),
			},
			{
				ResourceName: addr, ImportState: true, ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{"position"},
			},
		},
	})
}
