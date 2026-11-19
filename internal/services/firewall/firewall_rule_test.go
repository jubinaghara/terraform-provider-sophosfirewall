package firewall_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/acctest"
)

const rulesPath = "/firewall/rules/ipv4"

func TestFirewallRule(t *testing.T) {
	env := acctest.New(t)
	const addr = "sophosfirewall_firewall_rule.web"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_ipv4_address" "web" {
  name       = "web-server"
  ip_address = "203.0.113.10"
}

resource "sophosfirewall_firewall_rule" "web" {
  name              = "allow-web"
  source_zones      = ["LAN"]
  destination_zones = ["WAN"]
  destination_networks = {
    ipv4_addresses = [sophosfirewall_ipv4_address.web.name]
  }
  services    = ["HTTP", "HTTPS"]
  log_traffic = true

  security_features = {
    scan_http_and_decrypted_https = true
    zero_day_protection           = true
  }
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "action", "accept"),
					resource.TestCheckResourceAttr(addr, "enabled", "true"),
					resource.TestCheckResourceAttr(addr, "destination_networks.ipv4_addresses.#", "1"),
					resource.TestCheckNoResourceAttr(addr, "source_networks"),
					resource.TestCheckResourceAttr(addr, "security_features.zero_day_protection", "true"),
					// Server-side defaults for blocks we did not configure stay out of state.
					resource.TestCheckNoResourceAttr(addr, "email_scanning"),
					resource.TestCheckNoResourceAttr(addr, "synchronized_security_heartbeat"),
					resource.TestCheckNoResourceAttr(addr, "user_authentication"),
					checkStored(env, "allow-web", func(o map[string]any) error {
						if o["ruleType"] != "firewall" {
							return fmt.Errorf("ruleType = %v", o["ruleType"])
						}
						if sn := o["sourceNetworks"].(map[string]any); sn["any"] != true {
							return fmt.Errorf("sourceNetworks = %v, want any", sn)
						}
						return nil
					}),
				),
			},
			{
				// Switch destination to "any", drop a service, change the action.
				Config: env.Config(`
resource "sophosfirewall_ipv4_address" "web" {
  name       = "web-server"
  ip_address = "203.0.113.10"
}

resource "sophosfirewall_firewall_rule" "web" {
  name              = "allow-web"
  description       = "Web access"
  source_zones      = ["LAN"]
  destination_zones = ["WAN"]
  services          = ["HTTPS"]
  action            = "drop"
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr(addr, "destination_networks"),
					resource.TestCheckResourceAttr(addr, "services.#", "1"),
					resource.TestCheckResourceAttr(addr, "action", "drop"),
					resource.TestCheckNoResourceAttr(addr, "security_features"),
					checkStored(env, "allow-web", func(o map[string]any) error {
						if dn := o["destinationNetworks"].(map[string]any); dn["any"] != true || len(dn) != 1 {
							return fmt.Errorf("destinationNetworks = %v, want only any", dn)
						}
						if _, ok := o["securityFeatures"]; ok {
							return fmt.Errorf("securityFeatures should have been removed, got %v", o["securityFeatures"])
						}
						return nil
					}),
				),
			},
			{
				ResourceName:      addr,
				ImportState:       true,
				ImportStateVerify: true,
				// Import reads every block the firewall returns, including defaults.
				ImportStateVerifyIgnore: []string{"email_scanning", "synchronized_security_heartbeat", "security_features"},
			},
		},
	})
}

func TestFirewallRulePositioning(t *testing.T) {
	env := acctest.New(t)
	config := func(position string) string {
		return env.Config(fmt.Sprintf(`
resource "sophosfirewall_firewall_rule" "first" {
  name     = "first"
  position = "top"
}

resource "sophosfirewall_firewall_rule" "second" {
  name               = "second"
  %s
}`, position))
	}
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{Config: config(`position = "bottom"`)},
			{
				Config: config(`position = "before"
  position_reference = sophosfirewall_firewall_rule.first.name`),
				Check: func(*terraform.State) error {
					if len(env.Server.Moves) != 1 {
						return fmt.Errorf("expected one move, got %v", env.Server.Moves)
					}
					m := env.Server.Moves[0]
					if m["name"] != "second" || m["position"] != "before" || m["referenceItem"].(map[string]any)["name"] != "first" {
						return fmt.Errorf("unexpected move %v", m)
					}
					return nil
				},
			},
		},
	})
}

func TestFirewallRulePositionValidation(t *testing.T) {
	env := acctest.New(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{{
			Config: env.Config(`
resource "sophosfirewall_firewall_rule" "r" {
  name     = "r"
  position = "after"
}`),
			ExpectError: regexp.MustCompile(`position_reference is required`),
		}},
	})
}

func checkStored(env *acctest.Env, name string, f func(map[string]any) error) resource.TestCheckFunc {
	return func(*terraform.State) error {
		o := env.Server.Get(rulesPath, name)
		if o == nil {
			return fmt.Errorf("rule %q not stored", name)
		}
		return f(o)
	}
}
