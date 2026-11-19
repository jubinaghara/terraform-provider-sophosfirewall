package routing_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/acctest"
)

const gatewaysPath = "/routing/gateways/custom/ipv4"

func TestGateway(t *testing.T) {
	env := acctest.New(t)
	const addr = "sophosfirewall_gateway.mpls"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_gateway" "mpls" {
  name       = "mpls-gw"
  ip_address = "192.0.2.1"
  interface  = "Port3"
  zone       = "WAN"

  health_check = {
    enabled  = true
    interval = 30
    rules = [
      { protocol = "ping", host = "192.0.2.254" },
      { protocol = "tcp", host = "192.0.2.253", port = 443, logical_operator = "or" },
    ]
  }
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "health_check.enabled", "true"),
					resource.TestCheckResourceAttr(addr, "health_check.interval", "30"),
					// Server defaults fill in what was not configured.
					resource.TestCheckResourceAttr(addr, "health_check.timeout", "2"),
					resource.TestCheckResourceAttr(addr, "health_check.retries", "3"),
					resource.TestCheckResourceAttr(addr, "health_check.rules.#", "2"),
					resource.TestCheckResourceAttr(addr, "health_check.rules.0.logical_operator", "and"),
					resource.TestCheckNoResourceAttr(addr, "health_check.rules.0.port"),
					resource.TestCheckResourceAttr(addr, "health_check.rules.1.port", "443"),
					checkStored(env, gatewaysPath, "mpls-gw", func(o map[string]any) error {
						rules := o["healthCheck"].(map[string]any)["rules"].([]any)
						if r := rules[1].(map[string]any); r["host"].(map[string]any)["ipv4Address"] != "192.0.2.253" || r["logicalOperator"] != "or" {
							return fmt.Errorf("rules[1] = %v", r)
						}
						return nil
					}),
				),
			},
			{ResourceName: addr, ImportState: true, ImportStateVerify: true},
			{
				// Remove the health check: it is switched off on the firewall.
				Config: env.Config(`
resource "sophosfirewall_gateway" "mpls" {
  name       = "mpls-gw"
  ip_address = "192.0.2.2"
  interface  = "Port3"
  zone       = "WAN"
}

data "sophosfirewall_gateway" "mpls" {
  name = sophosfirewall_gateway.mpls.name
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr(addr, "health_check"),
					resource.TestCheckResourceAttr(addr, "ip_address", "192.0.2.2"),
					resource.TestCheckResourceAttr("data.sophosfirewall_gateway.mpls", "ip_address", "192.0.2.2"),
					resource.TestCheckResourceAttr("data.sophosfirewall_gateway.mpls", "zone", "WAN"),
					checkStored(env, gatewaysPath, "mpls-gw", func(o map[string]any) error {
						hc := o["healthCheck"].(map[string]any)
						if hc["enabled"] != false || hc["rules"] != nil {
							return fmt.Errorf("healthCheck = %v, want disabled without rules", hc)
						}
						return nil
					}),
				),
			},
			{ResourceName: addr, ImportState: true, ImportStateVerify: true},
		},
	})
}

func TestGatewayValidation(t *testing.T) {
	env := acctest.New(t)
	for name, tc := range map[string]struct{ body, err string }{
		"ping with port": {`
  health_check = {
    enabled = true
    rules   = [{ protocol = "ping", host = "192.0.2.254", port = 80 }]
  }`, `port is only valid for the tcp protocol`},
		"bad protocol": {`
  health_check = {
    enabled = true
    rules   = [{ protocol = "http", host = "192.0.2.254" }]
  }`, `value must be one of`},
		"timeout out of range": {`
  health_check = {
    enabled = true
    timeout = 30
  }`, `must be between 1 and 10`},
	} {
		t.Run(name, func(t *testing.T) {
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: env.Factories,
				Steps: []resource.TestStep{{
					Config: env.Config(`resource "sophosfirewall_gateway" "g" {
  name       = "g"
  ip_address = "192.0.2.1"` + tc.body + "\n}"),
					ExpectError: regexp.MustCompile(tc.err),
				}},
			})
		})
	}
}
