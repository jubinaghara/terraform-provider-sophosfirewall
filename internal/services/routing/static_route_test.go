package routing_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/acctest"
)

const staticRoutesPath = "/routing/static-unicast-routes/ipv4"

func checkStored(env *acctest.Env, collection, name string, f func(map[string]any) error) resource.TestCheckFunc {
	return func(*terraform.State) error {
		o := env.Server.Get(collection, name)
		if o == nil {
			return fmt.Errorf("%s %q not stored", collection, name)
		}
		return f(o)
	}
}

func TestStaticRoute(t *testing.T) {
	env := acctest.New(t)
	const addr = "sophosfirewall_static_route.branch"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_static_route" "branch" {
  name        = "branch-office"
  destination = "192.168.10.0/24"
  gateway     = "172.16.16.1"
  interface   = "Port1"
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(addr, "id"),
					resource.TestCheckResourceAttr(addr, "destination", "192.168.10.0/24"),
					resource.TestCheckResourceAttr(addr, "metric", "0"),
					resource.TestCheckResourceAttr(addr, "administrative_distance", "1"),
					resource.TestCheckResourceAttr(addr, "description", ""),
					checkStored(env, staticRoutesPath, "branch-office", func(o map[string]any) error {
						if o["destinationAddressIpv4"] != "192.168.10.0" || o["cidr"] != float64(24) {
							return fmt.Errorf("destination = %v/%v", o["destinationAddressIpv4"], o["cidr"])
						}
						if o["gatewayIpv4"] != "172.16.16.1" || o["interface"].(map[string]any)["name"] != "Port1" {
							return fmt.Errorf("next hop = %v via %v", o["gatewayIpv4"], o["interface"])
						}
						return nil
					}),
				),
			},
			{
				// Drop the gateway, change destination and preference in place.
				Config: env.Config(`
resource "sophosfirewall_static_route" "branch" {
  name                    = "branch-office"
  description             = "Branch office via tunnel"
  destination             = "10.20.0.0/16"
  interface               = "Port1"
  metric                  = 10
  administrative_distance = 5
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr(addr, "gateway"),
					resource.TestCheckResourceAttr(addr, "destination", "10.20.0.0/16"),
					resource.TestCheckResourceAttr(addr, "metric", "10"),
					resource.TestCheckResourceAttr(addr, "administrative_distance", "5"),
					checkStored(env, staticRoutesPath, "branch-office", func(o map[string]any) error {
						if _, ok := o["gatewayIpv4"]; ok {
							return fmt.Errorf("gatewayIpv4 should have been cleared, got %v", o["gatewayIpv4"])
						}
						return nil
					}),
				),
			},
			{ResourceName: addr, ImportState: true, ImportStateVerify: true},
			{
				// Import by name works too.
				ResourceName: addr, ImportState: true, ImportStateId: "branch-office", ImportStateVerify: true,
			},
			{
				// Renaming is not supported by the API.
				Config: env.Config(`
resource "sophosfirewall_static_route" "branch" {
  name                    = "branch-office-2"
  description             = "Branch office via tunnel"
  destination             = "10.20.0.0/16"
  interface               = "Port1"
  metric                  = 10
  administrative_distance = 5
}

data "sophosfirewall_static_route" "branch" {
  name = sophosfirewall_static_route.branch.name
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionReplace)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair("data.sophosfirewall_static_route.branch", "id", addr, "id"),
					resource.TestCheckResourceAttr("data.sophosfirewall_static_route.branch", "destination", "10.20.0.0/16"),
					resource.TestCheckResourceAttr("data.sophosfirewall_static_route.branch", "metric", "10"),
				),
			},
		},
	})
}

func TestStaticRouteBlackholeAndDefault(t *testing.T) {
	env := acctest.New(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_static_route" "sinkhole" {
  name        = "sinkhole"
  destination = "198.51.100.0/24"
  interface   = "Blackhole"
}

resource "sophosfirewall_static_route" "default" {
  name        = "default"
  destination = "0.0.0.0/0"
  gateway     = "203.0.113.1"
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("sophosfirewall_static_route.sinkhole", "interface", "Blackhole"),
					resource.TestCheckNoResourceAttr("sophosfirewall_static_route.sinkhole", "gateway"),
					resource.TestCheckResourceAttr("sophosfirewall_static_route.default", "destination", "0.0.0.0/0"),
					resource.TestCheckNoResourceAttr("sophosfirewall_static_route.default", "interface"),
					checkStored(env, staticRoutesPath, "default", func(o map[string]any) error {
						if o["cidr"] != float64(0) {
							return fmt.Errorf("cidr = %v, want 0", o["cidr"])
						}
						return nil
					}),
				),
			},
		},
	})
}

func TestStaticRouteValidation(t *testing.T) {
	env := acctest.New(t)
	for name, tc := range map[string]struct{ body, err string }{
		"no next hop": {`
  destination = "10.0.0.0/8"`, `Set gateway, interface or both`},
		"blackhole with gateway": {`
  destination = "10.0.0.0/8"
  interface   = "Blackhole"
  gateway     = "10.0.0.1"`, `A blackhole route has no gateway`},
		"non-canonical destination": {`
  destination = "10.1.2.3/8"
  interface   = "Port1"`, `must be the canonical network address "10.0.0.0/8"`},
		"name too long": {`
  destination = "10.0.0.0/8"
  interface   = "Port1"
  name        = "a-very-long-route-name"`, `string length must be between 1 and 20`},
		"bad gateway": {`
  destination = "10.0.0.0/8"
  gateway     = "10.0.0"`, `not a valid IPv4 address`},
	} {
		t.Run(name, func(t *testing.T) {
			body := tc.body
			if !regexp.MustCompile(`\bname\b`).MatchString(body) {
				body = "\n  name = \"r\"" + body
			}
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: env.Factories,
				Steps: []resource.TestStep{{
					Config:      env.Config(`resource "sophosfirewall_static_route" "r" {` + body + "\n}"),
					ExpectError: regexp.MustCompile(tc.err),
				}},
			})
		})
	}
}
