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

const sdwanRoutesPath = "/sd-wan/routes/ipv4"

const gateways = `
resource "sophosfirewall_gateway" "primary" {
  name       = "mpls-primary"
  ip_address = "192.0.2.1"
}

resource "sophosfirewall_gateway" "backup" {
  name       = "mpls-backup"
  ip_address = "198.51.100.1"
}
`

func TestSDWANRoute(t *testing.T) {
	env := acctest.New(t)
	const addr = "sophosfirewall_sdwan_route.voice"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(gateways + `
resource "sophosfirewall_sdwan_route" "voice" {
  name              = "voice"
  inbound_interface = "Port2"
  source_networks = {
    ipv4_groups = ["lan-voice"]
  }
  services     = ["SIP"]
  dscp_marking = "46-Expedited Forwarding(EF)"

  link_selection = {
    primary_gateway = { name = sophosfirewall_gateway.primary.name }
    backup_gateway  = { name = sophosfirewall_gateway.backup.name }
  }
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "enabled", "true"),
					resource.TestCheckResourceAttr(addr, "inbound_interface", "Port2"),
					resource.TestCheckResourceAttr(addr, "link_selection.primary_gateway.name", "mpls-primary"),
					resource.TestCheckResourceAttr(addr, "link_selection.route_through_specific_gateway", "false"),
					resource.TestCheckNoResourceAttr(addr, "destination_networks"),
					resource.TestCheckNoResourceAttr(addr, "applications"),
					resource.TestCheckNoResourceAttr(addr, "users"),
					checkStored(env, sdwanRoutesPath, "voice", func(o map[string]any) error {
						if dn := o["destinationNetworks"].(map[string]any); dn["any"] != true {
							return fmt.Errorf("destinationNetworks = %v, want any", dn)
						}
						if ui := o["usersOrGroups"].(map[string]any); ui["any"] != true {
							return fmt.Errorf("usersOrGroups = %v, want any", ui)
						}
						g := o["linkSelection"].(map[string]any)["gateway"].(map[string]any)
						if g["backupGateway"].(map[string]any)["name"] != "mpls-backup" {
							return fmt.Errorf("gateway = %v", g)
						}
						return nil
					}),
				),
			},
			{
				// Match any interface, add users and applications, fail over to WAN load balancing.
				Config: env.Config(gateways + `
resource "sophosfirewall_sdwan_route" "voice" {
  name        = "voice"
  description = "Voice traffic"
  source_networks = {
    ipv4_groups = ["lan-voice"]
  }
  services     = ["SIP"]
  applications = ["Teams"]
  user_groups  = ["Sales"]

  link_selection = {
    primary_gateway                = { name = sophosfirewall_gateway.primary.name }
    backup_gateway                 = { wan_link_load_balance = true }
    route_through_specific_gateway = true
  }
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr(addr, "inbound_interface"),
					resource.TestCheckNoResourceAttr(addr, "dscp_marking"),
					resource.TestCheckResourceAttr(addr, "applications.#", "1"),
					resource.TestCheckResourceAttr(addr, "user_groups.#", "1"),
					resource.TestCheckResourceAttr(addr, "link_selection.backup_gateway.wan_link_load_balance", "true"),
					resource.TestCheckNoResourceAttr(addr, "link_selection.backup_gateway.name"),
					checkStored(env, sdwanRoutesPath, "voice", func(o map[string]any) error {
						if ii := o["inboundInterface"].(map[string]any); ii["any"] != true || len(ii) != 1 {
							return fmt.Errorf("inboundInterface = %v, want only any", ii)
						}
						b := o["linkSelection"].(map[string]any)["gateway"].(map[string]any)["backupGateway"].(map[string]any)
						if b["wanLinkLoadBalance"] != true || len(b) != 1 {
							return fmt.Errorf("backupGateway = %v, want only wanLinkLoadBalance", b)
						}
						if _, ok := o["dscpMarking"]; ok {
							return fmt.Errorf("dscpMarking should have been cleared")
						}
						return nil
					}),
				),
			},
			{ResourceName: addr, ImportState: true, ImportStateVerify: true},
			{
				// Switching to an SD-WAN profile changes the link selection branch: replace.
				Config: env.Config(gateways + `
resource "sophosfirewall_sdwan_route" "voice" {
  name        = "voice"
  description = "Voice traffic"
  source_networks = {
    ipv4_groups = ["lan-voice"]
  }
  services     = ["SIP"]
  applications = ["Teams"]
  user_groups  = ["Sales"]

  link_selection = {
    sdwan_profile = "voice-profile"
  }
}

data "sophosfirewall_sdwan_route" "voice" {
  name = sophosfirewall_sdwan_route.voice.name
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionReplace)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "link_selection.sdwan_profile", "voice-profile"),
					resource.TestCheckNoResourceAttr(addr, "link_selection.primary_gateway"),
					resource.TestCheckResourceAttr("data.sophosfirewall_sdwan_route.voice", "link_selection.sdwan_profile", "voice-profile"),
					resource.TestCheckResourceAttr("data.sophosfirewall_sdwan_route.voice", "enabled", "true"),
					resource.TestCheckResourceAttrPair("data.sophosfirewall_sdwan_route.voice", "id", addr, "id"),
				),
			},
		},
	})
}

func TestSDWANRoutePositioning(t *testing.T) {
	env := acctest.New(t)
	config := func(position string) string {
		return env.Config(fmt.Sprintf(`
resource "sophosfirewall_sdwan_route" "first" {
  name           = "first"
  position       = "top"
  link_selection = { primary_gateway = { wan_link_load_balance = true } }
}

resource "sophosfirewall_sdwan_route" "second" {
  name           = "second"
  link_selection = { primary_gateway = { wan_link_load_balance = true } }
  %s
}`, position))
	}
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: config(`position = "bottom"`),
				Check: func(*terraform.State) error {
					if len(env.Server.Moves) != 0 {
						return fmt.Errorf("unexpected moves %v", env.Server.Moves)
					}
					return nil
				},
			},
			{
				Config: config(`position = "before"
  position_reference = sophosfirewall_sdwan_route.first.name`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction("sophosfirewall_sdwan_route.second", plancheck.ResourceActionUpdate)},
				},
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
			{
				ResourceName: "sophosfirewall_sdwan_route.second", ImportState: true, ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{"position", "position_reference"},
			},
		},
	})
}

func TestSDWANRouteValidation(t *testing.T) {
	env := acctest.New(t)
	for name, tc := range map[string]struct{ body, err string }{
		"position without reference": {`
  position       = "after"
  link_selection = { sdwan_profile = "p" }`, `position_reference is required`},
		"profile and gateway": {`
  link_selection = {
    sdwan_profile   = "p"
    primary_gateway = { name = "gw" }
  }`, `Invalid Attribute Combination`},
		"no link selection": {`
  link_selection = {}`, `Invalid Attribute Combination`},
		"gateway name and load balance": {`
  link_selection = { primary_gateway = { name = "gw", wan_link_load_balance = true } }`, `Invalid Attribute Combination`},
		"load balance false": {`
  link_selection = { primary_gateway = { wan_link_load_balance = false } }`, `must be true when set`},
		"bad dscp": {`
  dscp_marking   = "EF"
  link_selection = { sdwan_profile = "p" }`, `value must be one of`},
	} {
		t.Run(name, func(t *testing.T) {
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: env.Factories,
				Steps: []resource.TestStep{{
					Config:      env.Config(`resource "sophosfirewall_sdwan_route" "r" {` + "\n  name = \"r\"" + tc.body + "\n}"),
					ExpectError: regexp.MustCompile(tc.err),
				}},
			})
		})
	}
}
