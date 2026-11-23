package application_test

import (
	"fmt"
	"reflect"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/acctest"
)

const policiesPath = "/application/policies"

// ruleNames returns the rule names of a stored policy in order.
func ruleNames(o map[string]any) []string {
	var out []string
	rules, _ := o["rules"].([]any)
	for _, r := range rules {
		out = append(out, fmt.Sprint(r.(map[string]any)["name"]))
	}
	return out
}

func checkStored(env *acctest.Env, name string, check func(map[string]any) error) resource.TestCheckFunc {
	return func(*terraform.State) error {
		o := env.Server.Get(policiesPath, name)
		if o == nil {
			return fmt.Errorf("policy %q not found on server", name)
		}
		return check(o)
	}
}

func TestApplicationFilterPolicy(t *testing.T) {
	env := acctest.New(t)
	const addr = "sophosfirewall_application_filter_policy.office"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_application_filter_policy" "office" {
  name = "office-apps"

  rules = [
    {
      name         = "allow-collaboration"
      action       = "allow"
      applications = ["Microsoft Teams", "Slack"]
    },
    {
      name       = "deny-high-risk"
      action     = "deny"
      categories = ["P2P", "Proxy and Tunnel"]
      risks      = ["High", "Very High"]
    },
  ]
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(addr, "id"),
					resource.TestCheckResourceAttr(addr, "description", ""),
					resource.TestCheckResourceAttr(addr, "rules.#", "2"),
					resource.TestCheckResourceAttr(addr, "rules.0.name", "allow-collaboration"),
					resource.TestCheckResourceAttr(addr, "rules.0.schedule", "All The Time"),
					resource.TestCheckResourceAttr(addr, "rules.0.applications.#", "2"),
					resource.TestCheckNoResourceAttr(addr, "rules.0.categories"),
					resource.TestCheckResourceAttr(addr, "rules.1.categories.#", "2"),
					resource.TestCheckResourceAttr(addr, "rules.1.risks.#", "2"),
					resource.TestCheckNoResourceAttr(addr, "rules.1.applications"),
					checkStored(env, "office-apps", func(o map[string]any) error {
						rules := o["rules"].([]any)
						r0, r1 := rules[0].(map[string]any), rules[1].(map[string]any)
						if r0["selectionMode"] != "applicationList" || r0["applicationFilters"] != nil {
							return fmt.Errorf("rule 0 = %v", r0)
						}
						if r1["selectionMode"] != "applicationFilter" || r1["applicationList"] != nil {
							return fmt.Errorf("rule 1 = %v", r1)
						}
						want := []any{
							map[string]any{"attribute": "category", "operator": "in", "values": []any{"P2P", "Proxy and Tunnel"}},
							map[string]any{"attribute": "risk", "operator": "in", "values": []any{"High", "Very High"}},
						}
						if !reflect.DeepEqual(r1["applicationFilters"], want) {
							return fmt.Errorf("rule 1 filters = %v", r1["applicationFilters"])
						}
						if s := r1["schedule"].(map[string]any); s["name"] != "All The Time" {
							return fmt.Errorf("rule 1 schedule = %v", s)
						}
						return nil
					}),
				),
			},
			{
				// Describe, add a rule at the top and reorder: one PATCH replacing the rule set.
				Config: env.Config(`
resource "sophosfirewall_schedule" "work" {
  name       = "Work-Hours"
  type       = "recurring"
  time_slots = [{ day_of_week = "weekdays", start_time = "08:00", end_time = "18:00" }]
}

resource "sophosfirewall_application_filter_policy" "office" {
  name        = "office-apps"
  description = "Office application control"

  rules = [
    {
      name            = "deny-evasion"
      action          = "deny"
      characteristics = ["Can bypass firewall policy", "Tunnels other apps"]
      technologies    = ["Client Server"]
    },
    {
      name       = "deny-high-risk"
      action     = "deny"
      categories = ["P2P", "Proxy and Tunnel"]
      risks      = ["High", "Very High"]
    },
    {
      name         = "allow-collaboration"
      action       = "allow"
      schedule     = sophosfirewall_schedule.work.name
      applications = ["Microsoft Teams", "Slack", "Zoom"]
    },
  ]
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "rules.#", "3"),
					resource.TestCheckResourceAttr(addr, "rules.0.name", "deny-evasion"),
					resource.TestCheckResourceAttr(addr, "rules.2.schedule", "Work-Hours"),
					resource.TestCheckResourceAttr(addr, "rules.2.applications.#", "3"),
					checkStored(env, "office-apps", func(o map[string]any) error {
						if got, want := ruleNames(o), []string{"deny-evasion", "deny-high-risk", "allow-collaboration"}; !reflect.DeepEqual(got, want) {
							return fmt.Errorf("rule order = %v, want %v", got, want)
						}
						if o["description"] != "Office application control" {
							return fmt.Errorf("description = %v", o["description"])
						}
						return nil
					}),
				),
			},
			{ResourceName: addr, ImportState: true, ImportStateVerify: true},
			{ResourceName: addr, ImportState: true, ImportStateId: "office-apps", ImportStateVerify: true},
			{
				// The name cannot be patched, so renaming recreates the policy.
				Config: env.Config(`
resource "sophosfirewall_application_filter_policy" "office" {
  name  = "office-apps-v2"
  rules = [{ name = "deny-p2p", action = "deny", categories = ["P2P"] }]
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionDestroyBeforeCreate)},
				},
				Check: func(*terraform.State) error {
					if got := env.Server.Names(policiesPath); !reflect.DeepEqual(got, []string{"office-apps-v2"}) {
						return fmt.Errorf("policies on server = %v", got)
					}
					return nil
				},
			},
		},
	})
}

// A classification filter makes the firewall add characteristics
// "Cloud Application"; that must not show up as drift.
func TestApplicationFilterPolicyClassification(t *testing.T) {
	env := acctest.New(t)
	const addr = "sophosfirewall_application_filter_policy.cloud"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_application_filter_policy" "cloud" {
  name = "cloud-apps"
  rules = [
    {
      name            = "deny-unsanctioned"
      action          = "deny"
      classifications = ["Unsanctioned"]
      smart_filters   = ["storage"]
      other_filters   = { vendor = ["acme"] }
    },
  ]
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr(addr, "rules.0.characteristics"),
					resource.TestCheckResourceAttr(addr, "rules.0.classifications.#", "1"),
					resource.TestCheckResourceAttr(addr, "rules.0.smart_filters.0", "storage"),
					resource.TestCheckResourceAttr(addr, "rules.0.other_filters.vendor.0", "acme"),
					checkStored(env, "cloud-apps", func(o map[string]any) error {
						filters := o["rules"].([]any)[0].(map[string]any)["applicationFilters"].([]any)
						var attrs []string
						for _, f := range filters {
							attrs = append(attrs, fmt.Sprint(f.(map[string]any)["attribute"]))
						}
						if want := []string{"classification", "smartFilter", "vendor", "characteristics"}; !reflect.DeepEqual(attrs, want) {
							return fmt.Errorf("filter attributes = %v, want %v", attrs, want)
						}
						return nil
					}),
				),
			},
			// Re-planning the same configuration after a refresh must be empty.
			{
				Config: env.Config(`
resource "sophosfirewall_application_filter_policy" "cloud" {
  name = "cloud-apps"
  rules = [
    {
      name            = "deny-unsanctioned"
      action          = "deny"
      classifications = ["Unsanctioned"]
      smart_filters   = ["storage"]
      other_filters   = { vendor = ["acme"] }
    },
  ]
}`),
				PlanOnly: true,
			},
		},
	})
}

// The policy is applied by a firewall rule through security_features.
func TestApplicationFilterPolicyFirewallRule(t *testing.T) {
	env := acctest.New(t)
	const rule = "sophosfirewall_firewall_rule.web"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{{
			Config: env.Config(`
resource "sophosfirewall_application_filter_policy" "office" {
  name  = "office-apps"
  rules = [{ name = "deny-p2p", action = "deny", categories = ["P2P"] }]
}

resource "sophosfirewall_firewall_rule" "web" {
  name              = "lan-to-wan"
  action            = "accept"
  source_zones      = ["LAN"]
  destination_zones = ["WAN"]

  security_features = {
    application_policy = sophosfirewall_application_filter_policy.office.name
  }
}`),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(rule, "security_features.application_policy", "office-apps"),
				func(*terraform.State) error {
					o := env.Server.Get("/firewall/rules/ipv4", "lan-to-wan")
					sf, _ := o["securityFeatures"].(map[string]any)
					if ref, _ := sf["applicationPolicy"].(map[string]any); ref["name"] != "office-apps" {
						return fmt.Errorf("securityFeatures = %v", sf)
					}
					return nil
				},
			),
		}},
	})
}

func TestApplicationFilterPolicyDataSource(t *testing.T) {
	env := acctest.New(t)
	// A built-in policy as shipped by the firewall.
	env.Server.Seed(policiesPath, map[string]any{
		"name":        "Block high risk (Risk Level 4 and 5) apps",
		"description": "Drops traffic that are classified under high risk apps (Risk Level- 4 and 5)",
		"rules": []any{map[string]any{
			"id": "20000000-0000-4000-8000-000000000001", "name": "high-risk", "selectionMode": "applicationFilter",
			"applicationFilters": []any{map[string]any{"attribute": "risk", "operator": "in", "values": []any{"4", "5"}}},
			"action":             "deny", "schedule": map[string]any{"name": "All The Time"},
		}},
	})
	const ds = "data.sophosfirewall_application_filter_policy.high_risk"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{{
			Config: env.Config(`data "sophosfirewall_application_filter_policy" "high_risk" { name = "Block high risk (Risk Level 4 and 5) apps" }`),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet(ds, "id"),
				resource.TestCheckResourceAttr(ds, "rules.#", "1"),
				resource.TestCheckResourceAttr(ds, "rules.0.action", "deny"),
				resource.TestCheckResourceAttr(ds, "rules.0.risks.#", "2"),
				resource.TestCheckResourceAttr(ds, "rules.0.schedule", "All The Time"),
				resource.TestCheckNoResourceAttr(ds, "rules.0.applications"),
			),
		}},
	})
}

func TestApplicationFilterPolicyValidation(t *testing.T) {
	env := acctest.New(t)
	cfg := func(rules string) string {
		return env.Config(`
resource "sophosfirewall_application_filter_policy" "t" {
  name  = "t"
  rules = ` + rules + `
}`)
	}
	steps := []struct{ rules, err string }{
		{`[]`, `at least 1`},
		{`[{ name = "r", action = "drop", categories = ["P2P"] }]`, `value must be one of`},
		{`[{ name = "r", action = "deny" }]`, `Set\s+.applications. or at least one filter attribute`},
		{`[{ name = "r", action = "deny", applications = ["Slack"], risks = ["High"] }]`, `not\s+both`},
		{`[{ name = "r", action = "deny", categories = ["P2P"] }, { name = "r", action = "allow", categories = ["P2P"] }]`, `used more than once`},
		{`[{ name = "r", action = "deny", other_filters = { category = ["P2P"] } }]`, `Use the .categories. attribute`},
		{`[{ name = "r", action = "deny", categories = [] }]`, `at least 1`},
		{`[{ name = "a,b", action = "deny", categories = ["P2P"] }]`, `not a valid SFOS object name`},
	}
	var ts []resource.TestStep
	for _, s := range steps {
		ts = append(ts, resource.TestStep{Config: cfg(s.rules), ExpectError: regexp.MustCompile(s.err), PlanOnly: true})
	}
	resource.UnitTest(t, resource.TestCase{ProtoV6ProviderFactories: env.Factories, Steps: ts})
}
