package ips_test

import (
	"encoding/json"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/acctest"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/services/ips"
)

const addr = "sophosfirewall_ips_policy.p"

// checkRules compares the stored rules (as JSON) with want.
func checkRules(env *acctest.Env, name, want string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		o := env.Server.Get(ips.PoliciesPath, name)
		if o == nil {
			return fmt.Errorf("policy %q not stored", name)
		}
		got, _ := json.Marshal(o["rules"])
		var a, b any
		_ = json.Unmarshal(got, &a)
		if err := json.Unmarshal([]byte(want), &b); err != nil {
			return err
		}
		ga, _ := json.Marshal(a)
		gb, _ := json.Marshal(b)
		if string(ga) != string(gb) {
			return fmt.Errorf("stored rules =\n%s\nwant\n%s", ga, gb)
		}
		return nil
	}
}

func TestIPSPolicy(t *testing.T) {
	env := acctest.New(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_ips_policy" "p" {
  name = "web-servers"
  rules = [
    {
      name         = "critical-server"
      action       = "dropSession"
      severities   = ["Critical", "Major"]
      targets      = ["Server"]
      smart_filter = ["CVE-2021-44228"]
    },
  ]
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(addr, "id"),
					resource.TestCheckResourceAttr(addr, "description", ""),
					resource.TestCheckResourceAttr(addr, "rules.#", "1"),
					resource.TestCheckResourceAttr(addr, "rules.0.signature_source", "default"),
					resource.TestCheckResourceAttr(addr, "rules.0.severities.#", "2"),
					resource.TestCheckNoResourceAttr(addr, "rules.0.categories"),
					resource.TestCheckNoResourceAttr(addr, "rules.0.signatures"),
					resource.TestCheckNoResourceAttr(addr, "rules.0.additional_filters"),
					checkRules(env, "web-servers", `[{
  "name": "critical-server", "action": "dropSession", "signatureSource": "default", "selectionMode": "signatureFilter",
  "signatureFilters": [
    {"attribute": "severity", "operator": "in", "values": ["Critical", "Major"]},
    {"attribute": "target", "operator": "in", "values": ["Server"]},
    {"attribute": "smartFilter", "operator": "in", "values": ["CVE-2021-44228"]}
  ]
}]`),
				),
			},
			{
				// Add a rule in front, switch to a signature list, add other filters.
				Config: env.Config(`
resource "sophosfirewall_ips_policy" "p" {
  name        = "web-servers"
  description = "Public web servers"
  rules = [
    {
      name       = "weblogic"
      action     = "reset"
      signatures = ["SERVER-ORACLE Oracle WebLogic Server CVE-2018-2894", "SERVER-ORACLE Oracle WebLogic Server CVE-2020-14882"]
    },
    {
      name       = "critical-server"
      action     = "dropSession"
      categories = ["web-services"]
      severities = ["Critical", "Major"]
      platforms  = ["Linux"]
      targets    = ["Server"]
      additional_filters = {
        risk = ["high"]
      }
    },
  ]
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "description", "Public web servers"),
					resource.TestCheckResourceAttr(addr, "rules.0.name", "weblogic"),
					resource.TestCheckResourceAttr(addr, "rules.0.signatures.#", "2"),
					resource.TestCheckResourceAttr(addr, "rules.1.additional_filters.risk.#", "1"),
					resource.TestCheckNoResourceAttr(addr, "rules.1.smart_filter"),
					checkRules(env, "web-servers", `[{
  "name": "weblogic", "action": "reset", "signatureSource": "default", "selectionMode": "signatureList",
  "signatureList": [
    {"name": "SERVER-ORACLE Oracle WebLogic Server CVE-2018-2894"},
    {"name": "SERVER-ORACLE Oracle WebLogic Server CVE-2020-14882"}
  ]
}, {
  "name": "critical-server", "action": "dropSession", "signatureSource": "default", "selectionMode": "signatureFilter",
  "signatureFilters": [
    {"attribute": "category", "operator": "in", "values": ["web-services"]},
    {"attribute": "severity", "operator": "in", "values": ["Critical", "Major"]},
    {"attribute": "platform", "operator": "in", "values": ["Linux"]},
    {"attribute": "target", "operator": "in", "values": ["Server"]},
    {"attribute": "risk", "operator": "in", "values": ["high"]}
  ]
}]`),
				),
			},
			{
				// Reorder the rules: still an in-place update.
				Config: env.Config(`
resource "sophosfirewall_ips_policy" "p" {
  name        = "web-servers"
  description = "Public web servers"
  rules = [
    {
      name       = "critical-server"
      action     = "dropSession"
      categories = ["web-services"]
      severities = ["Critical", "Major"]
      platforms  = ["Linux"]
      targets    = ["Server"]
      additional_filters = {
        risk = ["high"]
      }
    },
    {
      name       = "weblogic"
      action     = "reset"
      signatures = ["SERVER-ORACLE Oracle WebLogic Server CVE-2018-2894", "SERVER-ORACLE Oracle WebLogic Server CVE-2020-14882"]
    },
  ]
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "rules.0.name", "critical-server"),
					resource.TestCheckResourceAttr(addr, "rules.1.name", "weblogic"),
					func(*terraform.State) error {
						rules := env.Server.Get(ips.PoliciesPath, "web-servers")["rules"].([]any)
						if n := rules[0].(map[string]any)["name"]; n != "critical-server" {
							return fmt.Errorf("first stored rule = %v", n)
						}
						return nil
					},
				),
			},
			{ResourceName: addr, ImportState: true, ImportStateVerify: true},
			{ResourceName: addr, ImportState: true, ImportStateVerify: true, ImportStateId: "web-servers"},
			{
				// The name cannot be patched.
				Config: env.Config(`
resource "sophosfirewall_ips_policy" "p" {
  name  = "web-servers-2"
  rules = [{ name = "all-critical", severities = ["Critical"] }]
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionDestroyBeforeCreate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "rules.0.action", "recommended"),
					func(*terraform.State) error {
						if env.Server.Get(ips.PoliciesPath, "web-servers") != nil {
							return fmt.Errorf("old policy still exists")
						}
						return nil
					},
				),
			},
		},
	})
}

// TestIPSPolicyFirewallRule attaches a policy to an accepting firewall rule.
func TestIPSPolicyFirewallRule(t *testing.T) {
	env := acctest.New(t)
	const rule = "sophosfirewall_firewall_rule.r"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_ips_policy" "p" {
  name = "lan-to-wan-strict"
  rules = [{
    name       = "client-critical"
    action     = "dropPacket"
    severities = ["Critical"]
    targets    = ["Client"]
  }]
}

resource "sophosfirewall_firewall_rule" "r" {
  name              = "lan-to-wan"
  action            = "accept"
  source_zones      = ["LAN"]
  destination_zones = ["WAN"]
  security_features = {
    ips_policy = sophosfirewall_ips_policy.p.name
  }
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(rule, "security_features.ips_policy", "lan-to-wan-strict"),
					func(*terraform.State) error {
						sf := env.Server.Get("/firewall/rules/ipv4", "lan-to-wan")["securityFeatures"].(map[string]any)
						if fmt.Sprint(sf["ipsPolicy"]) != "map[name:lan-to-wan-strict]" {
							return fmt.Errorf("stored ipsPolicy = %v", sf["ipsPolicy"])
						}
						return nil
					},
				),
			},
		},
	})
}

func TestIPSPolicyDataSourceBuiltIn(t *testing.T) {
	env := acctest.New(t)
	// A built-in policy as the firewall reports it, including read-only fields.
	env.Server.Seed(ips.PoliciesPath, map[string]any{
		"name":        "generalpolicy",
		"description": "General policy",
		"createdAt":   "2026-01-20T10:00:00Z",
		"rules": []any{
			map[string]any{
				"id": "e3030303-0303-4303-8303-030303030303", "name": "all", "action": "recommended",
				"signatureSource": "default", "selectionMode": "signatureFilter",
				"signatureFilters": []any{
					map[string]any{"attribute": "target", "operator": "in", "values": []any{"Server", "Client"}},
					map[string]any{"attribute": "risk", "operator": "in", "values": []any{"high"}},
				},
			},
			map[string]any{
				"id": "f4040404-0404-4404-8404-040404040404", "name": "known", "action": "dropSession",
				"signatureSource": "custom", "selectionMode": "signatureList",
				"signatureList": []any{map[string]any{"name": "my-custom-sig"}},
			},
		},
	})
	const ds = "data.sophosfirewall_ips_policy.general"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{{
			Config: env.Config(`data "sophosfirewall_ips_policy" "general" { name = "generalpolicy" }`),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet(ds, "id"),
				resource.TestCheckResourceAttr(ds, "description", "General policy"),
				resource.TestCheckResourceAttr(ds, "rules.#", "2"),
				resource.TestCheckResourceAttr(ds, "rules.0.targets.#", "2"),
				resource.TestCheckTypeSetElemAttr(ds, "rules.0.targets.*", "Client"),
				resource.TestCheckResourceAttr(ds, "rules.0.additional_filters.risk.0", "high"),
				resource.TestCheckNoResourceAttr(ds, "rules.0.signatures"),
				resource.TestCheckResourceAttr(ds, "rules.1.signature_source", "custom"),
				resource.TestCheckResourceAttr(ds, "rules.1.signatures.0", "my-custom-sig"),
			),
		}},
	})
}

func TestIPSPolicyValidation(t *testing.T) {
	env := acctest.New(t)
	cfg := func(rules string) string {
		return env.Config(fmt.Sprintf(`
resource "sophosfirewall_ips_policy" "t" {
  name  = "t"
  rules = %s
}`, rules))
	}
	steps := []resource.TestStep{
		{Config: cfg(`[]`), ExpectError: regexp.MustCompile(`at least 1`)},
		{Config: cfg(`[{ name = "r" }]`), ExpectError: regexp.MustCompile(`Missing signature selection`)},
		{
			Config:      cfg(`[{ name = "r", severities = ["Critical"], signatures = ["x"] }]`),
			ExpectError: regexp.MustCompile(`Conflicting signature selection`),
		},
		{
			Config:      cfg(`[{ name = "r", severities = ["Critical"] }, { name = "r", targets = ["Client"] }]`),
			ExpectError: regexp.MustCompile(`Duplicate rule name`),
		},
		{Config: cfg(`[{ name = "r", action = "block", targets = ["Client"] }]`), ExpectError: regexp.MustCompile(`value must be one of`)},
		{Config: cfg(`[{ name = "r", signature_source = "sophos", targets = ["Client"] }]`), ExpectError: regexp.MustCompile(`value must be one of`)},
		{Config: cfg(`[{ name = "r", severities = [] }]`), ExpectError: regexp.MustCompile(`at least 1`)},
		{
			Config:      cfg(`[{ name = "r", additional_filters = { severity = ["Critical"] } }]`),
			ExpectError: regexp.MustCompile(`value must be none of`),
		},
		{Config: cfg(`[{ name = "a,b", targets = ["Client"] }]`), ExpectError: regexp.MustCompile(`not a valid SFOS object name`)},
		{
			Config:      env.Config(`resource "sophosfirewall_ips_policy" "t" { name = "t" }`),
			ExpectError: regexp.MustCompile(`"rules" is required`),
		},
	}
	for i := range steps {
		steps[i].PlanOnly = true
	}
	resource.UnitTest(t, resource.TestCase{ProtoV6ProviderFactories: env.Factories, Steps: steps})
}
