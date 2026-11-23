package web_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/acctest"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfostest"
)

const webPoliciesPath = "/web/policies"

func storedPolicy(env *acctest.Env, name string, f func(map[string]any) error) resource.TestCheckFunc {
	return func(*terraform.State) error {
		o := env.Server.Get(webPoliciesPath, name)
		if o == nil {
			return fmt.Errorf("web policy %q not stored", name)
		}
		return f(o)
	}
}

func storedRules(o map[string]any) []map[string]any {
	raw, _ := o["rules"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		out = append(out, r.(map[string]any))
	}
	return out
}

func refNames(v any) []string {
	var out []string
	items, _ := v.([]any)
	for _, i := range items {
		out = append(out, i.(map[string]any)["name"].(string))
	}
	return out
}

const policyURLGroup = `
resource "sophosfirewall_url_group" "blocked" {
  name = "Blocked-Sites"
  urls = ["example.net"]
}
`

func TestWebPolicy(t *testing.T) {
	env := acctest.New(t)
	const addr = "sophosfirewall_web_policy.staff"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(policyURLGroup + `
resource "sophosfirewall_web_policy" "staff" {
  name           = "Staff"
  default_action = "allow"

  rules = [
    {
      user_groups = ["Sales"]
      categories  = ["Gambling", "Weapons"]
      url_groups  = [sophosfirewall_url_group.blocked.name]
      http_action = "deny"
    },
    {
      file_types         = ["Executable Files"]
      http_action        = "warn"
      follow_http_action = false
      https_action       = "allow"
      schedule           = "Work hours"
    },
  ]
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(addr, "id"),
					resource.TestCheckResourceAttr(addr, "description", ""),
					resource.TestCheckResourceAttr(addr, "max_file_size", "300"),
					// Omitted options take the firewall's defaults.
					resource.TestCheckResourceAttr(addr, "reporting", "true"),
					resource.TestCheckResourceAttr(addr, "youtube_filter", "off"),
					resource.TestCheckResourceAttr(addr, "quota_limit", "60"),
					resource.TestCheckNoResourceAttr(addr, "google_app_domains"),
					resource.TestCheckResourceAttr(addr, "rules.#", "2"),
					resource.TestCheckResourceAttr(addr, "rules.0.enabled", "true"),
					resource.TestCheckResourceAttr(addr, "rules.0.follow_http_action", "true"),
					resource.TestCheckNoResourceAttr(addr, "rules.0.https_action"),
					resource.TestCheckResourceAttr(addr, "rules.0.schedule", "All The Time"),
					resource.TestCheckResourceAttr(addr, "rules.0.apply_content_filters", "false"),
					resource.TestCheckResourceAttr(addr, "rules.0.categories.#", "2"),
					resource.TestCheckNoResourceAttr(addr, "rules.0.users"),
					resource.TestCheckNoResourceAttr(addr, "rules.1.user_groups"),
					resource.TestCheckResourceAttr(addr, "rules.1.https_action", "allow"),
					resource.TestCheckResourceAttr(addr, "rules.1.schedule", "Work hours"),
					storedPolicy(env, "Staff", func(o map[string]any) error {
						if o["maxFileSize"] != float64(300) || o["defaultAction"] != "allow" {
							return fmt.Errorf("maxFileSize/defaultAction = %v/%v", o["maxFileSize"], o["defaultAction"])
						}
						rules := storedRules(o)
						if len(rules) != 2 {
							return fmt.Errorf("rules = %v", o["rules"])
						}
						r0, r1 := rules[0], rules[1]
						if r0["httpAction"] != "deny" || r0["httpsAction"] != "deny" || r0["followHttpAction"] != true {
							return fmt.Errorf("rule 0 actions = %v", r0)
						}
						if got := refNames(r0["usersOrGroups"].(map[string]any)["userGroups"]); !reflect.DeepEqual(got, []string{"Sales"}) {
							return fmt.Errorf("rule 0 userGroups = %v", got)
						}
						act := r0["activities"].(map[string]any)
						if got := refNames(act["urlGroups"]); !reflect.DeepEqual(got, []string{"Blocked-Sites"}) {
							return fmt.Errorf("rule 0 urlGroups = %v", got)
						}
						if _, ok := act["fileTypes"]; ok {
							return fmt.Errorf("rule 0 activities = %v, want no fileTypes", act)
						}
						if ug := r1["usersOrGroups"].(map[string]any); ug["any"] != true || len(ug) != 1 {
							return fmt.Errorf("rule 1 usersOrGroups = %v, want any", ug)
						}
						if r1["httpsAction"] != "allow" || r1["followHttpAction"] != false {
							return fmt.Errorf("rule 1 = %v", r1)
						}
						if r1["schedule"].(map[string]any)["name"] != "Work hours" {
							return fmt.Errorf("rule 1 schedule = %v", r1["schedule"])
						}
						return nil
					}),
				),
			},
			{
				// Reorder the rules, change options and restrict Google and Microsoft 365 access.
				Config: env.Config(policyURLGroup + `
resource "sophosfirewall_web_policy" "staff" {
  name                        = "Staff"
  description                 = "Staff browsing"
  default_action              = "deny"
  restrict_file_size          = true
  max_file_size               = 500
  enforce_safe_search         = true
  youtube_filter              = "strict"
  quota_limit                 = 120
  restrict_google_app_domains = true
  google_app_domains          = ["example.com", "example.org"]
  restrict_office365_tenants  = true
  office365_tenants           = ["example.onmicrosoft.com"]
  office365_directory_id      = "00000000-1111-2222-3333-444444444444"

  rules = [
    {
      file_types         = ["Executable Files"]
      http_action        = "warn"
      follow_http_action = false
      https_action       = "allow"
      schedule           = "Work hours"
    },
    {
      users       = ["jdoe"]
      user_groups = ["Sales"]
      categories  = ["Gambling"]
      http_action = "quota"
      enabled     = false
    },
    {
      categories            = ["Social Networking"]
      content_filters       = ["Confidential"]
      apply_content_filters = true
      http_action           = "log"
    },
  ]
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "default_action", "deny"),
					resource.TestCheckResourceAttr(addr, "max_file_size", "500"),
					resource.TestCheckResourceAttr(addr, "reporting", "true"),
					resource.TestCheckResourceAttr(addr, "google_app_domains.#", "2"),
					resource.TestCheckResourceAttr(addr, "rules.#", "3"),
					resource.TestCheckResourceAttr(addr, "rules.0.http_action", "warn"),
					resource.TestCheckResourceAttr(addr, "rules.1.enabled", "false"),
					resource.TestCheckResourceAttr(addr, "rules.1.users.#", "1"),
					resource.TestCheckResourceAttr(addr, "rules.2.apply_content_filters", "true"),
					storedPolicy(env, "Staff", func(o map[string]any) error {
						rules := storedRules(o)
						var actions []string
						for _, r := range rules {
							actions = append(actions, r["httpAction"].(string))
						}
						if !reflect.DeepEqual(actions, []string{"warn", "quota", "log"}) {
							return fmt.Errorf("rule order = %v", actions)
						}
						if o["youtubeFilter"] != "strict" || o["quotaLimit"] != float64(120) || o["restrictFileSize"] != true {
							return fmt.Errorf("options = %v", o)
						}
						if got := refNames(rules[2]["contentFilters"]); !reflect.DeepEqual(got, []string{"Confidential"}) {
							return fmt.Errorf("contentFilters = %v", got)
						}
						return nil
					}),
				),
			},
			{ResourceName: addr, ImportState: true, ImportStateVerify: true},
			{ResourceName: addr, ImportState: true, ImportStateId: "Staff", ImportStateVerify: true},
			{
				// Drop the optional lists and the rules, read it back as a data source.
				Config: env.Config(policyURLGroup + `
resource "sophosfirewall_web_policy" "staff" {
  name           = "Staff"
  default_action = "deny"
}

data "sophosfirewall_web_policy" "staff" {
  name = sophosfirewall_web_policy.staff.name
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr(addr, "rules"),
					resource.TestCheckNoResourceAttr(addr, "google_app_domains"),
					resource.TestCheckNoResourceAttr(addr, "office365_directory_id"),
					resource.TestCheckResourceAttr(addr, "max_file_size", "300"),
					// Options that are no longer configured keep their value.
					resource.TestCheckResourceAttr(addr, "youtube_filter", "strict"),
					resource.TestCheckResourceAttrPair("data.sophosfirewall_web_policy.staff", "id", addr, "id"),
					resource.TestCheckResourceAttr("data.sophosfirewall_web_policy.staff", "default_action", "deny"),
					resource.TestCheckResourceAttr("data.sophosfirewall_web_policy.staff", "youtube_filter", "strict"),
					storedPolicy(env, "Staff", func(o map[string]any) error {
						if len(storedRules(o)) != 0 {
							return fmt.Errorf("rules = %v, want none", o["rules"])
						}
						for _, k := range []string{"googleAppDomainFilter", "office365FilterTenants", "office365FilterDirectoryId"} {
							if _, ok := o[k]; ok {
								return fmt.Errorf("%s should have been cleared: %v", k, o[k])
							}
						}
						return nil
					}),
				),
			},
			{
				// Renaming replaces the policy.
				Config: env.Config(`
resource "sophosfirewall_web_policy" "staff" {
  name           = "Staff-2"
  default_action = "deny"
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionReplace)},
				},
				Check: func(*terraform.State) error {
					if got := env.Server.Names(webPoliciesPath); !reflect.DeepEqual(got, []string{"Staff-2"}) {
						return fmt.Errorf("policies on server = %v", got)
					}
					return nil
				},
			},
		},
	})
}

func TestWebPolicyUnmanaged(t *testing.T) {
	env := acctest.New(t)
	config := env.Config(`
resource "sophosfirewall_web_policy" "p" {
  name           = "Guests"
  default_action = "allow"
}`)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{Config: config},
			{
				// Rules added in the web admin console and the "no limit"
				// file size sentinel are not drift.
				PreConfig: func() {
					patchPolicy(t, env, "Guests", map[string]any{
						"maxFileSize": 0,
						"rules": []any{map[string]any{
							"httpAction": "deny", "httpsAction": "deny", "followHttpAction": true, "enabled": true,
							"usersOrGroups": map[string]any{"any": true},
							"activities":    map[string]any{"categories": []any{map[string]any{"id": "c1", "name": "Gambling"}}},
							"schedule":      map[string]any{"name": "All The Time"},
						}},
					})
				},
				Config:   config,
				PlanOnly: true,
			},
			{
				// Other changes leave the unmanaged rules alone.
				Config: env.Config(`
resource "sophosfirewall_web_policy" "p" {
  name           = "Guests"
  description    = "Guest Wi-Fi"
  default_action = "allow"
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr("sophosfirewall_web_policy.p", "rules"),
					resource.TestCheckResourceAttr("sophosfirewall_web_policy.p", "max_file_size", "300"),
					storedPolicy(env, "Guests", func(o map[string]any) error {
						if len(storedRules(o)) != 1 {
							return fmt.Errorf("rules = %v, want the console rule kept", o["rules"])
						}
						return nil
					}),
				),
			},
		},
	})
}

func TestWebPolicyImportFromFirewall(t *testing.T) {
	env := acctest.New(t)
	env.Server.Seed(webPoliciesPath, map[string]any{
		"name": "Default Workplace Policy", "description": "", "defaultAction": "allow", "maxFileSize": 0,
		"reporting": true, "restrictFileSize": false, "youtubeFilter": "off", "quotaLimit": 60,
		"rules": []any{map[string]any{
			"httpAction": "deny", "httpsAction": "allow", "followHttpAction": false, "enabled": true,
			"usersOrGroups": map[string]any{"users": []any{map[string]any{"id": "u1", "name": "jdoe"}}},
			"activities": map[string]any{
				"dynamicCategories": []any{map[string]any{"id": "d1", "name": "Newly registered"}},
				"userActivities":    []any{map[string]any{"id": "a1", "name": "Not suitable for schools"}},
			},
			"schedule": map[string]any{"id": "s1", "name": "Work hours"},
		}},
	})
	const ds = "data.sophosfirewall_web_policy.default"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{{
			Config: env.Config(`
data "sophosfirewall_web_policy" "default" {
  name = "Default Workplace Policy"
}`),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(ds, "max_file_size", "300"),
				resource.TestCheckResourceAttr(ds, "rules.#", "1"),
				resource.TestCheckResourceAttr(ds, "rules.0.https_action", "allow"),
				resource.TestCheckResourceAttr(ds, "rules.0.follow_http_action", "false"),
				resource.TestCheckResourceAttr(ds, "rules.0.users.0", "jdoe"),
				resource.TestCheckResourceAttr(ds, "rules.0.dynamic_categories.0", "Newly registered"),
				resource.TestCheckResourceAttr(ds, "rules.0.user_activities.0", "Not suitable for schools"),
				resource.TestCheckResourceAttr(ds, "rules.0.schedule", "Work hours"),
				resource.TestCheckNoResourceAttr(ds, "rules.0.categories"),
			),
		}},
	})
}

func TestWebPolicyValidation(t *testing.T) {
	env := acctest.New(t)
	rule := func(body string) string {
		return "\n  rules = [{\n" + body + "\n  }]"
	}
	for name, tc := range map[string]struct{ body, err string }{
		"missing default action":   {``, `default_action`},
		"bad default action":       {`default_action = "warn"`, `value must be one of`},
		"bad youtube filter":       {`default_action = "allow"` + "\n" + `youtube_filter = "on"`, `value must be one of`},
		"quota not multiple of 10": {`default_action = "allow"` + "\n" + `quota_limit = 15`, `must be a multiple of 10`},
		"file size too large":      {`default_action = "allow"` + "\n" + `max_file_size = 2000`, `between 1 and 1536`},
		"bad google domain":        {`default_action = "allow"` + "\n" + `google_app_domains = ["https://example.com"]`, `must be a domain`},
		"google domains too long":  {`default_action = "allow"` + "\n" + `google_app_domains = [` + longDomains(5) + `]`, `List too long`},
		"bad directory id":         {`default_action = "allow"` + "\n" + `office365_directory_id = "a_b"`, `may only contain letters`},
		"empty rules":              {`default_action = "allow"` + "\n  rules = []", `at least 1`},
		"https with follow": {`default_action = "allow"` + rule(`http_action = "deny"
    https_action = "allow"`), `https_action cannot be set while follow_http_action is true`},
		"no https without follow": {`default_action = "allow"` + rule(`http_action = "deny"
    follow_http_action = false`), `https_action is required`},
		"log without content filters": {`default_action = "allow"` + rule(`http_action = "log"`), `log is only accepted`},
		"warn with dynamic categories": {`default_action = "allow"` + rule(`http_action = "warn"
    dynamic_categories = ["d"]`), `accept allow or deny`},
		"allow with content filters": {`default_action = "allow"` + rule(`http_action = "allow"
    apply_content_filters = true
    content_filters = ["c"]`), `accept deny or log`},
		"content filters missing": {`default_action = "allow"` + rule(`http_action = "deny"
    apply_content_filters = true`), `requires content_filters`},
		"content filters without follow": {`default_action = "allow"` + rule(`http_action = "deny"
    https_action = "deny"
    follow_http_action = false
    apply_content_filters = true
    content_filters = ["c"]`), `requires follow_http_action`},
		"content filters with dynamic categories": {`default_action = "allow"` + rule(`http_action = "deny"
    dynamic_categories = ["d"]
    apply_content_filters = true
    content_filters = ["c"]`), `cannot be combined with dynamic_categories`},
		"bad rule action": {`default_action = "allow"` + rule(`http_action = "block"`), `value must be one of`},
	} {
		t.Run(name, func(t *testing.T) {
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: env.Factories,
				Steps: []resource.TestStep{{
					Config:      env.Config(`resource "sophosfirewall_web_policy" "p" {` + "\n  name = \"p\"\n  " + tc.body + "\n}"),
					ExpectError: regexp.MustCompile(tc.err),
				}},
			})
		})
	}
}

// longDomains returns n distinct 64-character domains as HCL list elements.
func longDomains(n int) string {
	var out []string
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("%q", fmt.Sprintf("d%d%s.com", i, strings.Repeat("a", 58))))
	}
	return strings.Join(out, ", ")
}

// patchPolicy changes a policy behind Terraform's back, as the web admin console would.
func patchPolicy(t *testing.T, env *acctest.Env, name string, body map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPatch, env.Server.URL+"/api/firewall-config/v1"+webPoliciesPath+"/"+name, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+sfostest.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := env.Server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH %s: %s", name, resp.Status)
	}
}

// TestWebPolicyInvertedReporting mimics SFOS v23, which stores the inverse
// of the "reporting" value written and inverts it on a PATCH without it.
func TestWebPolicyInvertedReporting(t *testing.T) {
	env := acctest.New(t)
	env.Server.SetAfterWrite(webPoliciesPath, func(obj, body map[string]any) {
		if v, ok := body["reporting"].(bool); ok {
			obj["reporting"] = !v
		} else if v, ok := obj["reporting"].(bool); ok {
			obj["reporting"] = !v
		}
	})
	config := func(reporting bool, desc string) string {
		return env.Config(fmt.Sprintf(`
resource "sophosfirewall_web_policy" "p" {
  name           = "p"
  description    = %q
  default_action = "allow"
  reporting      = %t
  rules          = [{ categories = ["Gambling"], http_action = "deny" }]
}`, desc, reporting))
	}
	reporting := func(want bool) resource.TestCheckFunc {
		return storedPolicy(env, "p", func(o map[string]any) error {
			if o["reporting"] != want {
				return fmt.Errorf("stored reporting = %v, want %v", o["reporting"], want)
			}
			return nil
		})
	}
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{Config: config(true, "a"), Check: reporting(true)},
			{Config: config(true, "b"), Check: reporting(true)}, // PATCH without reporting
			{Config: config(false, "b"), Check: reporting(false)},
			{Config: config(false, "c"), Check: reporting(false)},
		},
	})
}
