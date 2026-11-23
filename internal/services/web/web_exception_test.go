package web_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/acctest"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfostest"
)

const exceptionsPath = "/web/exceptions"

// serverField checks a value of the stored exception, addressed by keys.
func serverField(env *acctest.Env, name string, want any, keys ...string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		var v any = env.Server.Get(exceptionsPath, name)
		for _, k := range keys {
			m, _ := v.(map[string]any)
			v = m[k]
		}
		if !reflect.DeepEqual(v, want) {
			return fmt.Errorf("%v on server = %#v, want %#v", keys, v, want)
		}
		return nil
	}
}

func TestWebException(t *testing.T) {
	env := acctest.New(t)
	const addr = "sophosfirewall_web_exception.bank"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_web_exception" "bank" {
  name = "Banking"
  conditions = {
    url_regexes     = ["^([A-Za-z0-9.-]*\\.)?bank\\.example/"]
    source_networks = ["192.0.2.0/24", "2001:db8::/32"]
  }
  skip = {
    https_decryption       = true
    certificate_validation = true
  }
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(addr, "id"),
					resource.TestCheckResourceAttr(addr, "description", ""),
					resource.TestCheckResourceAttr(addr, "enabled", "true"),
					resource.TestCheckResourceAttr(addr, "conditions.url_regexes.#", "1"),
					resource.TestCheckResourceAttr(addr, "conditions.source_networks.#", "2"),
					resource.TestCheckNoResourceAttr(addr, "conditions.web_categories"),
					resource.TestCheckNoResourceAttr(addr, "conditions.destination_networks"),
					resource.TestCheckResourceAttr(addr, "skip.https_decryption", "true"),
					resource.TestCheckResourceAttr(addr, "skip.malware_scanning", "false"),
					resource.TestCheckResourceAttr(addr, "skip.policy_check", "false"),
					serverField(env, "Banking", true, "conditions", "sourceIpOrNetworks", "enabled"),
					serverField(env, "Banking", []any{map[string]any{"ipv4Address": "192.0.2.0", "cidr": float64(24)}},
						"conditions", "sourceIpOrNetworks", "ipv4Networks"),
					serverField(env, "Banking", []any{map[string]any{"ipv6Address": "2001:db8::", "prefixLength": float64(32)}},
						"conditions", "sourceIpOrNetworks", "ipv6Networks"),
					serverField(env, "Banking", false, "conditions", "destinationIpOrNetworks", "enabled"),
					serverField(env, "Banking", false, "conditions", "webCategories", "enabled"),
					serverField(env, "Banking", true, "conditions", "urlRegexPatterns", "enabled"),
					serverField(env, "Banking", true, "skip", "certificateValidation"),
					serverField(env, "Banking", false, "skip", "zeroDayProtection"),
				),
			},
			{
				// Reordering a set is not a change.
				Config: env.Config(`
resource "sophosfirewall_web_exception" "bank" {
  name = "Banking"
  conditions = {
    source_networks = ["2001:db8::/32", "192.0.2.0/24"]
    url_regexes     = ["^([A-Za-z0-9.-]*\\.)?bank\\.example/"]
  }
  skip = {
    certificate_validation = true
    https_decryption       = true
  }
}`),
				PlanOnly: true,
			},
			{
				// Rename, switch conditions on and off and change skip flags in place.
				Config: env.Config(`
resource "sophosfirewall_web_exception" "bank" {
  name        = "Online-Banking"
  description = "Do not decrypt banking sites"
  enabled     = false
  conditions = {
    url_regexes          = ["^([A-Za-z0-9.-]*\\.)?bank\\.example/"]
    web_categories       = ["Banking"]
    destination_networks = ["198.51.100.10/32"]
  }
  skip = {
    https_decryption       = true
    certificate_validation = true
    malware_scanning       = true
  }
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "name", "Online-Banking"),
					resource.TestCheckResourceAttr(addr, "enabled", "false"),
					resource.TestCheckNoResourceAttr(addr, "conditions.source_networks"),
					resource.TestCheckTypeSetElemAttr(addr, "conditions.web_categories.*", "Banking"),
					resource.TestCheckTypeSetElemAttr(addr, "conditions.destination_networks.*", "198.51.100.10/32"),
					resource.TestCheckResourceAttr(addr, "skip.malware_scanning", "true"),
					serverField(env, "Online-Banking", false, "enabled"),
					serverField(env, "Online-Banking", false, "conditions", "sourceIpOrNetworks", "enabled"),
					serverField(env, "Online-Banking", []any{}, "conditions", "sourceIpOrNetworks", "ipv4Networks"),
					serverField(env, "Online-Banking", []any{map[string]any{"name": "Banking"}}, "conditions", "webCategories", "values"),
					serverField(env, "Online-Banking", []any{map[string]any{"ipv4Address": "198.51.100.10", "cidr": float64(32)}},
						"conditions", "destinationIpOrNetworks", "ipv4Networks"),
					serverField(env, "Online-Banking", true, "skip", "malwareScanning"),
				),
			},
			{ResourceName: addr, ImportState: true, ImportStateVerify: true},
			{ResourceName: addr, ImportState: true, ImportStateId: "Online-Banking", ImportStateVerify: true},
			{
				// Dropping the skip block resets every flag and stops tracking them.
				Config: env.Config(`
resource "sophosfirewall_web_exception" "bank" {
  name        = "Online-Banking"
  description = "Do not decrypt banking sites"
  enabled     = false
  conditions = {
    url_regexes          = ["^([A-Za-z0-9.-]*\\.)?bank\\.example/"]
    web_categories       = ["Banking"]
    destination_networks = ["198.51.100.10/32"]
  }
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr(addr, "skip"),
					serverField(env, "Online-Banking", false, "skip", "httpsDecryption"),
					serverField(env, "Online-Banking", false, "skip", "malwareScanning"),
				),
			},
		},
	})
}

// TestWebExceptionUnmanagedSkip checks that skip flags changed outside
// Terraform are not drift while the skip block is not configured.
func TestWebExceptionUnmanagedSkip(t *testing.T) {
	env := acctest.New(t)
	config := env.Config(`
resource "sophosfirewall_web_exception" "updates" {
  name = "Updates"
  conditions = {
    destination_networks = ["203.0.113.0/24"]
  }
}`)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{Config: config, Check: resource.TestCheckNoResourceAttr("sophosfirewall_web_exception.updates", "skip")},
			{
				PreConfig: func() {
					patchItem(t, env, exceptionsPath+"/Updates", map[string]any{"skip": map[string]any{"malwareScanning": true}})
				},
				Config:   config,
				PlanOnly: true,
			},
		},
	})
}

func TestWebExceptionDataSource(t *testing.T) {
	env := acctest.New(t)
	env.Server.Seed(exceptionsPath, map[string]any{
		"name": "Trusted", "description": "Trusted sites", "enabled": true,
		"conditions": map[string]any{
			"sourceIpOrNetworks": map[string]any{"enabled": false},
			"destinationIpOrNetworks": map[string]any{
				"enabled":      true,
				"ipv4Networks": []any{map[string]any{"ipv4Address": "203.0.113.5"}},
				"ipv6Networks": []any{map[string]any{"ipv6Address": "2001:db8:0:0::1", "prefixLength": 64}},
			},
			"urlRegexPatterns": map[string]any{"enabled": false, "values": []any{"ignored"}},
			"webCategories": map[string]any{
				"enabled": true,
				"values":  []any{map[string]any{"id": "00000000-0000-4000-8000-999999999999", "name": "Software Updates"}},
			},
		},
		"skip": map[string]any{
			"httpsDecryption": false, "certificateValidation": false, "malwareScanning": true,
			"zeroDayProtection": true, "policyCheck": false,
		},
	})
	const ds = "data.sophosfirewall_web_exception.trusted"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{{
			Config: env.Config(`data "sophosfirewall_web_exception" "trusted" { name = "Trusted" }`),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet(ds, "id"),
				resource.TestCheckResourceAttr(ds, "description", "Trusted sites"),
				resource.TestCheckResourceAttr(ds, "enabled", "true"),
				// A switched-off condition is null even if values are stored.
				resource.TestCheckNoResourceAttr(ds, "conditions.url_regexes"),
				resource.TestCheckNoResourceAttr(ds, "conditions.source_networks"),
				resource.TestCheckResourceAttr(ds, "conditions.destination_networks.#", "2"),
				// Omitted prefix lengths default to /32 and /128.
				resource.TestCheckTypeSetElemAttr(ds, "conditions.destination_networks.*", "203.0.113.5/32"),
				resource.TestCheckTypeSetElemAttr(ds, "conditions.destination_networks.*", "2001:db8::1/64"),
				resource.TestCheckTypeSetElemAttr(ds, "conditions.web_categories.*", "Software Updates"),
				resource.TestCheckResourceAttr(ds, "skip.malware_scanning", "true"),
				resource.TestCheckResourceAttr(ds, "skip.zero_day_protection", "true"),
				resource.TestCheckResourceAttr(ds, "skip.https_decryption", "false"),
			),
		}},
	})
}

func TestWebExceptionValidation(t *testing.T) {
	env := acctest.New(t)
	cfg := func(conditions string) string {
		return env.Config(fmt.Sprintf(`
resource "sophosfirewall_web_exception" "t" {
  name       = "t"
  conditions = %s
}`, conditions))
	}
	steps := []resource.TestStep{
		{Config: cfg(`{}`), ExpectError: regexp.MustCompile(`Set at least one of url_regexes`), PlanOnly: true},
		{Config: cfg(`{ url_regexes = [] }`), ExpectError: regexp.MustCompile(`at least 1`), PlanOnly: true},
		{Config: cfg(`{ web_categories = ["a,b"] }`), ExpectError: regexp.MustCompile(`not a valid SFOS object name`), PlanOnly: true},
		{
			Config:      env.Config(`resource "sophosfirewall_web_exception" "t" { name = "t" }`),
			ExpectError: regexp.MustCompile(`"conditions" is required`), PlanOnly: true,
		},
		{
			Config: env.Config(fmt.Sprintf(`
resource "sophosfirewall_web_exception" "t" {
  name        = "t"
  description = %q
  conditions  = { url_regexes = ["x"] }
}`, string(bytes.Repeat([]byte("a"), 251)))),
			ExpectError: regexp.MustCompile(`length must be at most 250`), PlanOnly: true,
		},
		{
			// Found on a live firewall: skipping decryption always skips validation.
			Config: env.Config(`
resource "sophosfirewall_web_exception" "t" {
  name       = "t"
  conditions = { url_regexes = ["x"] }
  skip       = { https_decryption = true }
}`),
			ExpectError: regexp.MustCompile(`Set certificate_validation = true`), PlanOnly: true,
		},
	}
	for bad, msg := range map[string]string{
		"192.0.2.1":      `not an IPv4 or IPv6 network in CIDR notation`,
		"192.0.2.1/24":   `must be the canonical network address "192.0.2.0/24"`,
		"192.0.2.0/33":   `not an IPv4 or IPv6 network`,
		"2001:DB8::/32":  `must be the canonical network address "2001:db8::/32"`,
		"example.com/32": `not an IPv4 or IPv6 network`,
	} {
		steps = append(steps, resource.TestStep{
			Config:      cfg(fmt.Sprintf(`{ source_networks = [%q] }`, bad)),
			ExpectError: regexp.MustCompile(regexp.QuoteMeta(msg)), PlanOnly: true,
		})
	}
	resource.UnitTest(t, resource.TestCase{ProtoV6ProviderFactories: env.Factories, Steps: steps})
}

// patchItem changes an object behind Terraform's back, as the firewall would.
func patchItem(t *testing.T, env *acctest.Env, item string, body map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPatch, env.Server.URL+"/api/firewall-config/v1"+item, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+sfostest.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := env.Server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH %s: HTTP %d", item, resp.StatusCode)
	}
}
