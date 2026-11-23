package trafficshaping_test

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/acctest"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfostest"
)

const policiesPath = "/traffic-shaping/policies"

// recorder sits in front of the fake firewall and records PATCH bodies.
type recorder struct {
	*httptest.Server
	mu      sync.Mutex
	patches []map[string]any
}

func newRecorder(t *testing.T, env *acctest.Env) *recorder {
	t.Helper()
	target, err := url.Parse(env.Server.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // test fake
	rec := &recorder{}
	rec.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch && strings.Contains(r.URL.Path, policiesPath) {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
			var m map[string]any
			_ = json.Unmarshal(body, &m)
			rec.mu.Lock()
			rec.patches = append(rec.patches, m)
			rec.mu.Unlock()
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(rec.Close)
	return rec
}

func (r *recorder) config(body string) string {
	return fmt.Sprintf(`
provider "sophosfirewall" {
  endpoint = %q
  api_key  = %q
  insecure = true
}
`, r.URL, sfostest.APIKey) + body
}

func (r *recorder) take() []map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.patches
	r.patches = nil
	return p
}

func TestTrafficShapingPolicyBestEffort(t *testing.T) {
	env := acctest.New(t)
	const addr = "sophosfirewall_traffic_shaping_policy.users"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_traffic_shaping_policy" "users" {
  name            = "Users-Limit"
  associates_with = "users"
  type            = "bestEffort"
  bandwidth = {
    limit = { aggregated_kbps = 10240 }
  }
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(addr, "id"),
					resource.TestCheckResourceAttr(addr, "description", ""),
					resource.TestCheckResourceAttr(addr, "is_shared", "false"),
					resource.TestCheckResourceAttr(addr, "bandwidth.limit.aggregated_kbps", "10240"),
					resource.TestCheckNoResourceAttr(addr, "bandwidth.guaranteed"),
					resource.TestCheckNoResourceAttr(addr, "scheduled_overrides"),
					func(*terraform.State) error {
						o := env.Server.Get(policiesPath, "Users-Limit")
						want := map[string]any{"bestEffort": map[string]any{"aggregatedKbps": float64(10240)}}
						if o["associatesWith"] != "users" || o["isShared"] != false || o["type"] != "bestEffort" || !reflect.DeepEqual(o["bandwidth"], want) {
							t.Errorf("policy on server = %v", o)
						}
						return nil
					},
				),
			},
			{
				// Rates, description and overrides change in place.
				Config: env.Config(`
resource "sophosfirewall_traffic_shaping_policy" "users" {
  name            = "Users-Limit"
  description     = "Per-user cap"
  associates_with = "users"
  type            = "bestEffort"
  bandwidth = {
    limit = { aggregated_kbps = 20480 }
  }
  scheduled_overrides = [
    {
      schedule  = "Work hours (5 Day week)"
      bandwidth = { guaranteed = { aggregated_kbps = 1024 }, limit = { aggregated_kbps = 4096 } }
    },
    {
      schedule  = "All Time On Weekends"
      bandwidth = { limit = { upload_kbps = 512, download_kbps = 2048 } }
    },
  ]
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "bandwidth.limit.aggregated_kbps", "20480"),
					resource.TestCheckResourceAttr(addr, "scheduled_overrides.#", "2"),
					resource.TestCheckResourceAttr(addr, "scheduled_overrides.0.bandwidth.guaranteed.aggregated_kbps", "1024"),
					resource.TestCheckResourceAttr(addr, "scheduled_overrides.1.bandwidth.limit.download_kbps", "2048"),
					resource.TestCheckNoResourceAttr(addr, "scheduled_overrides.1.bandwidth.guaranteed"),
					func(*terraform.State) error {
						o := env.Server.Get(policiesPath, "Users-Limit")
						ov, _ := o["scheduledOverrides"].([]any)
						if o["description"] != "Per-user cap" || len(ov) != 2 {
							t.Errorf("policy on server = %v", o)
						}
						return nil
					},
				),
			},
			{ResourceName: addr, ImportState: true, ImportStateVerify: true},
			{ResourceName: addr, ImportState: true, ImportStateId: "Users-Limit", ImportStateVerify: true},
			{
				// Removing the overrides clears them on the firewall.
				Config: env.Config(`
resource "sophosfirewall_traffic_shaping_policy" "users" {
  name            = "Users-Limit"
  description     = "Per-user cap"
  associates_with = "users"
  type            = "bestEffort"
  bandwidth = {
    limit = { aggregated_kbps = 20480 }
  }
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)},
				},
				Check: func(*terraform.State) error {
					o := env.Server.Get(policiesPath, "Users-Limit")
					if ov, _ := o["scheduledOverrides"].([]any); len(ov) != 0 {
						t.Errorf("overrides not cleared: %v", o)
					}
					return nil
				},
			},
			{
				// Overrides added on the firewall are not drift while unmanaged.
				PreConfig: func() {
					patchServer(t, env, "Users-Limit", map[string]any{"scheduledOverrides": []any{map[string]any{
						"schedule":  map[string]any{"name": "Work hours (5 Day week)"},
						"bandwidth": map[string]any{"bestEffort": map[string]any{"aggregatedKbps": 1024}},
					}}})
				},
				Config: env.Config(`
resource "sophosfirewall_traffic_shaping_policy" "users" {
  name            = "Users-Limit"
  description     = "Per-user cap"
  associates_with = "users"
  type            = "bestEffort"
  bandwidth = {
    limit = { aggregated_kbps = 20480 }
  }
}`),
				PlanOnly: true,
			},
			{
				// The type and the association cannot be patched.
				Config: env.Config(`
resource "sophosfirewall_traffic_shaping_policy" "users" {
  name            = "Users-Limit"
  associates_with = "rules"
  is_shared       = true
  type            = "guaranteed"
  bandwidth = {
    guaranteed = { aggregated_kbps = 5120 }
    limit      = { aggregated_kbps = 20480 }
  }
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionDestroyBeforeCreate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "type", "guaranteed"),
					resource.TestCheckResourceAttr(addr, "is_shared", "true"),
					resource.TestCheckResourceAttr(addr, "bandwidth.guaranteed.aggregated_kbps", "5120"),
				),
			},
		},
	})
}

// patchServer changes an object on the fake firewall behind Terraform's back.
func patchServer(t *testing.T, env *acctest.Env, name string, body map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPatch, env.Server.URL+"/api/firewall-config/v1"+policiesPath+"/"+url.PathEscape(name), bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+sfostest.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := env.Server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		t.Fatalf("PATCH %s: %d %s", name, resp.StatusCode, msg)
	}
}

func TestTrafficShapingPolicyGuaranteedPerDirection(t *testing.T) {
	env := acctest.New(t)
	rec := newRecorder(t, env)
	const addr = "sophosfirewall_traffic_shaping_policy.app"
	cfg := func(minUp, maxDown int) string {
		return rec.config(fmt.Sprintf(`
resource "sophosfirewall_traffic_shaping_policy" "app" {
  name            = "App-Guaranteed"
  associates_with = "applications"
  type            = "guaranteed"
  bandwidth = {
    guaranteed = { upload_kbps = %d, download_kbps = 1024 }
    limit      = { upload_kbps = 2048, download_kbps = %d }
  }
}`, minUp, maxDown))
	}
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: cfg(512, 4096),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "bandwidth.guaranteed.upload_kbps", "512"),
					resource.TestCheckResourceAttr(addr, "bandwidth.limit.download_kbps", "4096"),
					resource.TestCheckNoResourceAttr(addr, "bandwidth.limit.aggregated_kbps"),
					func(*terraform.State) error {
						rec.take()
						return nil
					},
				),
			},
			{
				// Changing one rate sends the complete bandwidth object, since
				// min/max and upload/download are only valid as pairs.
				Config: cfg(768, 4096),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)},
				},
				Check: func(*terraform.State) error {
					want := []map[string]any{{"bandwidth": map[string]any{"guaranteed": map[string]any{
						"min": map[string]any{"uploadKbps": float64(768), "downloadKbps": float64(1024)},
						"max": map[string]any{"uploadKbps": float64(2048), "downloadKbps": float64(4096)},
					}}}}
					if got := rec.take(); !reflect.DeepEqual(got, want) {
						t.Errorf("PATCH bodies = %v\nwant %v", got, want)
					}
					return nil
				},
			},
			{ResourceName: addr, ImportState: true, ImportStateVerify: true},
			{
				// The direction scope cannot be patched.
				Config: rec.config(`
resource "sophosfirewall_traffic_shaping_policy" "app" {
  name            = "App-Guaranteed"
  associates_with = "applications"
  type            = "guaranteed"
  bandwidth = {
    guaranteed = { aggregated_kbps = 1024 }
    limit      = { aggregated_kbps = 4096 }
  }
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionDestroyBeforeCreate)},
				},
				Check: resource.TestCheckResourceAttr(addr, "bandwidth.limit.aggregated_kbps", "4096"),
			},
		},
	})
}

// TestTrafficShapingPolicyFirewallRule references a policy from a rule's QoS settings.
func TestTrafficShapingPolicyFirewallRule(t *testing.T) {
	env := acctest.New(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_traffic_shaping_policy" "rules" {
  name            = "Rules-Shared"
  associates_with = "rules"
  is_shared       = true
  type            = "bestEffort"
  bandwidth = {
    limit = { upload_kbps = 2048, download_kbps = 8192 }
  }
}

resource "sophosfirewall_firewall_rule" "web" {
  name              = "shaped-web"
  source_zones      = ["LAN"]
  destination_zones = ["WAN"]
  services          = ["HTTPS"]
  qos = {
    traffic_shaping_policy = sophosfirewall_traffic_shaping_policy.rules.name
  }
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("sophosfirewall_firewall_rule.web", "qos.traffic_shaping_policy", "Rules-Shared"),
					func(*terraform.State) error {
						r := env.Server.Get("/firewall/rules/ipv4", "shaped-web")
						q, _ := r["qos"].(map[string]any)
						if !reflect.DeepEqual(q["trafficShapingPolicy"], map[string]any{"name": "Rules-Shared"}) {
							t.Errorf("rule qos on server = %v", r["qos"])
						}
						return nil
					},
				),
			},
		},
	})
}

func TestTrafficShapingPolicyDataSource(t *testing.T) {
	env := acctest.New(t)
	env.Server.Seed(policiesPath, map[string]any{
		"name": "Web-Guaranteed", "associatesWith": "webCategories", "isShared": true, "type": "guaranteed", "description": "",
		"bandwidth": map[string]any{"guaranteed": map[string]any{
			"min": map[string]any{"aggregatedKbps": 5120}, "max": map[string]any{"aggregatedKbps": 10240},
		}},
		"scheduledOverrides": []any{map[string]any{
			"schedule":  map[string]any{"id": "sched-001", "name": "Work hours (5 Day week)"},
			"bandwidth": map[string]any{"bestEffort": map[string]any{"uploadKbps": 2048, "downloadKbps": 4096}},
		}},
	})
	const ds = "data.sophosfirewall_traffic_shaping_policy.web"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{{
			Config: env.Config(`data "sophosfirewall_traffic_shaping_policy" "web" { name = "Web-Guaranteed" }`),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet(ds, "id"),
				resource.TestCheckResourceAttr(ds, "associates_with", "webCategories"),
				resource.TestCheckResourceAttr(ds, "is_shared", "true"),
				resource.TestCheckResourceAttr(ds, "bandwidth.guaranteed.aggregated_kbps", "5120"),
				resource.TestCheckResourceAttr(ds, "bandwidth.limit.aggregated_kbps", "10240"),
				resource.TestCheckResourceAttr(ds, "scheduled_overrides.#", "1"),
				resource.TestCheckResourceAttr(ds, "scheduled_overrides.0.schedule", "Work hours (5 Day week)"),
				resource.TestCheckResourceAttr(ds, "scheduled_overrides.0.bandwidth.limit.upload_kbps", "2048"),
			),
		}},
	})
}

func TestTrafficShapingPolicyValidation(t *testing.T) {
	env := acctest.New(t)
	cfg := func(body string) string {
		return env.Config(`
resource "sophosfirewall_traffic_shaping_policy" "t" {
  name            = "t"
  associates_with = "rules"
` + body + `
}`)
	}
	steps := []struct{ body, err string }{
		{`type = "limit"` + "\nbandwidth = { limit = { aggregated_kbps = 1024 } }", `value must be one of`},
		{`type = "guaranteed"` + "\nbandwidth = { limit = { aggregated_kbps = 1024 } }", `"guaranteed" is required when type is "guaranteed"`},
		{`type = "bestEffort"` + "\nbandwidth = { guaranteed = { aggregated_kbps = 512 }, limit = { aggregated_kbps = 1024 } }", `"guaranteed" can only be set when type is\s+"guaranteed"`},
		{`type = "bestEffort"` + "\nbandwidth = { limit = {} }", `Set either aggregated_kbps, or both upload_kbps and\s+download_kbps`},
		{`type = "bestEffort"` + "\nbandwidth = { limit = { aggregated_kbps = 1024, upload_kbps = 512 } }", `not both`},
		{`type = "bestEffort"` + "\nbandwidth = { limit = { upload_kbps = 512 } }", `must be set together`},
		{`type = "bestEffort"` + "\nbandwidth = { limit = { aggregated_kbps = 8 } }", `must be between 16 and\s+20480000`},
		{`type = "guaranteed"` + "\nbandwidth = { guaranteed = { aggregated_kbps = 512 }, limit = { upload_kbps = 512, download_kbps = 512 } }", `must both use aggregated_kbps`},
		{`type = "guaranteed"` + "\nbandwidth = { guaranteed = { aggregated_kbps = 2048 }, limit = { aggregated_kbps = 1024 } }", `must not exceed limit`},
		{`type = "bestEffort"` + "\nbandwidth = { limit = { aggregated_kbps = 1024 } }\nscheduled_overrides = []", `at least 1`},
		{`type = "bestEffort"` + "\nbandwidth = { limit = { aggregated_kbps = 1024 } }\n" +
			`scheduled_overrides = [{ schedule = "s", bandwidth = { guaranteed = { aggregated_kbps = 4096 }, limit = { aggregated_kbps = 1024 } } }]`, `must not exceed limit`},
	}
	var ts []resource.TestStep
	for _, s := range steps {
		ts = append(ts, resource.TestStep{Config: cfg(s.body), ExpectError: regexp.MustCompile(s.err), PlanOnly: true})
	}
	resource.UnitTest(t, resource.TestCase{ProtoV6ProviderFactories: env.Factories, Steps: ts})
}
