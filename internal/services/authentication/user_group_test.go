package authentication_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/acctest"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfostest"
)

const groupsPath = "/authentication/user-groups"

func TestUserGroup(t *testing.T) {
	env := acctest.New(t)
	const addr = "sophosfirewall_user_group.eng"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_user_group" "eng" {
  name                 = "Engineering"
  surfing_quota_policy = "Unlimited Internet Access"
  access_time_policy   = "Allowed all the time"
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(addr, "id"),
					resource.TestCheckResourceAttr(addr, "description", ""),
					resource.TestCheckResourceAttr(addr, "mac_binding", "false"),
					resource.TestCheckResourceAttr(addr, "l2tp", "false"),
					resource.TestCheckNoResourceAttr(addr, "ssl_vpn_policy"),
					func(*terraform.State) error {
						o := env.Server.Get(groupsPath, "Engineering")
						p := o["policies"].(map[string]any)
						if fmt.Sprint(p["allowedNetworksIpv4"]) != "map[any:true]" || fmt.Sprint(p["surfingQuotaPolicy"]) != "map[name:Unlimited Internet Access]" {
							return fmt.Errorf("stored policies = %v", p)
						}
						return nil
					},
				),
			},
			{
				Config: env.Config(`
resource "sophosfirewall_user_group" "eng" {
  name                         = "Engineering"
  description                  = "Engineering staff"
  surfing_quota_policy         = "Daily 8 hours"
  access_time_policy           = "Work hours (5 Day week)"
  network_traffic_quota_policy = "100 MB Total Traffic"
  traffic_shaping_policy       = "Engineering 10 Mbps"
  mac_binding                  = true
  quarantine_digest            = true
  ssl_vpn_policy               = "Remote engineers"
  clientless_policy            = "Engineering portal"
  l2tp                         = true
  ipsec_remote_access          = true
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "ssl_vpn_policy", "Remote engineers"),
					resource.TestCheckResourceAttr(addr, "network_traffic_quota_policy", "100 MB Total Traffic"),
					func(*terraform.State) error {
						o := env.Server.Get(groupsPath, "Engineering")
						v := o["vpnAccess"].(map[string]any)
						if v["l2tp"] != true || v["pptp"] != false || v["ipsecVpnRemoteAccess"] != true || o["emailQuarantineDigest"] != true {
							return fmt.Errorf("stored vpnAccess = %v", o)
						}
						return nil
					},
				),
			},
			{ResourceName: addr, ImportState: true, ImportStateVerify: true},
			{
				// Switch the login restriction to a range and drop optional policies.
				Config: env.Config(`
resource "sophosfirewall_user_group" "eng" {
  name                 = "Engineering"
  surfing_quota_policy = "Daily 8 hours"
  access_time_policy   = "Work hours (5 Day week)"
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr(addr, "ssl_vpn_policy"),
					resource.TestCheckNoResourceAttr(addr, "network_traffic_quota_policy"),
					func(*terraform.State) error {
						o := env.Server.Get(groupsPath, "Engineering")
						p := o["policies"].(map[string]any)
						if _, ok := p["trafficShapingPolicy"]; ok {
							return fmt.Errorf("trafficShapingPolicy not cleared: %v", p)
						}
						if _, ok := o["vpnAccess"].(map[string]any)["sslVpnRemoteAccessPolicy"]; ok {
							return fmt.Errorf("sslVpnRemoteAccessPolicy not cleared: %v", o["vpnAccess"])
						}
						return nil
					},
				),
			},
			{
				// Back to "any address".
				Config: env.Config(`
resource "sophosfirewall_user_group" "eng" {
  name                 = "Engineering"
  surfing_quota_policy = "Daily 8 hours"
  access_time_policy   = "Work hours (5 Day week)"
}`),
				Check: func(*terraform.State) error {
					a := env.Server.Get(groupsPath, "Engineering")["policies"].(map[string]any)["allowedNetworksIpv4"]
					if fmt.Sprint(a) != "map[any:true]" {
						return fmt.Errorf("allowedNetworksIpv4 = %v", a)
					}
					return nil
				},
			},
			{
				// The name cannot be patched.
				Config: env.Config(`
resource "sophosfirewall_user_group" "eng" {
  name                 = "Engineers"
  surfing_quota_policy = "Daily 8 hours"
  access_time_policy   = "Work hours (5 Day week)"
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionDestroyBeforeCreate)},
				},
			},
		},
	})
}

func TestUserGroupUnmanagedPolicies(t *testing.T) {
	env := acctest.New(t)
	config := env.Config(`
resource "sophosfirewall_user_group" "g" {
  name                 = "Sales"
  surfing_quota_policy = "Unlimited Internet Access"
  access_time_policy   = "Allowed all the time"
}`)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{Config: config},
			{
				// The firewall assigns a traffic shaping policy by itself: not drift.
				PreConfig: func() {
					// The fake treats a nested patch without common keys as a
					// oneOf branch switch, so send the complete policies object.
					policies := env.Server.Get(groupsPath, "Sales")["policies"].(map[string]any)
					policies["trafficShapingPolicy"] = map[string]any{"name": "Default"}
					patch(t, env, groupsPath+"/Sales", map[string]any{"policies": policies})
				},
				Config:   config,
				PlanOnly: true,
			},
		},
	})
}

// patch changes an object behind Terraform's back, as the firewall would.
func patch(t *testing.T, env *acctest.Env, item string, body map[string]any) {
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
		t.Fatalf("PATCH %s: %s", item, resp.Status)
	}
}

func TestUserGroupDataSourceBuiltIn(t *testing.T) {
	env := acctest.New(t)
	env.Server.Seed(groupsPath, map[string]any{
		"name": "Open Group", "description": "",
		"policies": map[string]any{
			"surfingQuotaPolicy":        map[string]any{"name": "Unlimited Internet Access"},
			"accessTimePolicy":          map[string]any{"name": "Allowed all the time"},
			"networkTrafficQuotaPolicy": map[string]any{"name": "Unlimited Internet Access"},
			"allowedNetworksIpv4":       map[string]any{"any": true},
			"macBinding":                false,
		},
		"vpnAccess":             map[string]any{"l2tp": false, "pptp": false, "ipsecVpnRemoteAccess": false, "sslVpnRemoteAccessPolicy": map[string]any{"name": "SSL VPN"}},
		"emailQuarantineDigest": true,
	})
	const ds = "data.sophosfirewall_user_group.open"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{{
			Config: env.Config(`data "sophosfirewall_user_group" "open" { name = "Open Group" }`),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet(ds, "id"),
				resource.TestCheckResourceAttr(ds, "surfing_quota_policy", "Unlimited Internet Access"),
				resource.TestCheckResourceAttr(ds, "access_time_policy", "Allowed all the time"),
				resource.TestCheckResourceAttr(ds, "network_traffic_quota_policy", "Unlimited Internet Access"),
				resource.TestCheckResourceAttr(ds, "ssl_vpn_policy", "SSL VPN"),
				resource.TestCheckResourceAttr(ds, "quarantine_digest", "true"),
			),
		}},
	})
}

func TestUserGroupValidation(t *testing.T) {
	env := acctest.New(t)
	cases := map[string]struct {
		body string
		err  string
	}{
		"missing access time": {`
  surfing_quota_policy = "Unlimited Internet Access"`, `access_time_policy`},
		"bad policy name": {`
  ssl_vpn_policy = "a,b"`, `not a valid SFOS object name`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			body := c.body
			if !strings.Contains(body, "surfing_quota_policy") {
				body = `
  surfing_quota_policy = "Unlimited Internet Access"
  access_time_policy   = "Allowed all the time"` + body
			}
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: env.Factories,
				Steps: []resource.TestStep{{
					Config:      env.Config("resource \"sophosfirewall_user_group\" \"t\" {\n  name = \"t\"" + body + "\n}\n"),
					ExpectError: regexp.MustCompile(strings.ReplaceAll(c.err, " ", `\s+`)),
				}},
			})
		})
	}
}
