// Package acctest runs Terraform test cases against an in-memory fake of the
// SFOS API (see internal/sfostest), so every resource can be exercised end to
// end with a real Terraform binary but without a firewall.
package acctest

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/provider"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfostest"
)

// Env is a fake firewall plus provider factories pointing at it.
type Env struct {
	Server    *sfostest.Server
	Factories map[string]func() (tfprotov6.ProviderServer, error)
}

// New starts a fake firewall with every collection the provider uses.
func New(t *testing.T) *Env {
	t.Helper()
	return &Env{
		Server: sfostest.NewServer(t, Collections()),
		Factories: map[string]func() (tfprotov6.ProviderServer, error){
			"sophosfirewall": providerserver.NewProtocol6WithError(provider.New("test")()),
		},
	}
}

// Config prefixes body with a provider block for the fake firewall.
func (e *Env) Config(body string) string {
	return fmt.Sprintf(`
provider "sophosfirewall" {
  endpoint = %q
  api_key  = %q
  insecure = true
}
`, e.Server.URL, sfostest.APIKey) + body
}

// Collections describes the fake API, including the server-side defaults the
// real firewall fills in for omitted fields.
func Collections() map[string]sfostest.Collection {
	rule := func(defaults map[string]any) sfostest.Collection {
		return sfostest.Collection{WriteOnly: []string{"position", "referenceItem"}, Movable: true, Defaults: defaults}
	}
	return map[string]sfostest.Collection{
		"/network/addresses/ipv4":         {},
		"/network/addresses/ipv6":         {},
		"/network/addresses/mac":          {OnCreate: macType},
		"/network/addresses/fqdn":         {},
		"/network/address-groups/country": {},
		"/network/zones":                  {Defaults: map[string]any{"description": ""}},
		"/firewall/rules/ipv4": rule(map[string]any{
			"logTraffic": false,
			"userAuthentication": map[string]any{
				"excludeUsersFromAccounting": false, "webAuthenticationForUnknownUsers": false,
			},
			"securityFeatures": map[string]any{
				"scanHttpAndDecryptedHttps": false, "zeroDayProtection": false, "scanFtp": false, "webProxy": false,
				"decryptHTTPSWebProxyMode": false, "blockQuicProtocol": false, "webCategoryBasedQosPolicy": false,
				"applicationBasedQosPolicy": false, "scanWithNdrActiveThreatIntelligence": false,
			},
			"emailScanning": map[string]any{"smtp": false, "smtps": false, "imap": false, "imaps": false, "pop3": false, "pop3s": false},
			"synchronizedSecurityHeartbeat": map[string]any{
				"source":      map[string]any{"blockClientsWithNoHeartbeat": false, "minimumLevel": "noRestriction"},
				"destination": map[string]any{"blockClientsWithNoHeartbeat": false, "minimumLevel": "noRestriction"},
			},
			"exclusions": map[string]any{},
		}),
		"/nat/rules/ipv4": rule(map[string]any{
			"linkedFirewallRule":  map[string]any{"name": "none"},
			"loadBalancingMethod": "roundRobin",
		}),
		"/network/interfaces/network-interfaces": {
			Defaults: map[string]any{"mtu": 1500, "mss": 1460},
			OnCreate: func(obj map[string]any) {
				if v, ok := obj["vlanDetails"].(map[string]any); ok && obj["hardwareName"] == nil {
					parent, _ := v["parentInterface"].(map[string]any)
					obj["hardwareName"] = fmt.Sprintf("%v.%v", parent["name"], v["vlanId"])
				}
				if obj["type"] == "vlan" {
					delete(obj, "mtu")
					delete(obj, "mss")
				}
			},
		},
	}
}

func macType(obj map[string]any) {
	if _, ok := obj["macAddresses"]; ok {
		obj["type"] = "macList"
	} else {
		obj["type"] = "macAddress"
	}
}
