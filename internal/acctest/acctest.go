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
		"/network/address-groups/ipv4":    {Defaults: map[string]any{"description": "", "ipv4Addresses": []any{}}},
		"/network/address-groups/ipv6":    {Defaults: map[string]any{"description": "", "ipv6Addresses": []any{}}},
		"/network/address-groups/fqdn":    {Defaults: map[string]any{"description": "", "fqdns": []any{}}},
		"/network/services":               {OnCreate: servicePorts},
		"/network/service-groups":         {},
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
		"/network/dhcp/server/servers/ipv4": {
			Defaults: map[string]any{"enabled": true, "acceptRelayRequests": false, "conflictDetection": false},
			OnCreate: dhcpOptionTypes,
		},
		"/authentication/user-groups":         {OnCreate: userGroupDefaults},
		"/routing/static-unicast-routes/ipv4": {Defaults: map[string]any{"metric": 0, "administrativeDistance": 1}},
		"/routing/gateways/custom/ipv4":       {OnCreate: gatewayHealthCheckDefaults},
		"/sd-wan/routes/ipv4": rule(map[string]any{
			"enabled":       true,
			"applications":  map[string]any{"any": true},
			"usersOrGroups": map[string]any{"any": true},
		}),
		"/network/dns/host-entries": {Defaults: map[string]any{"enableReverseResolution": false}},
		"/web/url-groups":           {Defaults: map[string]any{"description": ""}},
		"/web/exceptions":           {OnCreate: webExceptionDefaults},
		"/web/policies": {Defaults: map[string]any{
			"description": "", "reporting": true, "restrictFileSize": false, "enforceSafeSearch": false,
			"filterByImageLicense": false, "youtubeFilter": "off", "quotaLimit": 60, "propagateXForwardedFor": false,
			"restrictGoogleAppDomains": false, "restrictOffice365Tenants": false,
		}},
		"/administration/schedules": {Defaults: map[string]any{"description": ""}},

		// IPS policies; the rule lists are stored and returned as sent.
		"/intrusion-prevention/policies": {Defaults: map[string]any{"description": ""}},
		"/traffic-shaping/policies":      {Defaults: map[string]any{"description": ""}},
		"/application/policies":          {OnCreate: appPolicyDefaults},
	}
}

// appPolicyDefaults mimics the firewall for a new application filter
// policy: an empty description, server-assigned rule ids, and the implicit
// "Cloud Application" characteristics row added to classification filters.
func appPolicyDefaults(obj map[string]any) {
	if _, ok := obj["description"]; !ok {
		obj["description"] = ""
	}
	rules, _ := obj["rules"].([]any)
	for i, r := range rules {
		rule := r.(map[string]any)
		rule["id"] = fmt.Sprintf("10000000-0000-4000-8000-%012d", i+1)
		filters, _ := rule["applicationFilters"].([]any)
		hasClassification, hasCharacteristics := false, false
		for _, f := range filters {
			switch f.(map[string]any)["attribute"] {
			case "classification":
				hasClassification = true
			case "characteristics":
				hasCharacteristics = true
			}
		}
		if hasClassification && !hasCharacteristics {
			rule["applicationFilters"] = append(filters, map[string]any{
				"attribute": "characteristics", "operator": "in", "values": []any{"Cloud Application"},
			})
		}
	}
}

func macType(obj map[string]any) {
	if _, ok := obj["macAddresses"]; ok {
		obj["type"] = "macList"
	} else {
		obj["type"] = "macAddress"
	}
}

// servicePorts fills in the port ranges the firewall assumes for TCP/UDP
// service entries that omit them, and reports single ports as from == to.
func servicePorts(obj map[string]any) {
	entries, _ := obj["services"].([]any)
	for _, e := range entries {
		entry, ok := e.(map[string]any)
		if !ok || entry["protocol"] == nil {
			continue
		}
		for _, k := range []string{"sourcePort", "destinationPort"} {
			port, ok := entry[k].(map[string]any)
			switch {
			case !ok:
				entry[k] = map[string]any{"from": 1, "to": 65535}
			case port["from"] == nil:
				port["from"] = port["to"]
			}
		}
	}
}

// dhcpOptionTypes resolves the name and type of DHCP options like the
// firewall does, for a few standard codes.
func dhcpOptionTypes(obj map[string]any) {
	standard := map[float64][2]string{15: {"Domain_Name", "fqdn"}, 42: {"NTP_Servers", "ipv4AddrArray"}, 66: {"TFTP_Server_Name", "string"}}
	opts, _ := obj["dhcpOptions"].([]any)
	for _, o := range opts {
		opt := o.(map[string]any)
		if std, ok := standard[opt["code"].(float64)]; ok {
			opt["option"], opt["type"] = std[0], std[1]
		} else {
			opt["option"] = "Custom"
		}
	}
}

// userGroupDefaults fills in the policy and VPN settings the firewall
// always returns for a user group.
func userGroupDefaults(obj map[string]any) {
	if _, ok := obj["description"]; !ok {
		obj["description"] = ""
	}
	if _, ok := obj["emailQuarantineDigest"]; !ok {
		obj["emailQuarantineDigest"] = false
	}
	policies, _ := obj["policies"].(map[string]any)
	if policies == nil {
		policies = map[string]any{}
		obj["policies"] = policies
	}
	for k, v := range map[string]any{"allowedNetworksIpv4": map[string]any{"any": true}, "macBinding": false} {
		if _, ok := policies[k]; !ok {
			policies[k] = v
		}
	}
	vpn, _ := obj["vpnAccess"].(map[string]any)
	if vpn == nil {
		vpn = map[string]any{}
		obj["vpnAccess"] = vpn
	}
	for _, k := range []string{"l2tp", "pptp", "ipsecVpnRemoteAccess"} {
		if _, ok := vpn[k]; !ok {
			vpn[k] = false
		}
	}
}

// webExceptionDefaults fills in what the firewall always returns for a web
// exception: every condition (switched off unless given) and every skip flag.
func webExceptionDefaults(obj map[string]any) {
	fill := func(m map[string]any, defaults map[string]any) {
		for k, v := range defaults {
			if _, ok := m[k]; !ok {
				m[k] = v
			}
		}
	}
	child := func(m map[string]any, k string) map[string]any {
		c, _ := m[k].(map[string]any)
		if c == nil {
			c = map[string]any{}
			m[k] = c
		}
		return c
	}
	fill(obj, map[string]any{"description": "", "enabled": true})
	conditions := child(obj, "conditions")
	for _, k := range []string{"sourceIpOrNetworks", "destinationIpOrNetworks"} {
		fill(child(conditions, k), map[string]any{"enabled": false, "ipv4Networks": []any{}, "ipv6Networks": []any{}})
	}
	for _, k := range []string{"urlRegexPatterns", "webCategories"} {
		fill(child(conditions, k), map[string]any{"enabled": false, "values": []any{}})
	}
	fill(child(obj, "skip"), map[string]any{
		"httpsDecryption": false, "certificateValidation": false, "malwareScanning": false,
		"zeroDayProtection": false, "policyCheck": false,
	})
}

// gatewayHealthCheckDefaults fills in the firewall's health check defaults
// (60 s interval, 2 s timeout, 3 retries) for a new custom gateway.
func gatewayHealthCheckDefaults(obj map[string]any) {
	hc, ok := obj["healthCheck"].(map[string]any)
	if !ok {
		hc = map[string]any{"enabled": false}
		obj["healthCheck"] = hc
	}
	for k, v := range map[string]any{"intervalBetweenChecks": 60, "responseTimeout": 2, "retries": 3} {
		if _, ok := hc[k]; !ok {
			hc[k] = v
		}
	}
}
