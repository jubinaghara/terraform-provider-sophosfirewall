package dhcp_test

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

const serversPath = "/network/dhcp/server/servers/ipv4"

func TestDHCPServer(t *testing.T) {
	env := acctest.New(t)
	const addr = "sophosfirewall_dhcp_server.lan"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_dhcp_server" "lan" {
  name               = "LAN DHCP"
  interface          = "Port1"
  prefix_length      = 24
  gateway            = "192.168.1.1"
  default_lease_time = 1440
  max_lease_time     = 2880
  domain_name        = "branch.local"
  primary_dns        = "192.168.1.1"
  secondary_dns      = "1.1.1.1"
  boot_server        = "192.168.1.20"
  boot_file          = "pxelinux.0"

  address_pools = [
    { start_address = "192.168.1.100", end_address = "192.168.1.150" },
    { start_address = "192.168.1.200", end_address = "192.168.1.220" },
  ]
  static_mappings = [
    { mac_address = "00:11:22:33:44:55", ip_address = "192.168.1.50", hostname = "printer-01" },
  ]
  dhcp_options = [
    { code = 66, value = "tftp.branch.local" },
    { code = 150, type = "ipv4Addr", value = "192.168.1.20" },
  ]
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(addr, "id"),
					resource.TestCheckResourceAttr(addr, "enabled", "true"),
					resource.TestCheckResourceAttr(addr, "address_pools.#", "2"),
					resource.TestCheckResourceAttr(addr, "static_mappings.#", "1"),
					resource.TestCheckResourceAttr(addr, "conflict_detection", "false"),
					resource.TestCheckResourceAttr(addr, "accept_relay_requests", "false"),
					// The firewall resolves the type of option 66, but it stays out of state.
					resource.TestCheckTypeSetElemNestedAttrs(addr, "dhcp_options.*", map[string]string{"code": "66", "value": "tftp.branch.local"}),
					resource.TestCheckTypeSetElemNestedAttrs(addr, "dhcp_options.*", map[string]string{"code": "150", "type": "ipv4Addr"}),
					func(*terraform.State) error {
						o := env.Server.Get(serversPath, "LAN DHCP")
						if o["cidr"] != float64(24) || o["gatewayIpv4"] != "192.168.1.1" || o["primaryDnsIpv4"] != "192.168.1.1" {
							return fmt.Errorf("stored server = %v", o)
						}
						if b := o["bootNextServer"].(map[string]any); b["ipv4Address"] != "192.168.1.20" {
							return fmt.Errorf("bootNextServer = %v", b)
						}
						if _, ok := o["enabled"].(bool); !ok {
							return fmt.Errorf("enabled default missing")
						}
						return nil
					},
				),
			},
			{
				// Re-planning the same configuration must be a no-op (no drift
				// from the option type the firewall filled in).
				Config: env.Config(`
resource "sophosfirewall_dhcp_server" "lan" {
  name               = "LAN DHCP"
  interface          = "Port1"
  prefix_length      = 24
  gateway            = "192.168.1.1"
  default_lease_time = 1440
  max_lease_time     = 2880
  domain_name        = "branch.local"
  primary_dns        = "192.168.1.1"
  secondary_dns      = "1.1.1.1"
  boot_server        = "192.168.1.20"
  boot_file          = "pxelinux.0"

  address_pools = [
    { start_address = "192.168.1.100", end_address = "192.168.1.150" },
    { start_address = "192.168.1.200", end_address = "192.168.1.220" },
  ]
  static_mappings = [
    { mac_address = "00:11:22:33:44:55", ip_address = "192.168.1.50", hostname = "printer-01" },
  ]
  dhcp_options = [
    { code = 66, value = "tftp.branch.local" },
    { code = 150, type = "ipv4Addr", value = "192.168.1.20" },
  ]
}`),
				PlanOnly: true,
			},
			{
				Config: env.Config(`
resource "sophosfirewall_dhcp_server" "lan" {
  name                  = "LAN DHCP"
  interface             = "Port1"
  prefix_length         = 23
  gateway               = "192.168.0.1"
  default_lease_time    = 720
  max_lease_time        = 1440
  conflict_detection    = true
  accept_relay_requests = true
  primary_wins          = "192.168.0.10"
  boot_server           = "pxe.branch.local"

  address_pools = [
    { start_address = "192.168.0.100", end_address = "192.168.1.200" },
  ]
  static_mappings = [
    { mac_address = "00:11:22:33:44:55", ip_address = "192.168.1.50" },
    { mac_address = "00:11:22:33:44:66", ip_address = "192.168.1.51", hostname = "nas" },
  ]
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "prefix_length", "23"),
					resource.TestCheckResourceAttr(addr, "address_pools.#", "1"),
					resource.TestCheckResourceAttr(addr, "static_mappings.#", "2"),
					resource.TestCheckResourceAttr(addr, "boot_server", "pxe.branch.local"),
					resource.TestCheckNoResourceAttr(addr, "primary_dns"),
					resource.TestCheckNoResourceAttr(addr, "domain_name"),
					resource.TestCheckNoResourceAttr(addr, "boot_file"),
					resource.TestCheckNoResourceAttr(addr, "dhcp_options"),
					func(*terraform.State) error {
						o := env.Server.Get(serversPath, "LAN DHCP")
						for _, k := range []string{"primaryDnsIpv4", "secondaryDnsIpv4", "domainName", "bootFile"} {
							if _, ok := o[k]; ok {
								return fmt.Errorf("%s was not cleared: %v", k, o)
							}
						}
						if b := o["bootNextServer"].(map[string]any); b["fqdn"] != "pxe.branch.local" || b["ipv4Address"] != nil {
							return fmt.Errorf("bootNextServer = %v", b)
						}
						if o["conflictDetection"] != true || o["acceptRelayRequests"] != true {
							return fmt.Errorf("flags not updated: %v", o)
						}
						return nil
					},
				),
			},
			{ResourceName: addr, ImportState: true, ImportStateVerify: true},
			{
				// The name cannot be patched.
				Config: env.Config(`
resource "sophosfirewall_dhcp_server" "lan" {
  name               = "LAN DHCP 2"
  interface          = "Port1"
  prefix_length      = 23
  gateway            = "192.168.0.1"
  default_lease_time = 720
  max_lease_time     = 1440
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionDestroyBeforeCreate)},
				},
				Check: func(*terraform.State) error {
					if n := env.Server.Names(serversPath); len(n) != 1 || n[0] != "LAN DHCP 2" {
						return fmt.Errorf("servers = %v", n)
					}
					return nil
				},
			},
		},
	})
}

func TestDHCPServerUnmanagedDefaults(t *testing.T) {
	env := acctest.New(t)
	const addr = "sophosfirewall_dhcp_server.guest"
	config := env.Config(`
resource "sophosfirewall_dhcp_server" "guest" {
  name               = "Guest"
  interface          = "Port2.100"
  prefix_length      = 24
  gateway            = "10.100.0.1"
  default_lease_time = 60
  max_lease_time     = 120
}`)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{Config: config},
			{
				// The firewall fills in DNS servers by itself: no drift.
				PreConfig: func() {
					patch(t, env, serversPath+"/Guest", map[string]any{"primaryDnsIpv4": "10.100.0.1", "domainName": "guest.local"})
				},
				Config:   config,
				PlanOnly: true,
			},
			{
				ResourceName:  addr,
				ImportState:   true,
				ImportStateId: "Guest",
				ImportStateCheck: func(s []*terraform.InstanceState) error {
					if got := s[0].Attributes["primary_dns"]; got != "10.100.0.1" {
						return fmt.Errorf("imported primary_dns = %q", got)
					}
					return nil
				},
			},
		},
	})
}

// patch changes an object behind Terraform's back, as the firewall would.
func patch(t *testing.T, env *acctest.Env, item string, body map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPatch, env.Server.URL+"/api/firewall-config/v1"+strings.ReplaceAll(item, " ", "%20"), bytes.NewReader(b))
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

func TestDHCPServerDataSource(t *testing.T) {
	env := acctest.New(t)
	env.Server.Seed(serversPath, map[string]any{
		"name": "Office DHCP", "enabled": true, "interface": map[string]any{"name": "Port3"},
		"acceptRelayRequests": true, "cidr": 16, "gatewayIpv4": "10.0.0.1",
		"addressPools":       []any{map[string]any{"startAddressIpv4": "10.0.0.100", "endAddressIpv4": "10.0.0.200"}},
		"clientReservations": []any{map[string]any{"macAddress": "AA:BB:CC:DD:EE:01", "ipv4Address": "10.0.0.50", "hostname": "printer"}},
		"maxLifetime":        4320, "defaultLifetime": 2160, "conflictDetection": false,
		"primaryDnsIpv4": "10.0.0.2", "bootNextServer": map[string]any{"fqdn": "pxe.office.local"},
		"dhcpOptions": []any{map[string]any{"option": "Domain_Name", "code": 15, "type": "fqdn", "value": "office.local"}},
	})
	const ds = "data.sophosfirewall_dhcp_server.office"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{{
			Config: env.Config(`data "sophosfirewall_dhcp_server" "office" { name = "Office DHCP" }`),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(ds, "interface", "Port3"),
				resource.TestCheckResourceAttr(ds, "prefix_length", "16"),
				resource.TestCheckResourceAttr(ds, "accept_relay_requests", "true"),
				resource.TestCheckResourceAttr(ds, "primary_dns", "10.0.0.2"),
				resource.TestCheckResourceAttr(ds, "boot_server", "pxe.office.local"),
				resource.TestCheckResourceAttr(ds, "address_pools.0.start_address", "10.0.0.100"),
				resource.TestCheckResourceAttr(ds, "static_mappings.0.mac_address", "AA:BB:CC:DD:EE:01"),
				resource.TestCheckResourceAttr(ds, "dhcp_options.0.type", "fqdn"),
				resource.TestCheckResourceAttrSet(ds, "id"),
			),
		}},
	})
}

func TestDHCPServerValidation(t *testing.T) {
	env := acctest.New(t)
	cases := map[string]struct {
		body string
		err  string
	}{
		"lease times": {`
  default_lease_time = 2000
  max_lease_time     = 1000`, `must not exceed max_lease_time`},
		"pool order": {`
  address_pools = [{ start_address = "192.168.1.200", end_address = "192.168.1.100" }]`, `must not be greater than`},
		"duplicate mac": {`
  static_mappings = [
    { mac_address = "00:11:22:33:44:55", ip_address = "192.168.1.50" },
    { mac_address = "00:11:22:33:44:55", ip_address = "192.168.1.51" },
  ]`, `Duplicate MAC address`},
		"bad mac": {`
  static_mappings = [{ mac_address = "0011.2233.4455", ip_address = "192.168.1.50" }]`, `colon separated MAC`},
		"duplicate option": {`
  dhcp_options = [{ code = 66, value = "a" }, { code = 66, value = "b" }]`, `Duplicate DHCP option`},
		"option type": {`
  dhcp_options = [{ code = 150, type = "ipv4", value = "a" }]`, `value must be one of`},
		"option code": {`
  dhcp_options = [{ code = 256, value = "a" }]`, `between 1 and 255`},
		"too many pools": {`
  address_pools = [` + pools(9) + `]`, `at most 8`},
		"prefix": {`
  prefix_length = 32`, `between 1 and 31`},
		"gateway": {`
  gateway = "192.168.1"`, `not a valid IPv4 address`},
		"secondary dns": {`
  secondary_dns = "1.1.1.1"`, `primary_dns`},
		"boot server": {`
  boot_server = "pxe server"`, `boot_server`},
		"boot file": {`
  boot_file = "a;b"`, `must not contain`},
		"domain": {`
  domain_name = "-bad"`, `must be a domain name`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: env.Factories,
				Steps: []resource.TestStep{{
					Config:      env.Config(withDefaults(c.body)),
					ExpectError: regexp.MustCompile(strings.ReplaceAll(c.err, " ", `\s+`)),
				}},
			})
		})
	}
}

// withDefaults completes a server configuration; attributes in body win.
func withDefaults(body string) string {
	attrs := map[string]string{
		"prefix_length": "24", "gateway": `"192.168.1.1"`, "default_lease_time": "60", "max_lease_time": "120",
	}
	out := "resource \"sophosfirewall_dhcp_server\" \"t\" {\n  name = \"t\"\n  interface = \"Port1\"\n" + body + "\n"
	for k, v := range attrs {
		if !regexp.MustCompile(`(?m)^\s*` + k + `\s*=`).MatchString(body) {
			out += fmt.Sprintf("  %s = %s\n", k, v)
		}
	}
	return out + "}\n"
}

func pools(n int) string {
	s := ""
	for i := 0; i < n; i++ {
		s += fmt.Sprintf(`{ start_address = "192.168.1.%d", end_address = "192.168.1.%d" },`, 10+i, 10+i)
	}
	return s
}
