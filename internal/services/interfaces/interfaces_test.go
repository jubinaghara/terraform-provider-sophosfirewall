package interfaces_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/acctest"
)

const interfacesPath = "/network/interfaces/network-interfaces"

func TestVLANInterface(t *testing.T) {
	env := acctest.New(t)
	const addr = "sophosfirewall_interface.vlan"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_interface" "vlan" {
  name = "Port2.100"
  type = "vlan"
  zone = "LAN"
  vlan = {
    parent_interface = "Port2"
    vlan_id          = 100
  }
  ipv4 = {
    assignment_type = "static"
    address         = "10.100.0.1/24"
  }
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "hardware_name", "Port2.100"),
					resource.TestCheckResourceAttr(addr, "ipv4.address", "10.100.0.1/24"),
					resource.TestCheckNoResourceAttr(addr, "ipv6"),
				),
			},
			{
				Config: env.Config(`
resource "sophosfirewall_interface" "vlan" {
  name = "Port2.100"
  type = "vlan"
  zone = "LAN"
  vlan = {
    parent_interface = "Port2"
    vlan_id          = 100
  }
  ipv4 = {
    assignment_type = "static"
    address         = "10.100.0.2/25"
    gateway_name    = "gw-vlan100"
    gateway_address = "10.100.0.126"
  }
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "ipv4.address", "10.100.0.2/25"),
					func(*terraform.State) error {
						ip := env.Server.Get(interfacesPath, "Port2.100")["ipv4"].(map[string]any)
						if ip["ipv4Address"] != "10.100.0.2" || ip["cidr"] != float64(25) {
							return fmt.Errorf("stored ipv4 = %v", ip)
						}
						return nil
					},
				),
			},
			{ResourceName: addr, ImportState: true, ImportStateVerify: true},
		},
	})
}

func TestInterfaceValidation(t *testing.T) {
	env := acctest.New(t)
	config := env.Config(`
resource "sophosfirewall_interface" "vlan" {
  name = "Port2.100"
  type = "vlan"
  ipv4 = {
    assignment_type = "static"
  }
}`)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{Config: config, ExpectError: regexp.MustCompile(`"vlan" is required when type is "vlan"`)},
			{Config: config, ExpectError: regexp.MustCompile(`address is required when assignment_type is "static"`)},
		},
	})
}

func TestLAGInterface(t *testing.T) {
	env := acctest.New(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_interface" "lag" {
  name          = "Lag1"
  hardware_name = "Lag1"
  type          = "lag"
  zone          = "LAN"
  lag = {
    members = ["Port6", "Port7"]
    mode    = "lacp8023ad"
  }
  ipv4 = {
    assignment_type = "dhcp"
  }
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("sophosfirewall_interface.lag", "lag.members.#", "2"),
					resource.TestCheckResourceAttr("sophosfirewall_interface.lag", "mtu", "1500"),
				),
			},
		},
	})
}

func TestPhysicalInterfaceAdopt(t *testing.T) {
	env := acctest.New(t)
	env.Server.Seed(interfacesPath, map[string]any{
		"name": "Port2", "hardwareName": "Port2", "type": "physical", "zone": map[string]any{"name": "WAN"},
		"ipv4": map[string]any{"assignmentType": "dhcp", "ipv4Address": "198.51.100.7", "cidr": 24},
		"mtu":  1500, "mss": 1460, "overrideMac": false, "macAddress": "00:1a:2b:3c:4d:5e",
	})
	const addr = "sophosfirewall_physical_interface.wan"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_physical_interface" "wan" {
  name = "Port2"
  mtu  = 1492
  ipv4 = {
    assignment_type = "static"
    address         = "198.51.100.30/24"
    gateway_name    = "isp"
    gateway_address = "198.51.100.1"
  }
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "type", "physical"),
					resource.TestCheckResourceAttr(addr, "mtu", "1492"),
					resource.TestCheckNoResourceAttr(addr, "zone"),
				),
			},
			{
				// DHCP: the address becomes computed by the firewall.
				Config: env.Config(`
resource "sophosfirewall_physical_interface" "wan" {
  name = "Port2"
  ipv4 = {
    assignment_type = "dhcp"
  }
}`),
				Check: resource.TestCheckResourceAttr(addr, "ipv4.assignment_type", "dhcp"),
			},
		},
		CheckDestroy: func(*terraform.State) error {
			if env.Server.Get(interfacesPath, "Port2") == nil {
				return fmt.Errorf("physical interface must not be deleted")
			}
			return nil
		},
	})
}
