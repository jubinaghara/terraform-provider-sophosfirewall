package servicesobj_test

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/acctest"
)

func TestServiceTCPUDP(t *testing.T) {
	env := acctest.New(t)
	const svc = "sophosfirewall_service.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_service" "test" {
  name = "app-ports"
  tcp_udp = [
    { protocol = "tcp", destination_port = "8443" },
    { protocol = "udp", source_port = "1024:65535", destination_port = "5000:5010" },
  ]
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(svc, "id"),
					resource.TestCheckResourceAttr(svc, "description", ""),
					resource.TestCheckResourceAttr(svc, "tcp_udp.#", "2"),
					resource.TestCheckResourceAttr(svc, "tcp_udp.0.protocol", "tcp"),
					resource.TestCheckResourceAttr(svc, "tcp_udp.0.source_port", "1:65535"),
					resource.TestCheckResourceAttr(svc, "tcp_udp.0.destination_port", "8443"),
					resource.TestCheckResourceAttr(svc, "tcp_udp.1.source_port", "1024:65535"),
					resource.TestCheckResourceAttr(svc, "tcp_udp.1.destination_port", "5000:5010"),
					resource.TestCheckNoResourceAttr(svc, "ip_protocols"),
				),
			},
			{
				// In-place update of the entries and description.
				Config: env.Config(`
resource "sophosfirewall_service" "test" {
  name        = "app-ports"
  description = "Application ports"
  tcp_udp = [
    { protocol = "tcp", destination_port = "9443" },
  ]
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(svc, plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(svc, "description", "Application ports"),
					resource.TestCheckResourceAttr(svc, "tcp_udp.#", "1"),
					resource.TestCheckResourceAttr(svc, "tcp_udp.0.destination_port", "9443"),
				),
			},
			{ResourceName: svc, ImportState: true, ImportStateVerify: true},
			{ResourceName: svc, ImportState: true, ImportStateId: "app-ports", ImportStateVerify: true},
		},
	})

	got := env.Server.Get("/network/services", "app-ports")
	if got != nil {
		t.Fatalf("service not deleted after destroy: %v", got)
	}
}

func TestServiceWireFormat(t *testing.T) {
	env := acctest.New(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_service" "test" {
  name    = "web"
  tcp_udp = [{ protocol = "tcp", destination_port = "443" }]
}`),
				Check: func(*terraform.State) error {
					obj := env.Server.Get("/network/services", "web")
					if obj["type"] != "tcpOrUdp" {
						t.Errorf("type = %v, want tcpOrUdp", obj["type"])
					}
					entry := obj["services"].([]any)[0].(map[string]any)
					dst := entry["destinationPort"].(map[string]any)
					src := entry["sourcePort"].(map[string]any)
					if dst["from"] != float64(443) || dst["to"] != float64(443) {
						t.Errorf("destinationPort = %v, want 443-443", dst)
					}
					if src["from"] != float64(1) || src["to"] != float64(65535) {
						t.Errorf("sourcePort = %v, want 1-65535", src)
					}
					return nil
				},
			},
		},
	})
}

func TestServiceIPAndICMP(t *testing.T) {
	env := acctest.New(t)
	const ip, icmp, icmpv6 = "sophosfirewall_service.ip", "sophosfirewall_service.icmp", "sophosfirewall_service.icmpv6"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_service" "ip" {
  name         = "vpn-protocols"
  ip_protocols = ["gre", "esp"]
}
resource "sophosfirewall_service" "icmp" {
  name = "ping"
  icmp = [
    { type = "echoRequest" },
    { type = "destinationUnreachable", code = "portUnreachable" },
  ]
}
resource "sophosfirewall_service" "icmpv6" {
  name   = "ndp"
  icmpv6 = [{ type = "neighborSolicitation", code = "noCode" }]
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(ip, "ip_protocols.#", "2"),
					resource.TestCheckTypeSetElemAttr(ip, "ip_protocols.*", "gre"),
					resource.TestCheckResourceAttr(icmp, "icmp.#", "2"),
					resource.TestCheckResourceAttr(icmp, "icmp.0.code", "any"),
					resource.TestCheckResourceAttr(icmp, "icmp.1.code", "portUnreachable"),
					resource.TestCheckResourceAttr(icmpv6, "icmpv6.0.type", "neighborSolicitation"),
				),
			},
			{
				// Updating the IP protocols happens in place.
				Config: env.Config(`
resource "sophosfirewall_service" "ip" {
  name         = "vpn-protocols"
  ip_protocols = ["gre", "esp", "ah"]
}
resource "sophosfirewall_service" "icmp" {
  name = "ping"
  icmp = [{ type = "echoRequest", code = "noCode" }]
}
resource "sophosfirewall_service" "icmpv6" {
  name   = "ndp"
  icmpv6 = [{ type = "neighborSolicitation", code = "noCode" }]
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(ip, plancheck.ResourceActionUpdate),
						plancheck.ExpectResourceAction(icmp, plancheck.ResourceActionUpdate),
						plancheck.ExpectResourceAction(icmpv6, plancheck.ResourceActionNoop),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(ip, "ip_protocols.#", "3"),
					resource.TestCheckResourceAttr(icmp, "icmp.#", "1"),
				),
			},
			{ResourceName: ip, ImportState: true, ImportStateVerify: true},
			{ResourceName: icmp, ImportState: true, ImportStateVerify: true},
			{ResourceName: icmpv6, ImportState: true, ImportStateVerify: true},
			{
				// Switching the service type recreates the object, since the
				// API does not accept "type" in a PATCH.
				Config: env.Config(`
resource "sophosfirewall_service" "ip" {
  name    = "vpn-protocols"
  tcp_udp = [{ protocol = "udp", destination_port = "500" }]
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(ip, plancheck.ResourceActionDestroyBeforeCreate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(ip, "tcp_udp.0.destination_port", "500"),
					resource.TestCheckNoResourceAttr(ip, "ip_protocols.#"),
				),
			},
		},
	})
}

func TestServiceBuiltinDataSource(t *testing.T) {
	env := acctest.New(t)
	// Built-in services exist on every firewall and are referenced by name.
	env.Server.Seed("/network/services", map[string]any{
		"name": "HTTPS", "type": "tcpOrUdp",
		"services": []any{map[string]any{
			"protocol": "tcp", "sourcePort": map[string]any{"from": 1, "to": 65535}, "destinationPort": map[string]any{"from": 443, "to": 443},
		}},
	})
	env.Server.Seed("/network/services", map[string]any{
		"name": "PING", "description": "ICMP echo", "type": "icmp",
		"services": []any{map[string]any{"icmpType": "echoRequest", "icmpCode": "any"}},
	})
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
data "sophosfirewall_service" "https" {
  name = "HTTPS"
}
data "sophosfirewall_service" "ping" {
  name = "PING"
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.sophosfirewall_service.https", "id"),
					resource.TestCheckResourceAttr("data.sophosfirewall_service.https", "description", ""),
					resource.TestCheckResourceAttr("data.sophosfirewall_service.https", "tcp_udp.0.protocol", "tcp"),
					resource.TestCheckResourceAttr("data.sophosfirewall_service.https", "tcp_udp.0.source_port", "1:65535"),
					resource.TestCheckResourceAttr("data.sophosfirewall_service.https", "tcp_udp.0.destination_port", "443"),
					resource.TestCheckResourceAttr("data.sophosfirewall_service.ping", "icmp.0.type", "echoRequest"),
					resource.TestCheckResourceAttr("data.sophosfirewall_service.ping", "description", "ICMP echo"),
				),
			},
		},
	})
}

func TestServiceValidation(t *testing.T) {
	env := acctest.New(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config:      env.Config(`resource "sophosfirewall_service" "t" { name = "x" }`),
				ExpectError: regexp.MustCompile(`(?s)one \(and only one\) of.*ip_protocols,icmp,icmpv6`),
			},
			{
				Config: env.Config(`
resource "sophosfirewall_service" "t" {
  name         = "x"
  tcp_udp      = [{ protocol = "tcp" }]
  ip_protocols = ["gre"]
}`),
				ExpectError: regexp.MustCompile(`(?s)one \(and only one\) of`),
			},
			{
				Config: env.Config(`
resource "sophosfirewall_service" "t" {
  name    = "x"
  tcp_udp = [{ protocol = "tcp", destination_port = "443:80" }]
}`),
				ExpectError: regexp.MustCompile(`start below its end`),
			},
			{
				Config: env.Config(`
resource "sophosfirewall_service" "t" {
  name    = "x"
  tcp_udp = [{ protocol = "tcp", destination_port = "80:80" }]
}`),
				ExpectError: regexp.MustCompile(`(?s)write a single port as\s+"80"`),
			},
			{
				Config: env.Config(`
resource "sophosfirewall_service" "t" {
  name    = "x"
  tcp_udp = [{ protocol = "tcp", destination_port = "70000" }]
}`),
				ExpectError: regexp.MustCompile(`not a port number between 1 and 65535`),
			},
			{
				Config: env.Config(`
resource "sophosfirewall_service" "t" {
  name    = "x"
  tcp_udp = [{ protocol = "sctp" }]
}`),
				ExpectError: regexp.MustCompile(`value must be one of`),
			},
			{
				Config: env.Config(`
resource "sophosfirewall_service" "t" {
  name         = "x"
  ip_protocols = ["GRE"]
}`),
				ExpectError: regexp.MustCompile(`value must be one of`),
			},
			{
				Config: env.Config(`
resource "sophosfirewall_service" "t" {
  name = "x"
  icmp = [{ type = "echo" }]
}`),
				ExpectError: regexp.MustCompile(`value must be one of`),
			},
		},
	})
}
