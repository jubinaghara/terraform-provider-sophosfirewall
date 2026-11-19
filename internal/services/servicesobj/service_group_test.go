package servicesobj_test

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/acctest"
)

func TestServiceGroup(t *testing.T) {
	env := acctest.New(t)
	env.Server.Seed("/network/services", map[string]any{
		"name": "HTTPS", "type": "tcpOrUdp",
		"services": []any{map[string]any{"protocol": "tcp", "destinationPort": map[string]any{"from": 443, "to": 443}}},
	})
	const grp = "sophosfirewall_service_group.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_service" "app" {
  name    = "app"
  tcp_udp = [{ protocol = "tcp", destination_port = "8443" }]
}
resource "sophosfirewall_service_group" "test" {
  name     = "web-services"
  services = ["HTTPS", sophosfirewall_service.app.name]
}
data "sophosfirewall_service_group" "test" {
  name = sophosfirewall_service_group.test.name
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(grp, "id"),
					resource.TestCheckResourceAttr(grp, "description", ""),
					resource.TestCheckResourceAttr(grp, "services.#", "2"),
					resource.TestCheckTypeSetElemAttr(grp, "services.*", "HTTPS"),
					resource.TestCheckResourceAttrPair("data.sophosfirewall_service_group.test", "id", grp, "id"),
					resource.TestCheckResourceAttr("data.sophosfirewall_service_group.test", "services.#", "2"),
				),
			},
			{
				Config: env.Config(`
resource "sophosfirewall_service_group" "test" {
  name        = "web-services"
  description = "Web"
  services    = ["HTTPS"]
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(grp, plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(grp, "description", "Web"),
					resource.TestCheckResourceAttr(grp, "services.#", "1"),
				),
			},
			{ResourceName: grp, ImportState: true, ImportStateVerify: true},
			{ResourceName: grp, ImportState: true, ImportStateId: "web-services", ImportStateVerify: true},
		},
	})
}

func TestServiceGroupValidation(t *testing.T) {
	env := acctest.New(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config:      env.Config(`resource "sophosfirewall_service_group" "t" { name = "x" }`),
				ExpectError: regexp.MustCompile(`The argument "services" is required`),
			},
			{
				Config: env.Config(`resource "sophosfirewall_service_group" "t" {
  name     = "x"
  services = []
}`),
				ExpectError: regexp.MustCompile(`set must contain at least 1 elements`),
			},
		},
	})
}
