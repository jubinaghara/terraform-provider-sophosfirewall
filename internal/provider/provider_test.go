package provider

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// TestSchemas asks the framework to build every schema, which validates
// them (e.g. defaults on non-computed attributes) and catches duplicates.
func TestSchemas(t *testing.T) {
	server, err := providerserver.NewProtocol6WithError(New("test")())()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := server.GetProviderSchema(context.Background(), &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range resp.Diagnostics {
		t.Errorf("%s: %s: %s", d.Severity, d.Summary, d.Detail)
	}

	got := func(m map[string]*tfprotov6.Schema) string {
		var names []string
		for n := range m {
			names = append(names, n)
		}
		sort.Strings(names)
		return strings.Join(names, ",")
	}
	wantResources := []string{
		"sophosfirewall_country_group",
		"sophosfirewall_dhcp_server",
		"sophosfirewall_dns_host_entry",
		"sophosfirewall_firewall_rule",
		"sophosfirewall_fqdn_address",
		"sophosfirewall_fqdn_group",
		"sophosfirewall_gateway",
		"sophosfirewall_interface",
		"sophosfirewall_ipv4_address",
		"sophosfirewall_ipv4_group",
		"sophosfirewall_ipv6_address",
		"sophosfirewall_ipv6_group",
		"sophosfirewall_mac_address",
		"sophosfirewall_nat_rule",
		"sophosfirewall_physical_interface",
		"sophosfirewall_schedule",
		"sophosfirewall_sdwan_route",
		"sophosfirewall_service",
		"sophosfirewall_service_group",
		"sophosfirewall_static_route",
		"sophosfirewall_url_group",
		"sophosfirewall_user_group",
		"sophosfirewall_zone",
	}
	wantDataSources := []string{
		"sophosfirewall_country_group",
		"sophosfirewall_dhcp_server",
		"sophosfirewall_dns_host_entry",
		"sophosfirewall_firewall_rule",
		"sophosfirewall_fqdn_address",
		"sophosfirewall_fqdn_group",
		"sophosfirewall_gateway",
		"sophosfirewall_interface",
		"sophosfirewall_ipv4_address",
		"sophosfirewall_ipv4_group",
		"sophosfirewall_ipv6_address",
		"sophosfirewall_ipv6_group",
		"sophosfirewall_mac_address",
		"sophosfirewall_nat_rule",
		"sophosfirewall_schedule",
		"sophosfirewall_sdwan_route",
		"sophosfirewall_service",
		"sophosfirewall_service_group",
		"sophosfirewall_static_route",
		"sophosfirewall_url_group",
		"sophosfirewall_user_group",
		"sophosfirewall_zone",
	}
	if want := strings.Join(wantResources, ","); got(resp.ResourceSchemas) != want {
		t.Errorf("resources = %s\nwant        %s", got(resp.ResourceSchemas), want)
	}
	if want := strings.Join(wantDataSources, ","); got(resp.DataSourceSchemas) != want {
		t.Errorf("data sources = %s\nwant           %s", got(resp.DataSourceSchemas), want)
	}
}
