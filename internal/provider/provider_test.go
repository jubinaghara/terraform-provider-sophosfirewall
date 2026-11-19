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
	if want := "sophosfirewall_country_group,sophosfirewall_firewall_rule,sophosfirewall_fqdn_address,sophosfirewall_interface,sophosfirewall_ipv4_address,sophosfirewall_ipv6_address," +
		"sophosfirewall_mac_address,sophosfirewall_nat_rule,sophosfirewall_physical_interface,sophosfirewall_zone"; got(resp.ResourceSchemas) != want {
		t.Errorf("resources = %s\nwant        %s", got(resp.ResourceSchemas), want)
	}
	if want := "sophosfirewall_country_group,sophosfirewall_firewall_rule,sophosfirewall_fqdn_address,sophosfirewall_interface,sophosfirewall_ipv4_address,sophosfirewall_ipv6_address," +
		"sophosfirewall_mac_address,sophosfirewall_nat_rule,sophosfirewall_zone"; got(resp.DataSourceSchemas) != want {
		t.Errorf("data sources = %s\nwant           %s", got(resp.DataSourceSchemas), want)
	}
}
