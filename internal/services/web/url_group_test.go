package web_test

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/acctest"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/services/web"
)

const urlGroupsPath = "/web/url-groups"

func TestURLGroup(t *testing.T) {
	env := acctest.New(t)
	const addr = "sophosfirewall_url_group.shopping"
	serverURLs := func(want int) resource.TestCheckFunc {
		return func(*terraform.State) error {
			o := env.Server.Get(urlGroupsPath, "Allowed-Shopping")
			got, _ := o["urls"].([]any)
			if len(got) != want {
				return fmt.Errorf("urls on server = %v, want %d entries", o["urls"], want)
			}
			return nil
		}
	}
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_url_group" "shopping" {
  name = "Allowed-Shopping"
  urls = ["amazon.com", "ebay.com", "cdn.shopify.com"]
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(addr, "id"),
					resource.TestCheckResourceAttr(addr, "description", ""),
					resource.TestCheckResourceAttr(addr, "urls.#", "3"),
					resource.TestCheckTypeSetElemAttr(addr, "urls.*", "cdn.shopify.com"),
					serverURLs(3),
				),
			},
			{
				// Reordering the list is not a change.
				Config: env.Config(`
resource "sophosfirewall_url_group" "shopping" {
  name = "Allowed-Shopping"
  urls = ["ebay.com", "cdn.shopify.com", "amazon.com"]
}`),
				PlanOnly: true,
			},
			{
				Config: env.Config(`
resource "sophosfirewall_url_group" "shopping" {
  name        = "Allowed-Shopping"
  description = "Approved shopping domains"
  urls        = ["amazon.com", "etsy.com"]
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "urls.#", "2"),
					resource.TestCheckTypeSetElemAttr(addr, "urls.*", "etsy.com"),
					serverURLs(2),
				),
			},
			{ResourceName: addr, ImportState: true, ImportStateVerify: true},
			{ResourceName: addr, ImportState: true, ImportStateId: "Allowed-Shopping", ImportStateVerify: true},
			{
				// Removing every entry sends an empty list and keeps the group.
				Config: env.Config(`
resource "sophosfirewall_url_group" "shopping" {
  name        = "Allowed-Shopping"
  description = "Approved shopping domains"
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr(addr, "urls"),
					serverURLs(0),
				),
			},
			{
				// Renaming is not supported by the API's PATCH.
				Config: env.Config(`
resource "sophosfirewall_url_group" "shopping" {
  name = "Shopping"
  urls = ["amazon.com"]
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionDestroyBeforeCreate)},
				},
				Check: resource.TestCheckResourceAttr(addr, "name", "Shopping"),
			},
		},
	})
}

// largeSizeEnv sets the size of the group in TestURLGroupLarge, e.g. to the
// API maximum of 10000. Such a run takes many minutes because
// terraform-plugin-go and Terraform compare large sets in quadratic time;
// the provider's own handling is linear (see large_set.go).
const largeSizeEnv = "SOPHOSFIREWALL_TEST_URL_GROUP_SIZE"

// domains returns n quoted, comma separated domain names.
func domains(n, offset int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "%q,", fmt.Sprintf("host-%05d.example.com", i+offset))
	}
	return b.String()
}

// TestURLGroupLarge exercises a big group: real devices hold up to ~1,300
// groups and ~300,000 domains in total.
func TestURLGroupLarge(t *testing.T) {
	if testing.Short() {
		t.Skip("large URL group test skipped in -short mode")
	}
	size := 1000
	if v := os.Getenv(largeSizeEnv); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 2 || n > web.MaxURLs {
			t.Fatalf("%s=%q must be a number between 2 and %d", largeSizeEnv, v, web.MaxURLs)
		}
		size = n
	}
	env := acctest.New(t)
	const addr = "sophosfirewall_url_group.big"
	cfg := func(list string) string {
		return env.Config(fmt.Sprintf(`
resource "sophosfirewall_url_group" "big" {
  name = "Blocklist"
  urls = [%s]
}`, list))
	}
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: cfg(domains(size, 0)),
				Check:  resource.TestCheckResourceAttr(addr, "urls.#", fmt.Sprint(size)),
			},
			{
				// Swap one entry: still an in-place update of the whole list.
				Config: cfg(domains(size-1, 1) + `"replacement.example.com"`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "urls.#", fmt.Sprint(size)),
					resource.TestCheckTypeSetElemAttr(addr, "urls.*", "replacement.example.com"),
				),
			},
		},
	})
}

func TestURLGroupDataSource(t *testing.T) {
	env := acctest.New(t)
	env.Server.Seed(urlGroupsPath, map[string]any{
		"name": "Social", "description": "Social networks", "urls": []any{"facebook.com", "x.com"},
	})
	const ds = "data.sophosfirewall_url_group.social"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{{
			Config: env.Config(`data "sophosfirewall_url_group" "social" { name = "Social" }`),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet(ds, "id"),
				resource.TestCheckResourceAttr(ds, "description", "Social networks"),
				resource.TestCheckResourceAttr(ds, "urls.#", "2"),
				resource.TestCheckTypeSetElemAttr(ds, "urls.*", "x.com"),
			),
		}},
	})
}

func TestURLGroupValidation(t *testing.T) {
	env := acctest.New(t)
	cfg := func(urls string) string {
		return env.Config(fmt.Sprintf(`
resource "sophosfirewall_url_group" "t" {
  name = "t"
  urls = %s
}`, urls))
	}
	var steps []resource.TestStep
	for _, bad := range []string{`["https://example.com"]`, `["*.example.com"]`, `["example.com/path"]`, `["example.com:8080"]`, `["-example.com"]`} {
		steps = append(steps, resource.TestStep{Config: cfg(bad), ExpectError: regexp.MustCompile(`must be a domain or host name`), PlanOnly: true})
	}
	steps = append(steps,
		resource.TestStep{Config: cfg(`[]`), ExpectError: regexp.MustCompile(`at least 1`), PlanOnly: true},
		resource.TestStep{
			Config:      cfg("[" + domains(web.MaxURLs+1, 0) + "]"),
			ExpectError: regexp.MustCompile(`set must contain at least 1 elements and at most 10000`), PlanOnly: true,
		},
		resource.TestStep{Config: cfg(fmt.Sprintf("[%q]", strings.Repeat("a", 251))), ExpectError: regexp.MustCompile(`length must be between 1 and 250`), PlanOnly: true},
		resource.TestStep{
			Config:      env.Config(`resource "sophosfirewall_url_group" "t" { name = "a,b" }`),
			ExpectError: regexp.MustCompile(`not a valid SFOS object name`), PlanOnly: true,
		},
	)
	resource.UnitTest(t, resource.TestCase{ProtoV6ProviderFactories: env.Factories, Steps: steps})
}
