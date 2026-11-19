# Terraform Provider for Sophos Firewall (SFOS)

Manage Sophos Firewall configuration as code through the
**Firewall Configuration REST API** (`https://<firewall>:<port>/api/firewall-config/v1`).

> **Note:** This is not an official Sophos Firewall (SFOS) provider. It is developed independently
> and has been tested in a limited capacity. Try changes on a non-production firewall first.

## Compatibility

| Provider version | Sophos Firewall (SFOS) | API | Authentication |
|------------------|------------------------|-----|----------------|
| **23.x**         | **v23.0 and later**    | Firewall Configuration REST API | API key |
| 1.x              | older firmware         | legacy XML API | username / password |

Version 23.0.0 is a rewrite and is **not** backwards compatible with 1.x configurations: the
provider arguments, resource names and schemas are different. Pin `version = "~> 1.0"` to keep
using the old provider.

```hcl
terraform {
  required_providers {
    sophosfirewall = {
      source  = "jubinaghara/sophosfirewall"
      version = "~> 23.0"
    }
  }
}

provider "sophosfirewall" {
  endpoint = "https://172.16.16.16:4444" # or SFOS_ENDPOINT
  api_key  = var.sophosfirewall_api_key  # or SFOS_API_KEY
  insecure = true                        # factory self-signed certificate
}

resource "sophosfirewall_ipv4_address" "web" {
  name       = "web-server"
  ip_address = "203.0.113.10"
}

resource "sophosfirewall_firewall_rule" "allow_web" {
  name              = "allow-web"
  source_zones      = ["WAN"]
  destination_zones = ["DMZ"]
  destination_networks = {
    ipv4_addresses = [sophosfirewall_ipv4_address.web.name]
  }
  services = ["HTTPS"]
}
```

Create the API key under **Administration > API access** in the web admin console.

## Supported objects

| Area | Resource | Data source |
|------|----------|-------------|
| Hosts and services | `sophosfirewall_ipv4_address`, `sophosfirewall_ipv6_address` (host, network, range, list) | yes |
| | `sophosfirewall_mac_address` (single or list) | yes |
| | `sophosfirewall_fqdn_address` | yes |
| | `sophosfirewall_country_group` | yes |
| | `sophosfirewall_ipv4_group`, `sophosfirewall_ipv6_group`, `sophosfirewall_fqdn_group` | yes |
| | `sophosfirewall_service` (TCP/UDP, IP protocol, ICMP, ICMPv6) | yes (also built-in services such as `HTTPS`) |
| | `sophosfirewall_service_group` | yes |
| Network | `sophosfirewall_zone` | yes (also built-in zones such as `LAN`) |
| | `sophosfirewall_interface` (VLAN, bridge, LAG) | yes (any interface) |
| | `sophosfirewall_physical_interface` (adopts existing ports) | – |
| | `sophosfirewall_dhcp_server` (IPv4) | yes |
| | `sophosfirewall_dns_host_entry` | yes |
| Routing | `sophosfirewall_static_route` (IPv4) | yes |
| | `sophosfirewall_gateway` (custom IPv4 gateways) | yes |
| | `sophosfirewall_sdwan_route` (IPv4, ordered) | yes |
| Rules and policies | `sophosfirewall_firewall_rule` (IPv4) | yes |
| | `sophosfirewall_nat_rule` (IPv4 SNAT / DNAT / port forwarding) | yes |
| Web | `sophosfirewall_url_group` | yes |
| Authentication | `sophosfirewall_user_group` | yes (also built-in groups such as `Open Group`) |
| System | `sophosfirewall_schedule` (recurring or one-time) | yes |

Every resource supports `terraform import` by UUID or name. Full documentation is in
[`docs/`](docs/) and on the Terraform Registry. [`test/live`](test/live) applies, updates and
destroys one of every resource on a real firewall.

Conventions that apply everywhere:

* Objects reference each other **by name**, e.g. `ipv4_addresses = [sophosfirewall_ipv4_address.web.name]`.
* Omitting a match criterion of a rule (zones, networks, services, interfaces) means **any**.
* Optional blocks you do not configure are left alone and are not reported as drift.
* Rule order is controlled with `position` (`top`, `bottom`, `before`, `after`) and `position_reference`.

## Development

Requirements: Go (see `go.mod`) and Terraform ≥ 1.5.

```sh
make build   # compile
make test    # unit tests + end-to-end Terraform tests against an in-memory API fake
make docs    # regenerate docs/ with tfplugindocs
make install # install into ~/.terraform.d/plugins for local use
```

The test suite does not need a firewall: `internal/sfostest` implements a fake of the
API (merge-patch semantics, server-side defaults, omitted empty lists), and
`internal/acctest` runs real `terraform plan/apply/import` cycles against it.

### Architecture

```
internal/
  sfos/          HTTP client: auth, retries, errors, shared API types (NameRef, Selector)
  framework/     generic resource + data source engine driven by a declarative spec
  services/      one package per API area; each object type is a single spec file
    shared/      rule match criteria (networks, zones, services) and rule positioning
  provider/      provider configuration and the registry of object types
  sfostest/      in-memory fake of the SFOS API
  acctest/       test helpers wiring the fake to the provider
```

Most SFOS objects share one REST contract (`POST` collection, `GET`/`PATCH`/`DELETE`
`{collection}/{idOrName}`), so `internal/framework` implements CRUD, import,
minimal JSON-merge-patch updates and data sources **once**. A new object type only
supplies its schema, model and two conversion functions. See
[CONTRIBUTING.md](CONTRIBUTING.md) for a walkthrough.

## License

[MPL-2.0](LICENSE)
