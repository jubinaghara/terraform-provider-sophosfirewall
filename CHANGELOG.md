## 23.2.0 (November 23, 2026)

Adds the security policies that firewall rules apply, which configuration telemetry shows
on more than 99% of firewalls. Every resource was applied, updated and destroyed on a live
SFOS v23 firewall (`test/live`).

FEATURES:

* **New Resource / Data Source:** `sophosfirewall_web_policy`: web policies with ordered rules (categories, URL groups, file types, user activities; HTTP/HTTPS actions, quotas, schedules)
* **New Resource / Data Source:** `sophosfirewall_web_exception`: web exceptions that skip HTTPS decryption, certificate validation, malware scanning, zero-day protection or the policy check
* **New Resource / Data Source:** `sophosfirewall_traffic_shaping_policy`: QoS policies (guaranteed or best-effort, aggregated or per-direction bandwidth, scheduled overrides)
* **New Resource / Data Source:** `sophosfirewall_ips_policy`: intrusion prevention policies with ordered rules selecting signatures by filter or by name
* **New Resource / Data Source:** `sophosfirewall_application_filter_policy`: application filter policies with ordered rules selecting applications by name or by category, risk, characteristic, technology or classification
* All five can be applied by `sophosfirewall_firewall_rule` (`security_features.web_policy`, `ips_policy`, `application_policy` and `qos.traffic_shaping_policy`), and their data sources also read built-in policies

BUG FIXES:

* `sophosfirewall_firewall_rule`, `sophosfirewall_nat_rule`, `sophosfirewall_sdwan_route`: changing `position` of an existing rule to `top` or `bottom` failed with "top is not a valid MovePosition". The firewall's move endpoints accept only `before`/`after`, so the rule is now moved before the first or after the last rule.
* `sophosfirewall_web_policy`: works around SFOS v23 storing the inverse of the `reporting` value written; the value is checked and corrected after every create and update.

## 23.1.0 (November 19, 2026)

Covers the most used firewall objects according to configuration telemetry. Every
resource was applied, updated and destroyed on a live SFOS v23 firewall (`test/live`).

FEATURES:

* **New Resource / Data Source:** `sophosfirewall_ipv4_group`, `sophosfirewall_ipv6_group`, `sophosfirewall_fqdn_group`: address groups
* **New Resource / Data Source:** `sophosfirewall_service`: TCP/UDP, IP protocol, ICMP and ICMPv6 services
* **New Resource / Data Source:** `sophosfirewall_service_group`: service groups
* **New Resource / Data Source:** `sophosfirewall_schedule`: recurring and one-time schedules
* **New Resource / Data Source:** `sophosfirewall_url_group`: URL groups, up to 10,000 domains
* **New Resource / Data Source:** `sophosfirewall_dns_host_entry`: DNS host entries
* **New Resource / Data Source:** `sophosfirewall_dhcp_server`: IPv4 DHCP servers
* **New Resource / Data Source:** `sophosfirewall_user_group`: user groups
* **New Resource / Data Source:** `sophosfirewall_static_route`, `sophosfirewall_gateway`, `sophosfirewall_sdwan_route`: static routes, custom gateways and SD-WAN routes

BUG FIXES:

* `sophosfirewall_interface`: bridge and LAG interfaces could not be created ("Invalid mtu"); LAG interfaces now take the `zone` the firewall requires
* `sophosfirewall_interface`, `sophosfirewall_physical_interface`: validate that `mtu` exceeds `mss` by at least 40
* Objects the firewall stores despite failing to activate them (`addRunConfigFailed`) are rolled back, and deletes the firewall reports as failed but still performs are no longer errors

NOTES:

* The provider description and README note that this is not an official Sophos provider.

## 23.0.0 (November 19, 2026)

BREAKING CHANGES:

* Complete rewrite on the SFOS Firewall Configuration REST API. **Requires Sophos Firewall v23.0 or later.**
* Authentication now uses an API key (`api_key` / `SFOS_API_KEY`) instead of a username and password. The firewall address is set with `endpoint` / `SFOS_ENDPOINT`.
* Resource names and schemas differ from 1.x, so configurations written for 1.x must be migrated. Pin `version = "~> 1.0"` to keep the old provider.

FEATURES:

* **New Resource / Data Source:** `sophosfirewall_ipv4_address`: IPv4 hosts, networks, ranges and lists
* **New Resource / Data Source:** `sophosfirewall_ipv6_address`: IPv6 hosts, networks, ranges and lists
* **New Resource / Data Source:** `sophosfirewall_mac_address`: MAC address objects and lists
* **New Resource / Data Source:** `sophosfirewall_fqdn_address`: FQDN address objects
* **New Resource / Data Source:** `sophosfirewall_country_group`: country groups
* **New Resource / Data Source:** `sophosfirewall_zone`: zones and their device services
* **New Resource / Data Source:** `sophosfirewall_interface`: VLAN, bridge and LAG interfaces
* **New Resource:** `sophosfirewall_physical_interface`: configures existing physical ports
* **New Resource / Data Source:** `sophosfirewall_firewall_rule`: IPv4 firewall rules, including positioning
* **New Resource / Data Source:** `sophosfirewall_nat_rule`: IPv4 SNAT, DNAT and port forwarding rules
