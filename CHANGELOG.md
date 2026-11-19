## 23.0.0 (Unreleased)

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
