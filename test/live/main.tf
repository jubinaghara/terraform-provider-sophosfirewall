# Live end-to-end test: creates one of every resource type on a real firewall,
# updates them in place (-var v2=true), reads them back through every data
# source, and destroys them again. See README.md in this folder.
#
# Safety: every object is named TF-Live*/TFLive*, every address is in the
# unused 10.98.0.0/16 range, and only the spare ports Port3-Port6/PortF1 are
# touched. Rules only match 10.98.x.x, so live traffic is unaffected.

terraform {
  required_providers {
    sophosfirewall = {
      source = "jubinaghara/sophosfirewall"
    }
  }
}

# Endpoint and API key come from SFOS_ENDPOINT / SFOS_API_KEY / SFOS_INSECURE.
provider "sophosfirewall" {}

variable "static_routes" {
  description = "Include the static route; set false when the firewall cannot activate routes (addRunConfigFailed)."
  type        = bool
  default     = true
}

variable "v2" {
  description = "Second pass: change attributes to exercise in-place updates."
  type        = bool
  default     = false
}

locals {
  desc = var.v2 ? "TF live test - updated" : "TF live test"
}

# ---------------------------------------------------------------- addresses --

resource "sophosfirewall_ipv4_address" "host" {
  name        = "TF-Live-Host"
  description = local.desc
  ip_address  = var.v2 ? "10.98.10.11" : "10.98.10.10"
}

resource "sophosfirewall_ipv4_address" "network" {
  name    = "TF-Live-Network"
  network = "10.98.10.0/24"
}

resource "sophosfirewall_ipv4_address" "range" {
  name        = "TF-Live-Range"
  range_start = "10.98.20.10"
  range_end   = var.v2 ? "10.98.20.30" : "10.98.20.20"
}

resource "sophosfirewall_ipv4_address" "list" {
  name         = "TF-Live-List"
  ip_addresses = var.v2 ? ["10.98.30.1", "10.98.30.2", "10.98.30.3"] : ["10.98.30.1", "10.98.30.2"]
}

resource "sophosfirewall_ipv6_address" "host" {
  name       = "TF-Live-V6-Host"
  ip_address = "fd98::10"
}

resource "sophosfirewall_ipv6_address" "network" {
  name    = "TF-Live-V6-Network"
  network = "fd98:10::/64"
}

resource "sophosfirewall_mac_address" "single" {
  name        = "TF-Live-MAC"
  mac_address = "02:98:00:00:00:01"
}

resource "sophosfirewall_mac_address" "list" {
  name          = "TF-Live-MAC-List"
  mac_addresses = ["02:98:00:00:00:02", "02:98:00:00:00:03"]
}

resource "sophosfirewall_fqdn_address" "a" {
  name = "TF-Live-FQDN-A"
  fqdn = "a.tf-live.example.com"
}

resource "sophosfirewall_fqdn_address" "wildcard" {
  name = "TF-Live-FQDN-Wildcard"
  fqdn = "*.tf-live.example.com"
}

resource "sophosfirewall_country_group" "this" {
  name        = "TF-Live-Countries"
  description = local.desc
  countries   = var.v2 ? ["Antarctica", "Greenland"] : ["Antarctica"]
}

# ------------------------------------------------------------ address groups --

resource "sophosfirewall_ipv4_group" "this" {
  name        = "TF-Live-IPv4-Group"
  description = local.desc
  addresses = var.v2 ? [sophosfirewall_ipv4_address.host.name] : [
    sophosfirewall_ipv4_address.host.name,
    sophosfirewall_ipv4_address.network.name,
  ]
}

resource "sophosfirewall_ipv6_group" "this" {
  name      = "TF-Live-IPv6-Group"
  addresses = [sophosfirewall_ipv6_address.host.name, sophosfirewall_ipv6_address.network.name]
}

resource "sophosfirewall_fqdn_group" "this" {
  name      = "TF-Live-FQDN-Group"
  addresses = [sophosfirewall_fqdn_address.a.name, sophosfirewall_fqdn_address.wildcard.name]
}

# ------------------------------------------------------------------ services --

resource "sophosfirewall_service" "tcp_udp" {
  name        = "TF-Live-Svc-TCP-UDP"
  description = local.desc
  tcp_udp = [
    { protocol = "tcp", destination_port = var.v2 ? "9443" : "8443" },
    { protocol = "udp", source_port = "1024:65535", destination_port = "9000:9010" },
  ]
}

resource "sophosfirewall_service" "ip" {
  name         = "TF-Live-Svc-IP"
  ip_protocols = ["gre", "esp"]
}

resource "sophosfirewall_service" "icmp" {
  name = "TF-Live-Svc-ICMP"
  icmp = [{ type = "echoRequest" }, { type = "echoReply" }]
}

resource "sophosfirewall_service" "icmpv6" {
  name   = "TF-Live-Svc-ICMPv6"
  icmpv6 = [{ type = "neighborSolicitation", code = "noCode" }]
}

resource "sophosfirewall_service_group" "this" {
  name     = "TF-Live-Svc-Group"
  services = var.v2 ? ["HTTPS", sophosfirewall_service.tcp_udp.name, sophosfirewall_service.icmp.name] : ["HTTPS", sophosfirewall_service.tcp_udp.name]
}

# ------------------------------------------------------- zones / interfaces --

resource "sophosfirewall_zone" "this" {
  name        = "TFLiveZone"
  type        = "dmz"
  description = local.desc
  services    = var.v2 ? ["ping", "https"] : ["ping"]
}

# Port3 is adopted into the built-in DMZ zone (not TFLiveZone), so destroying
# the test zone is never blocked by the port. Terraform cannot "delete" a
# physical port; run restore-ports after destroy to unassign it again.
resource "sophosfirewall_physical_interface" "port3" {
  name = "Port3"
  zone = "DMZ"
  mtu  = var.v2 ? 1400 : 1500
  mss  = var.v2 ? 1360 : 1460
  ipv4 = {
    assignment_type = "static"
    address         = "10.98.3.1/24"
  }
}

resource "sophosfirewall_interface" "vlan" {
  name = "Port3.98"
  type = "vlan"
  zone = sophosfirewall_zone.this.name
  vlan = {
    parent_interface = sophosfirewall_physical_interface.port3.name
    vlan_id          = 98
  }
  ipv4 = {
    assignment_type = "static"
    address         = "10.98.98.1/24"
  }
}

resource "sophosfirewall_interface" "bridge" {
  name          = "TFLiveBr"
  hardware_name = "Bridge9"
  type          = "bridge"
  description   = local.desc
  bridge = {
    members = [
      { interface = "Port4", zone = "DMZ" },
      { interface = "PortF1", zone = "DMZ" },
    ]
  }
  ipv4 = {
    assignment_type = "static"
    address         = "10.98.4.1/24"
  }
}

resource "sophosfirewall_interface" "lag" {
  name          = "TFLiveLag"
  hardware_name = "Lag9"
  type          = "lag"
  zone          = "DMZ"
  lag = {
    members = ["Port5", "Port6"]
    mode    = "activeBackup"
  }
  ipv4 = {
    assignment_type = "static"
    address         = "10.98.5.1/24"
  }
}

# ------------------------------------------------------------------- DHCP ----

resource "sophosfirewall_dhcp_server" "this" {
  name               = "TF-Live-DHCP"
  interface          = sophosfirewall_interface.vlan.name
  prefix_length      = 24
  gateway            = "10.98.98.1"
  default_lease_time = var.v2 ? 720 : 1440
  max_lease_time     = 2880
  domain_name        = "tf-live.example.com"
  primary_dns        = "10.98.98.1"
  address_pools = [
    { start_address = "10.98.98.100", end_address = var.v2 ? "10.98.98.150" : "10.98.98.200" },
  ]
  static_mappings = [
    { mac_address = "02:98:00:00:00:10", ip_address = "10.98.98.50", hostname = "tf-live-printer" },
  ]
}

# ---------------------------------------------------------------- routing ----

resource "sophosfirewall_gateway" "this" {
  name       = "TF-Live-GW"
  ip_address = "10.98.3.254"
  interface  = sophosfirewall_physical_interface.port3.name
  zone       = "DMZ"
  health_check = {
    enabled  = true
    interval = var.v2 ? 30 : 60
    rules    = [{ protocol = "ping", host = "10.98.3.254" }]
  }
}


# Only blackhole routes are tested: this lab firewall rejects every route with
# a gateway or interface and, after a few failed attempts, any route change
# ("addRunConfigFailed" / "updateRunConfigFailed", also when sent to the API
# by hand). The provider rolls such half-created routes back.
resource "sophosfirewall_static_route" "blackhole" {
  count       = var.static_routes ? 1 : 0
  name        = "TF-Live-Sinkhole"
  destination = "10.98.201.0/24"
  interface   = "Blackhole"
}

resource "sophosfirewall_sdwan_route" "first" {
  name        = "TF-Live-SDWAN-1"
  description = local.desc
  position    = "bottom"
  source_networks = {
    ipv4_groups = [sophosfirewall_ipv4_group.this.name]
  }
  services = [sophosfirewall_service.tcp_udp.name]
  link_selection = {
    primary_gateway = { name = sophosfirewall_gateway.this.name }
  }
}

resource "sophosfirewall_sdwan_route" "second" {
  name               = "TF-Live-SDWAN-2"
  position           = "after"
  position_reference = sophosfirewall_sdwan_route.first.name
  destination_networks = {
    ipv4_addresses = [sophosfirewall_ipv4_address.network.name]
  }
  link_selection = {
    primary_gateway = { name = sophosfirewall_gateway.this.name }
    backup_gateway  = { wan_link_load_balance = true }
  }
}

# ---------------------------------------------------------- authentication ---

resource "sophosfirewall_user_group" "this" {
  name                 = "TF-Live-Users"
  description          = local.desc
  surfing_quota_policy = "Unlimited Internet Access"
  access_time_policy   = var.v2 ? "Allowed only during Work Hours" : "Allowed all the time"
}

# ----------------------------------------------- schedules / web / DNS ------

resource "sophosfirewall_schedule" "recurring" {
  name        = "TF-Live-Schedule"
  description = local.desc
  type        = "recurring"
  time_slots = var.v2 ? [
    { day_of_week = "weekdays", start_time = "07:00", end_time = "19:00" },
    { day_of_week = "sat", start_time = "09:00", end_time = "13:00" },
    ] : [
    { day_of_week = "weekdays", start_time = "08:00", end_time = "18:00" },
  ]
}

resource "sophosfirewall_schedule" "one_time" {
  name       = "TF-Live-Window"
  type       = "oneTime"
  start_date = "2027-01-02 00:00:00"
  end_date   = var.v2 ? "2027-01-04 00:00:00" : "2027-01-03 00:00:00"
  time_slots = [{ day_of_week = "allDays", start_time = "00:00", end_time = "23:59" }]
}

resource "sophosfirewall_url_group" "this" {
  name        = "TF-Live-URLs"
  description = local.desc
  urls        = var.v2 ? ["tf-live.example.com", "cdn.tf-live.example.com", "tf-live.example.org"] : ["tf-live.example.com", "cdn.tf-live.example.com"]
}

resource "sophosfirewall_dns_host_entry" "this" {
  name                      = "TF-Live-DNS"
  domain                    = "host.tf-live.example.com"
  enable_reverse_resolution = var.v2
  addresses = [
    { ipv4_address = "10.98.10.10", ttl = var.v2 ? 300 : 3600 },
    { ipv6_address = "fd98::10" },
  ]
}

resource "sophosfirewall_dns_host_entry" "interface" {
  name   = "TF-Live-DNS-Iface"
  domain = "port3.tf-live.example.com"
  addresses = [
    { ipv4_interface = sophosfirewall_physical_interface.port3.name },
  ]
}

# ---------------------------------------------------------- firewall / NAT ---

resource "sophosfirewall_firewall_rule" "allow" {
  name              = "TF-Live-Allow"
  description       = local.desc
  position          = "bottom"
  source_zones      = ["LAN"]
  destination_zones = [sophosfirewall_zone.this.name]
  source_networks = {
    ipv4_groups = [sophosfirewall_ipv4_group.this.name]
  }
  destination_networks = {
    ipv4_addresses = [sophosfirewall_ipv4_address.host.name]
    fqdn_groups    = [sophosfirewall_fqdn_group.this.name]
  }
  service_groups = [sophosfirewall_service_group.this.name]
  log_traffic    = var.v2
  schedule       = sophosfirewall_schedule.recurring.name
}

resource "sophosfirewall_firewall_rule" "drop" {
  name               = "TF-Live-Drop"
  action             = "drop"
  position           = "after"
  position_reference = sophosfirewall_firewall_rule.allow.name
  source_networks = {
    ipv4_addresses = [sophosfirewall_ipv4_address.range.name]
    country_groups = [sophosfirewall_country_group.this.name]
  }
}

resource "sophosfirewall_nat_rule" "snat" {
  name                = "TF-Live-SNAT"
  description         = local.desc
  position            = "bottom"
  outbound_interfaces = ["Port2"]
  original_source_networks = {
    ipv4_addresses = [sophosfirewall_ipv4_address.network.name]
  }
  translated_source = { masquerade = true }
}

resource "sophosfirewall_nat_rule" "dnat" {
  name               = "TF-Live-DNAT"
  position           = "after"
  position_reference = sophosfirewall_nat_rule.snat.name
  original_destination_networks = {
    ipv4_addresses = [sophosfirewall_ipv4_address.list.name]
  }
  original_services      = [var.v2 ? "HTTP" : "HTTPS"]
  translated_destination = { ipv4_address = sophosfirewall_ipv4_address.host.name }
}

# ------------------------------------------------- security policies (23.2) --

resource "sophosfirewall_web_policy" "this" {
  name                = "TF-Live-WebPolicy"
  description         = local.desc
  default_action      = "allow"
  enforce_safe_search = var.v2
  youtube_filter      = var.v2 ? "moderate" : "off"
  rules = concat(
    [{
      categories  = ["Hacking"]
      url_groups  = [sophosfirewall_url_group.this.name]
      http_action = "deny"
    }],
    var.v2 ? [{
      categories         = ["Advertisements"]
      http_action        = "deny"
      follow_http_action = false
      https_action       = "warn"
      schedule           = sophosfirewall_schedule.recurring.name
    }] : [],
  )
}

resource "sophosfirewall_web_exception" "this" {
  name        = "TF-Live-WebException"
  description = local.desc
  enabled     = !var.v2
  conditions = {
    web_categories  = ["Hacking"]
    source_networks = var.v2 ? ["10.98.50.0/24", "10.98.51.0/24"] : ["10.98.50.0/24"]
  }
  skip = {
    https_decryption       = true
    certificate_validation = true
    malware_scanning       = var.v2
  }
}

resource "sophosfirewall_traffic_shaping_policy" "this" {
  name            = "TF-Live-QoS"
  description     = local.desc
  associates_with = "rules"
  type            = "bestEffort"
  bandwidth = {
    limit = var.v2 ? { aggregated_kbps = 20480 } : { aggregated_kbps = 10240 }
  }
  scheduled_overrides = [{
    schedule  = sophosfirewall_schedule.recurring.name
    bandwidth = { limit = { aggregated_kbps = var.v2 ? 2048 : 1024 } }
  }]
}

resource "sophosfirewall_ips_policy" "this" {
  name        = "TF-Live-IPS"
  description = local.desc
  rules = concat(
    var.v2 ? [{ name = "TFLive-Client", targets = ["Client"], action = "dropPacket" }] : [],
    [{
      name       = "TFLive-Critical"
      action     = var.v2 ? "dropSession" : "dropPacket"
      severities = ["Critical", "Major"]
      targets    = ["Server"]
      platforms  = ["Linux", "Windows"]
    }],
  )
}

resource "sophosfirewall_application_filter_policy" "this" {
  name        = "TF-Live-AppPolicy"
  description = local.desc
  rules = concat(
    [{
      name         = "TFLive-Allow-Teams"
      action       = "allow"
      applications = ["Microsoft Teams"]
    }],
    [{
      name     = "TFLive-Deny-Risky"
      action   = "deny"
      risks    = var.v2 ? ["High", "Very High"] : ["Very High"]
      schedule = var.v2 ? sophosfirewall_schedule.recurring.name : null
    }],
  )
}

# Applies all four policies; only matches the unused 10.98.10.0/24 network.
resource "sophosfirewall_firewall_rule" "secure" {
  name              = "TF-Live-Secure"
  position          = var.v2 ? "top" : "bottom"
  source_zones      = ["LAN"]
  destination_zones = ["WAN"]
  source_networks = {
    ipv4_addresses = [sophosfirewall_ipv4_address.network.name]
  }
  security_features = {
    web_policy         = sophosfirewall_web_policy.this.name
    ips_policy         = sophosfirewall_ips_policy.this.name
    application_policy = sophosfirewall_application_filter_policy.this.name
  }
  qos = {
    traffic_shaping_policy = sophosfirewall_traffic_shaping_policy.this.name
  }
  depends_on = [sophosfirewall_firewall_rule.drop]
}

# ------------------------------------------------------------ data sources ---
# One per data source type; each reads back an object created above (or a
# built-in one) and the outputs are compared with the resources.

data "sophosfirewall_ipv4_address" "this" { name = sophosfirewall_ipv4_address.host.name }
data "sophosfirewall_ipv6_address" "this" { name = sophosfirewall_ipv6_address.host.name }
data "sophosfirewall_mac_address" "this" { name = sophosfirewall_mac_address.single.name }
data "sophosfirewall_fqdn_address" "this" { name = sophosfirewall_fqdn_address.a.name }
data "sophosfirewall_country_group" "this" { name = sophosfirewall_country_group.this.name }
data "sophosfirewall_ipv4_group" "this" { name = sophosfirewall_ipv4_group.this.name }
data "sophosfirewall_ipv6_group" "this" { name = sophosfirewall_ipv6_group.this.name }
data "sophosfirewall_fqdn_group" "this" { name = sophosfirewall_fqdn_group.this.name }
data "sophosfirewall_service" "builtin" { name = "HTTPS" }
data "sophosfirewall_service" "this" { name = sophosfirewall_service.tcp_udp.name }
data "sophosfirewall_service_group" "this" { name = sophosfirewall_service_group.this.name }
data "sophosfirewall_zone" "builtin" { name = "LAN" }
data "sophosfirewall_zone" "this" { name = sophosfirewall_zone.this.name }
data "sophosfirewall_interface" "port1" { name = "Port1" }
data "sophosfirewall_interface" "vlan" { name = sophosfirewall_interface.vlan.name }
data "sophosfirewall_dhcp_server" "this" { name = sophosfirewall_dhcp_server.this.name }
data "sophosfirewall_gateway" "this" { name = sophosfirewall_gateway.this.name }
data "sophosfirewall_static_route" "this" {
  count = var.static_routes ? 1 : 0
  name  = sophosfirewall_static_route.blackhole[0].name
}
data "sophosfirewall_sdwan_route" "this" { name = sophosfirewall_sdwan_route.first.name }
data "sophosfirewall_user_group" "builtin" { name = "Open Group" }
data "sophosfirewall_user_group" "this" { name = sophosfirewall_user_group.this.name }
data "sophosfirewall_firewall_rule" "this" { name = sophosfirewall_firewall_rule.allow.name }
data "sophosfirewall_nat_rule" "this" { name = sophosfirewall_nat_rule.snat.name }
data "sophosfirewall_schedule" "this" { name = sophosfirewall_schedule.recurring.name }
data "sophosfirewall_url_group" "this" { name = sophosfirewall_url_group.this.name }
data "sophosfirewall_dns_host_entry" "this" { name = sophosfirewall_dns_host_entry.this.name }
data "sophosfirewall_web_policy" "builtin" { name = "Default Workplace Policy" }
data "sophosfirewall_web_policy" "this" { name = sophosfirewall_web_policy.this.name }
data "sophosfirewall_web_exception" "this" { name = sophosfirewall_web_exception.this.name }
data "sophosfirewall_traffic_shaping_policy" "this" { name = sophosfirewall_traffic_shaping_policy.this.name }
data "sophosfirewall_ips_policy" "builtin" { name = "generalpolicy" }
data "sophosfirewall_ips_policy" "this" { name = sophosfirewall_ips_policy.this.name }
data "sophosfirewall_application_filter_policy" "builtin" { name = "Block high risk (Risk Level 4 and 5) apps" }
data "sophosfirewall_application_filter_policy" "this" { name = sophosfirewall_application_filter_policy.this.name }

output "data_source_checks" {
  description = "Every value must be true."
  value = {
    ipv4_address  = data.sophosfirewall_ipv4_address.this.id == sophosfirewall_ipv4_address.host.id
    ipv6_address  = data.sophosfirewall_ipv6_address.this.id == sophosfirewall_ipv6_address.host.id
    mac_address   = data.sophosfirewall_mac_address.this.id == sophosfirewall_mac_address.single.id
    fqdn_address  = data.sophosfirewall_fqdn_address.this.id == sophosfirewall_fqdn_address.a.id
    country_group = data.sophosfirewall_country_group.this.id == sophosfirewall_country_group.this.id
    ipv4_group    = data.sophosfirewall_ipv4_group.this.id == sophosfirewall_ipv4_group.this.id
    ipv6_group    = data.sophosfirewall_ipv6_group.this.id == sophosfirewall_ipv6_group.this.id
    fqdn_group    = data.sophosfirewall_fqdn_group.this.id == sophosfirewall_fqdn_group.this.id
    service_built = data.sophosfirewall_service.builtin.id != ""
    service       = data.sophosfirewall_service.this.id == sophosfirewall_service.tcp_udp.id
    service_group = data.sophosfirewall_service_group.this.id == sophosfirewall_service_group.this.id
    zone_built    = data.sophosfirewall_zone.builtin.id != ""
    zone          = data.sophosfirewall_zone.this.id == sophosfirewall_zone.this.id
    interface     = data.sophosfirewall_interface.vlan.id == sophosfirewall_interface.vlan.id
    port1         = data.sophosfirewall_interface.port1.id != ""
    dhcp_server   = data.sophosfirewall_dhcp_server.this.id == sophosfirewall_dhcp_server.this.id
    gateway       = data.sophosfirewall_gateway.this.id == sophosfirewall_gateway.this.id
    static_route  = var.static_routes ? data.sophosfirewall_static_route.this[0].id == sophosfirewall_static_route.blackhole[0].id : true
    sdwan_route   = data.sophosfirewall_sdwan_route.this.id == sophosfirewall_sdwan_route.first.id
    user_built    = data.sophosfirewall_user_group.builtin.id != ""
    user_group    = data.sophosfirewall_user_group.this.id == sophosfirewall_user_group.this.id
    firewall_rule = data.sophosfirewall_firewall_rule.this.id == sophosfirewall_firewall_rule.allow.id
    nat_rule      = data.sophosfirewall_nat_rule.this.id == sophosfirewall_nat_rule.snat.id
    schedule      = data.sophosfirewall_schedule.this.id == sophosfirewall_schedule.recurring.id
    url_group     = data.sophosfirewall_url_group.this.id == sophosfirewall_url_group.this.id
    dns_host      = data.sophosfirewall_dns_host_entry.this.id == sophosfirewall_dns_host_entry.this.id
    web_built     = data.sophosfirewall_web_policy.builtin.id != ""
    web_policy    = data.sophosfirewall_web_policy.this.id == sophosfirewall_web_policy.this.id
    web_exception = data.sophosfirewall_web_exception.this.id == sophosfirewall_web_exception.this.id
    qos_policy    = data.sophosfirewall_traffic_shaping_policy.this.id == sophosfirewall_traffic_shaping_policy.this.id
    ips_built     = data.sophosfirewall_ips_policy.builtin.id != ""
    ips_policy    = data.sophosfirewall_ips_policy.this.id == sophosfirewall_ips_policy.this.id
    app_built     = data.sophosfirewall_application_filter_policy.builtin.id != ""
    app_policy    = data.sophosfirewall_application_filter_policy.this.id == sophosfirewall_application_filter_policy.this.id
  }
}
