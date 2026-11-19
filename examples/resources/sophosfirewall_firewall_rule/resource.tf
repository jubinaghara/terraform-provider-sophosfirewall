resource "sophosfirewall_firewall_rule" "allow_web" {
  name        = "allow-lan-web"
  description = "LAN users may browse the web"
  position    = "top"

  source_zones      = ["LAN"]
  destination_zones = ["WAN"]
  source_networks = {
    ipv4_addresses = ["corp-lan"]
  }
  services    = ["HTTP", "HTTPS"]
  log_traffic = true

  security_features = {
    web_policy                    = "Default Workplace Policy"
    scan_http_and_decrypted_https = true
    zero_day_protection           = true
    ips_policy                    = "generalpolicy"
  }
}

# Place a rule relative to another one.
resource "sophosfirewall_firewall_rule" "block_countries" {
  name               = "block-countries"
  action             = "drop"
  position           = "before"
  position_reference = sophosfirewall_firewall_rule.allow_web.name

  source_zones = ["WAN"]
  source_networks = {
    country_groups = ["blocked-countries"]
  }
}
