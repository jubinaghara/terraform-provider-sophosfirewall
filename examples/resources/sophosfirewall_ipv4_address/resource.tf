# A single host
resource "sophosfirewall_ipv4_address" "web_server" {
  name        = "web-server"
  description = "Public web server"
  ip_address  = "203.0.113.10"
}

# A network in CIDR notation
resource "sophosfirewall_ipv4_address" "corp_lan" {
  name    = "corp-lan"
  network = "192.0.2.0/24"
}

# An address range
resource "sophosfirewall_ipv4_address" "dhcp_pool" {
  name        = "dhcp-pool"
  range_start = "192.0.2.100"
  range_end   = "192.0.2.200"
}

# A list of hosts
resource "sophosfirewall_ipv4_address" "dns_servers" {
  name         = "dns-servers"
  ip_addresses = ["192.0.2.53", "198.51.100.53"]
}
