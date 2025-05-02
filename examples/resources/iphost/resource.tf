# Simple IP host example
resource "sophosfirewall_iphost" "single_ip" {
  name       = "web_server"
  ip_family  = "IPv4"
  host_type  = "IP"
  ip_address = "192.168.1.10"
}

# IP Range example
resource "sophosfirewall_iphost" "ip_range" {
  name            = "dhcp_clients"
  ip_family       = "IPv4"
  host_type       = "IPRange"
  start_ip_address = "192.168.1.100"
  end_ip_address   = "192.168.1.200"
}

# Network example
resource "sophosfirewall_iphost" "network" {
  name       = "internal_lan"
  ip_family  = "IPv4"
  host_type  = "Network"
  ip_address = "10.0.0.0"
  subnet     = "255.255.0.0"
}

# IPv6 example
resource "sophosfirewall_iphost" "ipv6_host" {
  name       = "ipv6_server"
  ip_family  = "IPv6"
  host_type  = "IP"
  ip_address = "2001:db8::1"
}