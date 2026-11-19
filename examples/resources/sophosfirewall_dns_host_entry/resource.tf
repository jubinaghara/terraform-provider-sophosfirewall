resource "sophosfirewall_dns_host_entry" "intranet" {
  name                      = "intranet"
  domain                    = "intranet.example.com"
  enable_reverse_resolution = true

  addresses = [
    { ipv4_address = "192.0.2.10" },
    { ipv6_address = "2001:db8::10", ttl = 300 },
  ]
}

# Answer with the current address of a firewall interface.
resource "sophosfirewall_dns_host_entry" "vpn" {
  name   = "vpn"
  domain = "vpn.example.com"

  addresses = [
    { ipv4_interface = "Port2", publish_on_wan = true },
  ]
}
