# Source NAT: masquerade LAN traffic leaving through Port2.
resource "sophosfirewall_nat_rule" "outbound" {
  name                = "lan-masquerade"
  outbound_interfaces = ["Port2"]
  original_source_networks = {
    ipv4_addresses = ["corp-lan"]
  }
  translated_source = { masquerade = true }
}

# Destination NAT / port forwarding to an internal web server.
resource "sophosfirewall_nat_rule" "web_forward" {
  name               = "web-port-forward"
  position           = "top"
  inbound_interfaces = ["Port2"]
  original_destination_networks = {
    ipv4_addresses = ["wan-public-ip"]
  }
  original_services      = ["HTTPS"]
  translated_destination = { ipv4_address = "web-server" }
}
