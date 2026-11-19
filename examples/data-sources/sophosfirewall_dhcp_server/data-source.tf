data "sophosfirewall_dhcp_server" "lan" {
  name = "LAN DHCP"
}

output "lan_dhcp_pools" {
  value = data.sophosfirewall_dhcp_server.lan.address_pools
}
