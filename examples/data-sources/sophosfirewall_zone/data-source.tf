# Built-in zones cannot be created, but can be referenced.
data "sophosfirewall_zone" "lan" {
  name = "LAN"
}

output "lan_services" {
  value = data.sophosfirewall_zone.lan.services
}
