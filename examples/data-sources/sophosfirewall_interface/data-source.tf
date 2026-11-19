data "sophosfirewall_interface" "port1" {
  name = "Port1"
}

output "port1_address" {
  value = data.sophosfirewall_interface.port1.ipv4.address
}
