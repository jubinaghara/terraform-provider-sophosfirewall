# Built-in services cannot be managed, but can be looked up.
data "sophosfirewall_service" "https" {
  name = "HTTPS"
}

output "https_ports" {
  value = data.sophosfirewall_service.https.tcp_udp[*].destination_port
}
