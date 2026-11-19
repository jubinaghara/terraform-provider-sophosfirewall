resource "sophosfirewall_ipv4_address" "web1" {
  name       = "web-01"
  ip_address = "203.0.113.10"
}

resource "sophosfirewall_ipv4_address" "web2" {
  name       = "web-02"
  ip_address = "203.0.113.11"
}

resource "sophosfirewall_ipv4_group" "web" {
  name        = "web-servers"
  description = "Public web servers"
  addresses = [
    sophosfirewall_ipv4_address.web1.name,
    sophosfirewall_ipv4_address.web2.name,
  ]
}
