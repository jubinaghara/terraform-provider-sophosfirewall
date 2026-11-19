resource "sophosfirewall_ipv6_address" "corp_v6" {
  name    = "corp-v6"
  network = "2001:db8:10::/64"
}

resource "sophosfirewall_ipv6_address" "web_v6" {
  name       = "web-v6"
  ip_address = "2001:db8:10::10"
}
