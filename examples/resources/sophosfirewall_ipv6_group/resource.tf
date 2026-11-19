resource "sophosfirewall_ipv6_address" "dns" {
  name       = "dns-v6"
  ip_address = "2001:db8::53"
}

resource "sophosfirewall_ipv6_group" "infra" {
  name        = "infra-v6"
  description = "Infrastructure IPv6 hosts"
  addresses   = [sophosfirewall_ipv6_address.dns.name]
}
