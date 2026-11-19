resource "sophosfirewall_fqdn_address" "updates" {
  name = "vendor-updates"
  fqdn = "*.updates.example.com"
}

resource "sophosfirewall_fqdn_address" "cdn" {
  name = "vendor-cdn"
  fqdn = "cdn.example.com"
}

resource "sophosfirewall_fqdn_group" "vendor" {
  name        = "vendor-services"
  description = "Hosts the vendor software needs to reach"
  addresses = [
    sophosfirewall_fqdn_address.updates.name,
    sophosfirewall_fqdn_address.cdn.name,
  ]
}
