resource "sophosfirewall_fqdn_address" "updates" {
  name = "vendor-updates"
  fqdn = "*.updates.example.com"
}
