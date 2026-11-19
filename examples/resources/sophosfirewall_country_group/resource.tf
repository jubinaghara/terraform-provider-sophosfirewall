resource "sophosfirewall_country_group" "blocked" {
  name        = "blocked-countries"
  description = "Countries we never accept traffic from"
  countries   = ["North Korea", "Iran"]
}
