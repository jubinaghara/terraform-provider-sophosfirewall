data "sophosfirewall_url_group" "shopping" {
  name = "Allowed-Shopping"
}

output "shopping_domains" {
  value = data.sophosfirewall_url_group.shopping.urls
}
