data "sophosfirewall_dns_host_entry" "intranet" {
  name = "intranet"
}

output "intranet_addresses" {
  value = data.sophosfirewall_dns_host_entry.intranet.addresses
}
