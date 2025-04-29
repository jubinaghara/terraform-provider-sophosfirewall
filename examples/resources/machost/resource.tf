#Single MAC address
resource "sophosfirewall_machost" "ExampleMACAddress" {
  name      = "ExampleMACAddress"
  type       = "MACAddress"
  description = "test"
  mac_address = "00:16:76:49:33:CE"
}

#MAC list
resource "sophosfirewall_machost" "ExampleMACList" {
  name      = "ExampleMACList"
  type      = "MACLIST"
   description = "test"
  list_of_mac_addresses = "00:16:76:49:33:CE,00:16:76:49:33:CB"
}

