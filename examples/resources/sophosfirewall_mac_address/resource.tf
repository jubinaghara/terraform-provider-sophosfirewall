resource "sophosfirewall_mac_address" "printer" {
  name        = "office-printer"
  mac_address = "00:1a:2b:3c:4d:5e"
}

resource "sophosfirewall_mac_address" "kiosks" {
  name          = "kiosks"
  mac_addresses = ["00:1a:2b:3c:4d:01", "00:1a:2b:3c:4d:02"]
}
