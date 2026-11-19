# Physical ports always exist; this resource adopts and configures one.
# Destroying it only stops Terraform from managing the port.
resource "sophosfirewall_physical_interface" "wan" {
  name = "Port2"
  zone = "WAN"
  mtu  = 1500

  ipv4 = {
    assignment_type = "static"
    address         = "198.51.100.30/24"
    gateway_name    = "isp-gateway"
    gateway_address = "198.51.100.1"
  }
}
