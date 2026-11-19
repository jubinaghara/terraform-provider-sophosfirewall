resource "sophosfirewall_dhcp_server" "lan" {
  name               = "LAN DHCP"
  interface          = "Port1"
  prefix_length      = 24
  gateway            = "192.168.1.1"
  default_lease_time = 1440
  max_lease_time     = 2880

  domain_name   = "branch.local"
  primary_dns   = "192.168.1.1"
  secondary_dns = "1.1.1.1"

  conflict_detection = true

  address_pools = [
    { start_address = "192.168.1.100", end_address = "192.168.1.200" },
  ]

  static_mappings = [
    { mac_address = "00:11:22:33:44:55", ip_address = "192.168.1.50", hostname = "printer-01" },
  ]

  # PXE boot
  boot_server = "192.168.1.20"
  boot_file   = "pxelinux.0"

  dhcp_options = [
    { code = 42, value = "192.168.1.1" },                      # NTP servers (standard code)
    { code = 150, type = "ipv4Addr", value = "192.168.1.20" }, # custom code: type is required
  ]
}
