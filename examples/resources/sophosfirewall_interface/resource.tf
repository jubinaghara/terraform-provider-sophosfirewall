# VLAN on a physical port
resource "sophosfirewall_interface" "guest_vlan" {
  name = "Port2.100"
  type = "vlan"
  zone = "LAN"

  vlan = {
    parent_interface = "Port2"
    vlan_id          = 100
  }

  ipv4 = {
    assignment_type = "static"
    address         = "10.100.0.1/24"
  }
}

# Link aggregation group
resource "sophosfirewall_interface" "uplink" {
  name          = "Lag1"
  hardware_name = "Lag1"
  type          = "lag"

  lag = {
    members             = ["Port6", "Port7"]
    mode                = "lacp8023ad"
    load_balance_method = "layer3And4"
  }

  ipv4 = {
    assignment_type = "static"
    address         = "10.60.0.1/24"
  }
}

# Bridge
resource "sophosfirewall_interface" "bridge" {
  name          = "Bridge1"
  hardware_name = "Bridge1"
  type          = "bridge"
  description   = "Transparent segment"

  bridge = {
    members = [
      { interface = "Port8", zone = "LAN" },
      { interface = "Port9", zone = "LAN" },
    ]
    stp = true
  }

  ipv4 = {
    assignment_type = "static"
    address         = "192.168.50.1/24"
  }
}
