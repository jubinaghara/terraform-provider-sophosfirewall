# A small but complete setup: objects, a zone, a VLAN, firewall and NAT rules.
terraform {
  required_providers {
    sophosfirewall = {
      source = "jubinaghara/sophosfirewall"
    }
  }
}

provider "sophosfirewall" {} # configured through SFOS_ENDPOINT / SFOS_API_KEY / SFOS_INSECURE

resource "sophosfirewall_zone" "iot" {
  name     = "IoT"
  type     = "lan"
  services = ["ping", "dns"]
}

resource "sophosfirewall_interface" "iot_vlan" {
  name = "Port3.20"
  type = "vlan"
  zone = sophosfirewall_zone.iot.name
  vlan = {
    parent_interface = "Port3"
    vlan_id          = 20
  }
  ipv4 = {
    assignment_type = "static"
    address         = "10.20.0.1/24"
  }
}

resource "sophosfirewall_ipv4_address" "iot_net" {
  name    = "iot-network"
  network = "10.20.0.0/24"
}

resource "sophosfirewall_fqdn_address" "iot_cloud" {
  name = "iot-cloud"
  fqdn = "*.iot.example.com"
}

resource "sophosfirewall_firewall_rule" "iot_to_cloud" {
  name              = "iot-to-cloud"
  source_zones      = [sophosfirewall_zone.iot.name]
  destination_zones = ["WAN"]
  source_networks = {
    ipv4_addresses = [sophosfirewall_ipv4_address.iot_net.name]
  }
  destination_networks = {
    fqdn_addresses = [sophosfirewall_fqdn_address.iot_cloud.name]
  }
  services    = ["HTTPS"]
  log_traffic = true
}

resource "sophosfirewall_firewall_rule" "iot_deny" {
  name               = "iot-deny-all"
  action             = "drop"
  position           = "after"
  position_reference = sophosfirewall_firewall_rule.iot_to_cloud.name
  source_zones       = [sophosfirewall_zone.iot.name]
  log_traffic        = true
}

resource "sophosfirewall_nat_rule" "iot_masq" {
  name                = "iot-masquerade"
  outbound_interfaces = ["Port2"]
  original_source_networks = {
    ipv4_addresses = [sophosfirewall_ipv4_address.iot_net.name]
  }
  translated_source = { masquerade = true }
}
