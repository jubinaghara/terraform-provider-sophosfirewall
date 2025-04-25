# Configure the Sophos provider
provider "sophos" {
  url      = "https://192.168.1.1:4444"
  username = "admin"
  password = var.sophos_password
}

# Create a basic firewall rule
resource "sophos_firewall_rule" "allow_internal_web" {
  name        = "Allow Internal Web Traffic"
  description = "Allow HTTP/HTTPS traffic from LAN to WAN"
  policy_type = "Network"
  status      = "Enable"
  position    = "Top"
  ip_family   = "IPv4"
  
  # Rule action
  action             = "Accept"
  log_traffic        = "Enable"
  skip_local_destined = "Disable"
  
  # Zone settings
  source_zones      = ["LAN"]
  destination_zones = ["WAN"]
  
  # Network settings
  source_networks      = ["LAN_NETWORK"]
  destination_networks = ["Any"]
}

# Create a rule positioned after another rule
resource "sophos_firewall_rule" "block_social_media" {
  name        = "Block Social Media"
  description = "Block access to social media sites"
  policy_type = "Network"
  status      = "Enable"
  position    = "After"
  after_rule  = sophos_firewall_rule.allow_internal_web.name
  
  # Rule action
  action             = "Drop"
  log_traffic        = "Enable"
  skip_local_destined = "Disable"
  
  # Zone settings
  source_zones      = ["LAN"]
  destination_zones = ["WAN"]
  
  # Schedule
  schedule = "Business_Hours"
}

# Create a rule positioned before another rule
resource "sophos_firewall_rule" "allow_voip" {
  name        = "Allow VoIP Traffic"
  description = "Allow VoIP traffic for IP phones"
  policy_type = "Network"
  status      = "Enable"
  position    = "Before"
  before_rule = sophos_firewall_rule.block_social_media.name
  
  # Rule action
  action             = "Accept"
  log_traffic        = "Enable"
  skip_local_destined = "Disable"
  
  # Zone settings
  source_zones      = ["LAN"]
  destination_zones = ["WAN"]
}

# Create a rule at the bottom of the ruleset
resource "sophos_firewall_rule" "default_block" {
  name        = "Default Block"
  description = "Block all other traffic"
  policy_type = "Network"
  status      = "Enable"
  position    = "Bottom"
  
  # Rule action
  action             = "Drop"
  log_traffic        = "Enable"
  skip_local_destined = "Disable"
  
  # Zone settings
  source_zones      = ["Any"]
  destination_zones = ["Any"]
}

# Variables
variable "sophos_password" {
  description = "Password for Sophos Firewall"
  type        = string
  sensitive   = true
}

---
page_title: "sophosfirewall_iphost Resource - terraform-provider-sophosfirewall"
subcategory: "Firewall"
description: |-
  Manages IP host objects in Sophos Firewall.
---

# Resource: sophosfirewall_iphost

Manages IP host objects in Sophos Firewall. IP hosts are used to define individual IP addresses, ranges, or networks that can be referenced in firewall rules.

## Example Usage

### Single IP Address

```terraform
resource "sophosfirewall_iphost" "web_server" {
  name       = "web_server"
  ip_family  = "IPv4"
  host_type  = "IP"
  ip_address = "192.168.1.10"
}
```

### IP Range

```terraform
resource "sophosfirewall_iphost" "dhcp_range" {
  name             = "dhcp_clients"
  ip_family        = "IPv4"
  host_type        = "Range"
  start_ip_address = "192.168.1.100"
  end_ip_address   = "192.168.1.200"
}
```

### Network Subnet

```terraform
resource "sophosfirewall_iphost" "internal_lan" {
  name       = "internal_lan"
  ip_family  = "IPv4"
  host_type  = "Network"
  ip_address = "10.0.0.0"
  subnet     = "255.255.0.0"
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required) The name of the IP host object.
* `ip_family` - (Required) IP address family. Valid values are `IPv4` or `IPv6`.
* `host_type` - (Required) Type of host object. Valid values are `IP`, `Range`, or `Network`.
* `ip_address` - (Required for `IP` and `Network` types) The IP address.
* `subnet` - (Required for `Network` type) The subnet mask.
* `start_ip_address` - (Required for `Range` type) The start IP address of the range.
* `end_ip_address` - (Required for `Range` type) The end IP address of the range.

## Attribute Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The ID of the IP host object. This is the same as the `name`.

## Import

IP host objects can be imported using the name:

```
terraform import sophosfirewall_iphost.web_server web_server
```
