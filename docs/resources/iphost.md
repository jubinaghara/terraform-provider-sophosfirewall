---
page_title: "Sophos: sophos_iphost"
subcategory: "Network"
description: |-
  Manages a Sophos IP Host object.
---

# Resource: sophos_iphost

Manages a Sophos IP Host object. This resource allows you to create, update, and delete IP Host entries in your Sophos firewall.

## Example Usage

```hcl
resource "sophos_iphost" "webserver" {
  name        = "WebServer01"
  ip_address  = "192.168.1.100"
  description = "Primary web server"
}

# Simple IP host example
resource "sophosfirewall_iphost" "single_ip" {
  name       = "web_server"
  ip_family  = "IPv4"
  host_type  = "IP"
  ip_address = "192.168.1.10"
}

# IP Range example
resource "sophosfirewall_iphost" "ip_range" {
  name            = "dhcp_clients"
  ip_family       = "IPv4"
  host_type       = "Range"
  start_ip_address = "192.168.1.100"
  end_ip_address   = "192.168.1.200"
}

# Network example
resource "sophosfirewall_iphost" "network" {
  name       = "internal_lan"
  ip_family  = "IPv4"
  host_type  = "Network"
  ip_address = "10.0.0.0"
  subnet     = "255.255.0.0"
}

# IPv6 example
resource "sophosfirewall_iphost" "ipv6_host" {
  name       = "ipv6_server"
  ip_family  = "IPv6"
  host_type  = "IP"
  ip_address = "2001:db8::1"
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required) Name of the IP Host.
* `ip_address` - (Required) IP address of the host.
* `description` - (Optional) Description of the IP Host.

## Import

IP Hosts can be imported using the name, e.g.,

```
$ terraform import sophos_iphost.webserver WebServer01
```