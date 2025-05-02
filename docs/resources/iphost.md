---
page_title: "Sophos: sophosfirewall_iphost"
subcategory: "Host & Objects > IP Host"
description: |-
  Manages a Sophos IP Host object.
---

# Resource: sophos_iphost

Manages a Sophos IP Host object. This resource allows you to create, update, and delete IP Host entries in your Sophos firewall.

## Example Usage for Single IP address

```hcl
resource "sophosfirewall_iphost" "single_ip" {
  name       = "web_server"
  ip_family  = "IPv4"
  host_type  = "IP"
  ip_address = "192.168.1.10"
}
```

## Example Usage for IP range
```hcl
resource "sophosfirewall_iphost" "ip_range" {
  name            = "dhcp_clients"
  ip_family       = "IPv4"
  host_type       = "IPRange"
  start_ip_address = "192.168.1.100"
  end_ip_address   = "192.168.1.200"
}
```

## Example Usage for Network
```hcl
resource "sophosfirewall_iphost" "network" {
  name       = "internal_lan"
  ip_family  = "IPv4"
  host_type  = "Network"
  ip_address = "10.0.0.0"
  subnet     = "255.255.0.0"
}
```

## Example Usage for IP list
```hcl
resource "sophosfirewall_iphost" "listofIPaddresstest1234" {
  name      = "listofIPaddresstest1234"
  ip_family  = "IPv4"
  host_type  = "IPList"
  list_of_ip_addresses  = "192.168.1.30,192.168.2.30"
}
```

## Example Usage for IPv6 address
```hcl
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
$ terraform import sophosfirewall_iphost.webserver WebServer01
```