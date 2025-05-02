---
page_title: "Sophos: sophosfirewall_iphostgroup"
subcategory: "Host & Objects > Host Group"
description: |-
  Manages a Sophos IP Host Group object.
---

# Resource: sophos_iphost

Manages a Sophos IP Host Group object. This resource allows you to create, update, and delete IP Host entries in your Sophos firewall.

## Example Usage for Single IP address

```hcl
resource "sophosfirewall_iphostgroup" "example-host-group" {
  name       = "example-host-group"
  ip_family  = "IPv4"
  host_list = ["testHG"]
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required) Name of the IP Host.
* `ip_family` - (Required) IPv4 or IPv6
* `description` - (Optional) Description of the IP Host.

## Import

IP Hosts can be imported using the name, e.g.,

```
$ terraform import sophosfirewall_iphost.webserver WebServer01
```