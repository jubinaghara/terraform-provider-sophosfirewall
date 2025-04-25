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