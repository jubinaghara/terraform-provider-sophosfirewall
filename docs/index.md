---
page_title: "Provider: Sophos"
description: |-
  The Sophos provider is used to interact with the resources supported by Sophos Firewall. The provider needs to be configured with proper credentials before it can be used.
---

# Sophos Provider

The Sophos provider is used to interact with the resources supported by Sophos Firewall. The provider needs to be configured with proper credentials before it can be used.

Use the navigation on the left to read about the available resources.

## Example Usage

```hcl
# Configure the Sophos provider
provider "sophos" {
  url      = "https://192.168.1.1:4444"
  username = "admin"
  password = var.sophos_password
}

# Create a firewall rule
resource "sophos_firewall_rule" "example" {
  # ...resource configuration...
}
```

## Authentication

The Sophos provider offers a flexible means of providing credentials for authentication. The following methods are supported, and are explained in detail below:

- Static credentials
- Environment variables

### Static credentials

Static credentials can be provided by specifying the `username` and `password` attributes in the provider block:

```hcl
provider "sophos" {
  url      = "https://192.168.1.1:4444"
  username = "admin"
  password = "your-password"
}
```

### Environment variables

You can provide your credentials via the `SOPHOS_URL`, `SOPHOS_USERNAME` and `SOPHOS_PASSWORD` environment variables:

```hcl
provider "sophos" {}
```

```sh
export SOPHOS_URL="https://192.168.1.1:4444"
export SOPHOS_USERNAME="admin"
export SOPHOS_PASSWORD="your-password"
```

## Argument Reference

The following arguments are supported in the provider block:

* `url` - (Required) The URL of the Sophos Firewall. This can also be specified with the `SOPHOS_URL` environment variable.
* `username` - (Required) Username for Sophos Firewall. This can also be specified with the `SOPHOS_USERNAME` environment variable.
* `password` - (Required) Password for Sophos Firewall. This can also be specified with the `SOPHOS_PASSWORD` environment variable.
* `insecure` - (Optional) Whether to skip TLS verification. Defaults to `false`.
* `timeout` - (Optional) Timeout for API operations in seconds. Defaults to 60.