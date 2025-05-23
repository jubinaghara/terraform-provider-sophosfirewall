---
page_title: "Sophos: sophosfirewall_firewall_rule"
subcategory: "Firewall"
description: |-
  Manages a Sophos Firewall rule.
---

# Resource: sophos_firewall_rule

Manages a Sophos Firewall rule. This resource allows you to create, update, and delete firewall rules in your Sophos firewall.

## Example Usage

```hcl
resource "sophos_firewall_rule" "allow_internal_web" {
  name        = "allow_internal_web"
  description = "Allow HTTP/HTTPS traffic from LAN to WAN"
  policy_type = "Network"
  status      = "Enable"
  position    = "Top"
  ip_family   = "IPv4"
  
  # Rule action
  action                   = "Accept"
  log_traffic              = "Enable"
  skip_local_destined      = "Disable"
  schedule                 = "All The Time"
  
  # Zone settings
  source_zones      = ["LAN"]
  destination_zones = ["WAN"]
  
  # Network settings
  source_networks      = [sophosfirewall_iphost.terraformSrc2.name]
  destination_networks = [sophosfirewall_iphost.terraformDst3.name]

  depends_on = [
    sophosfirewall_iphost.terraformSrc2,
    sophosfirewall_iphost.terraformDst3
  ]

  #Advanced security
  traffic_shapping_policy          = "None"
  web_filter                       = "Allow All"
  scan_virus                       = "Enable"
  zero_day_protection              = "Enable"
  application_control              = "None"
  block_quick_quic                 = "Disable" 
  decrypt_https                    = "Disable" 
  dest_security_heartbeat          = "Disable" 
  source_security_heartbeat        = "Disable"
  dscp_marking                     = "-1" 
  intrusion_prevention             = "None" 
  minimum_destination_hb_permitted = "No Restriction" 
  minimum_source_hb_permitted      = "No Restriction" 
  proxy_mode                       = "Disable" 
  scan_ftp                         = "Disable" 
  scan_imap                        = "Disable" 
  scan_imaps                       = "Disable" 
  scan_pop3                        = "Disable" 
  scan_pop3s                       = "Disable" 
  scan_smtp                        = "Disable" 
  scan_smtps                       = "Disable" 
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required) Name of the firewall rule. Cannot be modified after creation.
* `description` - (Optional) Description of the rule.
* `ip_family` - (Optional) IP Family (IPv4 or IPv6). Defaults to IPv4.
* `status` - (Optional) Status (Enable or Disable). Defaults to Enable.
* `position` - (Optional) Position (Top, Bottom, After, Before). Where to position the rule.
* `policy_type` - (Required) Policy Type (Network).
* `after_rule` - (Optional) Rule to position after (used when position is 'After').
* `before_rule` - (Optional) Rule to position before (used when position is 'Before').
* `action` - (Required) Action (Accept, Reject, Drop).
* `log_traffic` - (Optional) Log traffic (Enable or Disable). Defaults to Disable.
* `skip_local_destined` - (Optional) Skip local destined (Enable or Disable). Defaults to Disable.
* `source_zones` - (Required) List of source zones.
* `destination_zones` - (Required) List of destination zones.
* `schedule` - (Optional) Schedule name. Defaults to "".
* `source_networks` - (Optional) List of source networks.
* `destination_networks` - (Optional) List of destination networks.

## Import

Firewall rules can be imported using the name, e.g.,

```
$ terraform import sophos_firewallrule.allow_internal_web "Allow Internal Web Traffic"
```