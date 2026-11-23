# Rules are evaluated top to bottom. Each rule matches either individual
# applications or applications selected by filters.
resource "sophosfirewall_application_filter_policy" "office" {
  name        = "office-apps"
  description = "Allow collaboration tools, block evasive and high-risk apps"

  rules = [
    {
      name         = "allow-collaboration"
      action       = "allow"
      applications = ["Microsoft Teams", "Slack", "Zoom"]
    },
    {
      name            = "deny-evasion"
      action          = "deny"
      categories      = ["Proxy and Tunnel"]
      characteristics = ["Can bypass firewall policy", "Tunnels other apps"]
    },
    {
      name       = "deny-p2p-office-hours"
      action     = "deny"
      categories = ["P2P"]
      schedule   = "Work hours (5 Day week)"
    },
  ]
}

# Firewall rules apply the policy to allowed traffic.
resource "sophosfirewall_firewall_rule" "lan_to_wan" {
  name              = "lan-to-wan"
  action            = "accept"
  source_zones      = ["LAN"]
  destination_zones = ["WAN"]

  security_features = {
    application_policy = sophosfirewall_application_filter_policy.office.name
  }
}
