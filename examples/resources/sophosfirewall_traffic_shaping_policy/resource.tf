# Cap each user at 10 Mbps, with a tighter limit during work hours.
resource "sophosfirewall_traffic_shaping_policy" "users" {
  name            = "Users-10M"
  description     = "Per-user cap"
  associates_with = "users"
  type            = "bestEffort"
  bandwidth = {
    limit = { aggregated_kbps = 10240 }
  }
  scheduled_overrides = [
    {
      schedule  = "Work hours (5 Day week)"
      bandwidth = { limit = { upload_kbps = 1024, download_kbps = 4096 } }
    },
  ]
}

# Guarantee 5 Mbps (burst to 20 Mbps) shared by all traffic of a rule.
resource "sophosfirewall_traffic_shaping_policy" "voip" {
  name            = "VoIP"
  associates_with = "rules"
  is_shared       = true
  type            = "guaranteed"
  bandwidth = {
    guaranteed = { aggregated_kbps = 5120 }
    limit      = { aggregated_kbps = 20480 }
  }
}

resource "sophosfirewall_firewall_rule" "voip" {
  name              = "voip"
  source_zones      = ["LAN"]
  destination_zones = ["WAN"]
  services          = ["SIP"]
  qos = {
    traffic_shaping_policy = sophosfirewall_traffic_shaping_policy.voip.name
  }
}
