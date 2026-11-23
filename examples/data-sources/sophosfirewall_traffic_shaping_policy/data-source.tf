data "sophosfirewall_traffic_shaping_policy" "voip" {
  name = "VoIP"
}

output "voip_limit_kbps" {
  value = data.sophosfirewall_traffic_shaping_policy.voip.bandwidth.limit.aggregated_kbps
}
