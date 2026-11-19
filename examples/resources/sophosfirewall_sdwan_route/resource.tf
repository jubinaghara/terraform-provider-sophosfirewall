# Send voice traffic over MPLS, falling back to WAN link load balancing.
resource "sophosfirewall_sdwan_route" "voice" {
  name              = "voice-over-mpls"
  position          = "top"
  inbound_interface = "Port2"
  source_networks = {
    ipv4_groups = ["lan-voice"]
  }
  services     = ["SIP"]
  dscp_marking = "46-Expedited Forwarding(EF)"

  link_selection = {
    primary_gateway = { name = sophosfirewall_gateway.mpls.name }
    backup_gateway  = { wan_link_load_balance = true }
  }
}

# Steer SaaS traffic of remote staff with an SD-WAN profile.
resource "sophosfirewall_sdwan_route" "saas" {
  name               = "saas"
  position           = "after"
  position_reference = sophosfirewall_sdwan_route.voice.name
  applications       = ["m365-apps"]
  user_groups        = ["remote-staff"]

  link_selection = {
    sdwan_profile                  = "saas-priority-profile"
    route_through_specific_gateway = true
  }
}
