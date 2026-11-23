resource "sophosfirewall_ips_policy" "web_servers" {
  name        = "Web-Servers-IPS"
  description = "Protect public web servers"

  # Rules are evaluated in order.
  rules = [
    {
      # Select individual signatures by name.
      name       = "WebLogic-CVEs"
      action     = "reset"
      signatures = ["SERVER-ORACLE Oracle WebLogic Server CVE-2018-2894"]
    },
    {
      # Select by signature attributes; a signature must match every filter.
      name       = "Critical-Server"
      action     = "dropSession"
      severities = ["Critical", "Major"]
      targets    = ["Server"]
      platforms  = ["Linux", "Windows"]
    },
    {
      # Everything else aimed at servers gets the recommended action.
      name    = "Server-Recommended"
      targets = ["Server"]
    },
  ]
}

resource "sophosfirewall_firewall_rule" "dmz_web" {
  name              = "WAN-to-DMZ-Web"
  action            = "accept"
  source_zones      = ["WAN"]
  destination_zones = ["DMZ"]
  services          = ["HTTPS"]

  security_features = {
    ips_policy = sophosfirewall_ips_policy.web_servers.name
  }
}
