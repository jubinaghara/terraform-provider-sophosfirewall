# Custom gateway with a ping and a TCP health check.
resource "sophosfirewall_gateway" "mpls" {
  name       = "mpls-primary"
  ip_address = "192.0.2.1"
  interface  = "Port3"
  zone       = "WAN"

  health_check = {
    enabled  = true
    interval = 30
    timeout  = 2
    retries  = 3
    rules = [
      { protocol = "ping", host = "192.0.2.254" },
      { protocol = "tcp", host = "192.0.2.253", port = 443, logical_operator = "and" },
    ]
  }
}
