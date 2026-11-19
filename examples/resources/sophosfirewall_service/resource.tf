# TCP/UDP ports. Omitted ports default to "1:65535" (any port).
resource "sophosfirewall_service" "dns" {
  name        = "dns-custom"
  description = "DNS over UDP and TCP"
  tcp_udp = [
    { protocol = "udp", destination_port = "53" },
    { protocol = "tcp", source_port = "1024:65535", destination_port = "53" },
  ]
}

# IP protocols
resource "sophosfirewall_service" "vpn" {
  name         = "ipsec-protocols"
  ip_protocols = ["esp", "ah"]
}

# ICMP; the code defaults to "any".
resource "sophosfirewall_service" "ping" {
  name = "ping"
  icmp = [
    { type = "echoRequest" },
    { type = "echoReply" },
  ]
}

# ICMPv6
resource "sophosfirewall_service" "ndp" {
  name = "neighbor-discovery"
  icmpv6 = [
    { type = "neighborSolicitation", code = "noCode" },
    { type = "neighborAdvertisement", code = "noCode" },
  ]
}
