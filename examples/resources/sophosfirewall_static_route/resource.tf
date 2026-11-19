# Reach a branch office network through a next-hop router on Port1.
resource "sophosfirewall_static_route" "branch" {
  name        = "branch-office"
  description = "Branch office LAN"
  destination = "192.168.10.0/24"
  gateway     = "172.16.16.1"
  interface   = "Port1"
  metric      = 10
}

# Drop traffic to a network (blackhole route).
resource "sophosfirewall_static_route" "sinkhole" {
  name        = "sinkhole"
  destination = "198.51.100.0/24"
  interface   = "Blackhole"
}
