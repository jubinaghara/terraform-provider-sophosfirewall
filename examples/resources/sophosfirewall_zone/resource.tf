resource "sophosfirewall_zone" "guest" {
  name        = "GuestWiFi"
  type        = "lan"
  description = "Guest wireless users"
  services    = ["ping", "dns", "captivePortal"]
}
