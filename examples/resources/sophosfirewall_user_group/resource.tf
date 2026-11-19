resource "sophosfirewall_user_group" "engineering" {
  name                 = "Engineering"
  description          = "Engineering staff"
  surfing_quota_policy = "Unlimited Internet Access"
  access_time_policy   = "Allowed all the time"

  quarantine_digest   = true
  ssl_vpn_policy      = "Remote engineers"
  ipsec_remote_access = true

}
