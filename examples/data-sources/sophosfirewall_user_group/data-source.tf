# Built-in groups cannot be created, but can be referenced.
data "sophosfirewall_user_group" "open" {
  name = "Open Group"
}

output "open_group_surfing_quota" {
  value = data.sophosfirewall_user_group.open.surfing_quota_policy
}
