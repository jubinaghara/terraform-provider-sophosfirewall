data "sophosfirewall_web_policy" "default" {
  name = "Default Workplace Policy"
}

output "default_workplace_rules" {
  value = length(data.sophosfirewall_web_policy.default.rules)
}
