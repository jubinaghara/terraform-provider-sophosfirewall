# Look up a built-in policy, e.g. to attach it to a firewall rule.
data "sophosfirewall_ips_policy" "general" {
  name = "generalpolicy"
}

output "general_policy_rules" {
  value = data.sophosfirewall_ips_policy.general.rules[*].name
}
