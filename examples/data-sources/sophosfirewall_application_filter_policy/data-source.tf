# Built-in policies can be referenced as well.
data "sophosfirewall_application_filter_policy" "high_risk" {
  name = "Block high risk (Risk Level 4 and 5) apps"
}

output "high_risk_rules" {
  value = data.sophosfirewall_application_filter_policy.high_risk.rules
}
