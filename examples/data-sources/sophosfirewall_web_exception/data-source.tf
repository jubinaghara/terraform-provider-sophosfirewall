data "sophosfirewall_web_exception" "banking" {
  name = "Finance-Banking"
}

output "banking_skips_decryption" {
  value = data.sophosfirewall_web_exception.banking.skip.https_decryption
}
