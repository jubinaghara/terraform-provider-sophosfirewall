# Do not decrypt or inspect online banking for the finance department.
resource "sophosfirewall_web_exception" "banking" {
  name        = "Finance-Banking"
  description = "No HTTPS decryption for banking sites"

  conditions = {
    web_categories  = ["Banking"]
    source_networks = ["10.10.20.0/24"]
  }

  skip = {
    https_decryption       = true
    certificate_validation = true
  }
}

# Let a trusted update server through without malware scanning.
resource "sophosfirewall_web_exception" "updates" {
  name = "Vendor-Updates"

  conditions = {
    url_regexes          = ["^([A-Za-z0-9.-]*\\.)?updates\\.example\\.com/"]
    destination_networks = ["203.0.113.0/24", "2001:db8:100::/48"]
  }

  skip = {
    malware_scanning    = true
    zero_day_protection = true
  }
}
