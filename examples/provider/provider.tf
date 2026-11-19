terraform {
  required_providers {
    sophosfirewall = {
      source  = "jubinaghara/sophosfirewall"
      version = "~> 23.0"
    }
  }
}

# The endpoint and API key can also come from SFOS_ENDPOINT and SFOS_API_KEY.
provider "sophosfirewall" {
  endpoint = "https://172.16.16.16:4444"
  api_key  = var.sophosfirewall_api_key
  insecure = true # appliance uses its factory self-signed certificate
}

variable "sophosfirewall_api_key" {
  type      = string
  sensitive = true
}
