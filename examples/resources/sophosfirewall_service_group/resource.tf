# Groups can mix built-in services and services managed by Terraform.
resource "sophosfirewall_service" "app" {
  name    = "app-https"
  tcp_udp = [{ protocol = "tcp", destination_port = "8443" }]
}

resource "sophosfirewall_service_group" "web" {
  name        = "web-services"
  description = "Web traffic"
  services    = ["HTTP", "HTTPS", sophosfirewall_service.app.name]
}
