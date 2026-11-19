resource "sophosfirewall_url_group" "shopping" {
  name        = "Allowed-Shopping"
  description = "Approved shopping domains"
  urls        = ["amazon.com", "ebay.com", "cdn.shopify.com"]
}

# Large lists (up to 10,000 domains per group) are best kept in a file,
# one domain per line.
resource "sophosfirewall_url_group" "blocklist" {
  name = "Blocklist"
  urls = toset(compact(split("\n", file("${path.module}/blocklist.txt"))))
}
