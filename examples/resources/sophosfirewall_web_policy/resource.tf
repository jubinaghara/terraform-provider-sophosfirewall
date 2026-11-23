resource "sophosfirewall_url_group" "blocked" {
  name = "Blocked-Sites"
  urls = ["example.net"]
}

resource "sophosfirewall_web_policy" "staff" {
  name                = "Staff"
  description         = "Web policy for staff"
  default_action      = "allow"
  enforce_safe_search = true
  youtube_filter      = "moderate"
  restrict_file_size  = true
  max_file_size       = 500

  # Rules are evaluated top to bottom.
  rules = [
    {
      # Omitting users and user_groups applies the rule to anybody.
      categories  = ["Gambling", "Weapons"]
      url_groups  = [sophosfirewall_url_group.blocked.name]
      http_action = "deny"
    },
    {
      user_groups = ["Sales"]
      categories  = ["Social Networking"]
      http_action = "quota"
      schedule    = "Work hours"
    },
    {
      # Different actions for HTTP and HTTPS.
      file_types         = ["Executable Files"]
      http_action        = "deny"
      follow_http_action = false
      https_action       = "warn"
    },
  ]
}
