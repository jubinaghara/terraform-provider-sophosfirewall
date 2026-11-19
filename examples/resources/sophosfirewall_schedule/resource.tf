# A weekly schedule, e.g. for rules that only apply during office hours.
resource "sophosfirewall_schedule" "office_hours" {
  name        = "Office-Hours"
  description = "Weekdays 08:00-18:00, Saturday mornings"
  type        = "recurring"

  time_slots = [
    { day_of_week = "weekdays", start_time = "08:00", end_time = "18:00" },
    { day_of_week = "sat", start_time = "09:00", end_time = "13:00" },
  ]
}

# A one-time maintenance window.
resource "sophosfirewall_schedule" "maintenance" {
  name       = "Maintenance-2026-12"
  type       = "oneTime"
  start_date = "2026-12-24 00:00:00"
  end_date   = "2026-12-27 00:00:00"

  time_slots = [
    { day_of_week = "allDays", start_time = "00:00", end_time = "23:59" },
  ]
}

# Firewall rules reference schedules by name.
resource "sophosfirewall_firewall_rule" "guest_web" {
  name              = "guest-web-office-hours"
  source_zones      = ["LAN"]
  destination_zones = ["WAN"]
  services          = ["HTTP", "HTTPS"]
  schedule          = sophosfirewall_schedule.office_hours.name
}
