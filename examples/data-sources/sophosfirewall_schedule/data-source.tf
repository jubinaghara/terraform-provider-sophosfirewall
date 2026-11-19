# Built-in schedules can be referenced as well.
data "sophosfirewall_schedule" "work_hours" {
  name = "Work hours (5 Day week)"
}

output "work_hours_slots" {
  value = data.sophosfirewall_schedule.work_hours.time_slots
}
