package administration_test

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/acctest"
)

const schedulesPath = "/administration/schedules"

func TestScheduleRecurring(t *testing.T) {
	env := acctest.New(t)
	const addr = "sophosfirewall_schedule.work"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_schedule" "work" {
  name = "Work-Hours"
  type = "recurring"
  time_slots = [
    { day_of_week = "weekdays", start_time = "09:00", end_time = "17:00" },
    { day_of_week = "sat", start_time = "10:00", end_time = "14:00" },
  ]
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(addr, "id"),
					resource.TestCheckResourceAttr(addr, "description", ""),
					resource.TestCheckResourceAttr(addr, "time_slots.#", "2"),
					resource.TestCheckTypeSetElemNestedAttrs(addr, "time_slots.*", map[string]string{
						"day_of_week": "weekdays", "start_time": "09:00", "end_time": "17:00",
					}),
					resource.TestCheckNoResourceAttr(addr, "start_date"),
				),
			},
			{
				// Rename, describe and change the slots in place.
				Config: env.Config(`
resource "sophosfirewall_schedule" "work" {
  name        = "Business-Hours"
  description = "Office opening hours"
  type        = "recurring"
  time_slots = [
    { day_of_week = "weekdays", start_time = "08:00", end_time = "18:00" },
  ]
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "name", "Business-Hours"),
					resource.TestCheckResourceAttr(addr, "time_slots.#", "1"),
					func(*terraform.State) error {
						if o := env.Server.Get(schedulesPath, "Business-Hours"); o == nil || o["description"] != "Office opening hours" {
							t.Errorf("schedule on server = %v", o)
						}
						return nil
					},
				),
			},
			{ResourceName: addr, ImportState: true, ImportStateVerify: true},
			{ResourceName: addr, ImportState: true, ImportStateId: "Business-Hours", ImportStateVerify: true},
			{
				// The type cannot be patched, so changing it recreates the schedule.
				Config: env.Config(`
resource "sophosfirewall_schedule" "work" {
  name       = "Business-Hours"
  type       = "oneTime"
  start_date = "2026-12-24 00:00:00"
  end_date   = "2026-12-27 00:00:00"
  time_slots = [
    { day_of_week = "allDays", start_time = "00:00", end_time = "23:59" },
  ]
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionDestroyBeforeCreate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "type", "oneTime"),
					resource.TestCheckResourceAttr(addr, "start_date", "2026-12-24 00:00:00"),
				),
			},
		},
	})
}

func TestScheduleOneTime(t *testing.T) {
	env := acctest.New(t)
	const addr = "sophosfirewall_schedule.maintenance"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{
			{
				Config: env.Config(`
resource "sophosfirewall_schedule" "maintenance" {
  name        = "Maintenance-Window"
  description = "One-time maintenance window"
  type        = "oneTime"
  start_date  = "2026-04-25 00:00:00"
  end_date    = "2026-04-25 06:00:00"
  time_slots  = [{ day_of_week = "allDays", start_time = "00:00", end_time = "06:00" }]
}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "end_date", "2026-04-25 06:00:00"),
					func(*terraform.State) error {
						o := env.Server.Get(schedulesPath, "Maintenance-Window")
						if o["type"] != "oneTime" || o["startDate"] != "2026-04-25 00:00:00" {
							t.Errorf("schedule on server = %v", o)
						}
						return nil
					},
				),
			},
			{
				// Extending the window is an in-place update.
				Config: env.Config(`
resource "sophosfirewall_schedule" "maintenance" {
  name        = "Maintenance-Window"
  description = "One-time maintenance window"
  type        = "oneTime"
  start_date  = "2026-04-25 00:00:00"
  end_date    = "2026-04-26 00:00:00"
  time_slots  = [{ day_of_week = "allDays", start_time = "00:00", end_time = "08:00" }]
}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)},
				},
				Check: resource.TestCheckResourceAttr(addr, "end_date", "2026-04-26 00:00:00"),
			},
			{ResourceName: addr, ImportState: true, ImportStateVerify: true},
		},
	})
}

func TestScheduleDataSource(t *testing.T) {
	env := acctest.New(t)
	env.Server.Seed(schedulesPath, map[string]any{
		"name": "All Time On Weekdays", "type": "recurring", "description": "",
		"timeSlots": []any{map[string]any{"dayOfWeek": "weekdays", "startTime": "00:00", "endTime": "23:59"}},
	})
	const ds = "data.sophosfirewall_schedule.weekdays"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: env.Factories,
		Steps: []resource.TestStep{{
			Config: env.Config(`data "sophosfirewall_schedule" "weekdays" { name = "All Time On Weekdays" }`),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet(ds, "id"),
				resource.TestCheckResourceAttr(ds, "type", "recurring"),
				resource.TestCheckResourceAttr(ds, "time_slots.#", "1"),
				resource.TestCheckResourceAttr(ds, "time_slots.0.day_of_week", "weekdays"),
			),
		}},
	})
}

func TestScheduleValidation(t *testing.T) {
	env := acctest.New(t)
	cfg := func(body string) string {
		return env.Config(`
resource "sophosfirewall_schedule" "t" {
  name = "t"
` + body + `
}`)
	}
	slot := `time_slots = [{ day_of_week = "mon", start_time = "09:00", end_time = "17:00" }]`
	steps := []struct{ body, err string }{
		{`type = "recurring"`, `time_slots`},
		{`type = "daily"` + "\n" + slot, `value must be one of`},
		{`type = "oneTime"` + "\n" + slot, `"start_date" is required when type is "oneTime"`},
		{`type = "recurring"` + "\nstart_date = \"2026-04-25 00:00:00\"\n" + slot, `"start_date" can only be set when type is\s+"oneTime"`},
		{`type = "oneTime"` + "\nstart_date = \"2026-04-25 00:00:00\"\nend_date = \"2026-04-24 00:00:00\"\n" + slot, `must be after start_date`},
		{`type = "oneTime"` + "\nstart_date = \"2026-02-30 00:00:00\"\nend_date = \"2026-03-01 00:00:00\"\n" + slot, `not a valid date and time`},
		{`type = "recurring"` + "\n" + `time_slots = [{ day_of_week = "mon", start_time = "9:00", end_time = "17:00" }]`, `24-hour time formatted HH:MM`},
		{`type = "recurring"` + "\n" + `time_slots = [{ day_of_week = "mon", start_time = "18:00", end_time = "08:00" }]`, `end_time "08:00" must be after start_time "18:00"`},
		{`type = "recurring"` + "\n" + `time_slots = [{ day_of_week = "monday", start_time = "08:00", end_time = "18:00" }]`, `value must be one of`},
		{`type = "recurring"` + "\n" + `time_slots = []`, `at least 1`},
	}
	var ts []resource.TestStep
	for _, s := range steps {
		ts = append(ts, resource.TestStep{Config: cfg(s.body), ExpectError: regexp.MustCompile(s.err), PlanOnly: true})
	}
	resource.UnitTest(t, resource.TestCase{ProtoV6ProviderFactories: env.Factories, Steps: ts})
}
