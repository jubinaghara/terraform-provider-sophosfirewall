// Package administration implements system objects such as schedules.
package administration

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/framework"
)

const (
	scheduleRecurring = "recurring"
	scheduleOneTime   = "oneTime"
	dateLayout        = "2006-01-02 15:04:05"
)

// Days are the dayOfWeek values of a schedule time slot.
var Days = []string{"allDays", "sun", "mon", "tue", "wed", "thu", "fri", "sat", "weekdays", "weekdaysWithSaturday"}

var (
	timeRe = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)
	dateRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$`)
)

type scheduleModel struct {
	ID          types.String    `tfsdk:"id"`
	Name        types.String    `tfsdk:"name"`
	Description types.String    `tfsdk:"description"`
	Type        types.String    `tfsdk:"type"`
	StartDate   types.String    `tfsdk:"start_date"`
	EndDate     types.String    `tfsdk:"end_date"`
	TimeSlots   []timeSlotModel `tfsdk:"time_slots"`
}

type timeSlotModel struct {
	DayOfWeek types.String `tfsdk:"day_of_week"`
	StartTime types.String `tfsdk:"start_time"`
	EndTime   types.String `tfsdk:"end_time"`
}

type schedule struct {
	ID          string     `json:"id,omitempty"`
	Name        string     `json:"name"`
	Description *string    `json:"description,omitempty"`
	Type        string     `json:"type"`
	StartDate   *string    `json:"startDate,omitempty"`
	EndDate     *string    `json:"endDate,omitempty"`
	TimeSlots   []timeSlot `json:"timeSlots"`
}

type timeSlot struct {
	DayOfWeek string `json:"dayOfWeek"`
	StartTime string `json:"startTime"`
	EndTime   string `json:"endTime"`
}

// Schedule manages /administration/schedules.
var Schedule = &framework.Resource[scheduleModel, schedule]{
	Name:  "schedule",
	Title: "schedule",
	Path:  "/administration/schedules",
	Schema: schema.Schema{
		MarkdownDescription: "Manages a schedule (*System > Profiles > Schedule*). Firewall rules and policies " +
			"reference schedules by name to restrict when they apply. A `recurring` schedule repeats every week " +
			"in its time slots; a `oneTime` schedule applies in its time slots between `start_date` and `end_date`.",
		Attributes: map[string]schema.Attribute{
			"id":          framework.IDAttribute(),
			"name":        framework.NameAttribute("schedule", 50, false),
			"description": framework.DescriptionAttribute(255),
			"type": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Schedule type. " + framework.OneOfMarkdown(scheduleRecurring, scheduleOneTime) +
					" Changing this forces a new resource.",
				Validators:    []validator.String{stringvalidator.OneOf(scheduleRecurring, scheduleOneTime)},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"start_date": dateAttribute("Start of a `oneTime` schedule in the firewall's local time, " +
				"formatted `YYYY-MM-DD HH:MM:SS`. Required when `type` is `oneTime`, not allowed otherwise."),
			"end_date": dateAttribute("End of a `oneTime` schedule in the firewall's local time, " +
				"formatted `YYYY-MM-DD HH:MM:SS`. Must be after `start_date`. Required when `type` is `oneTime`, not allowed otherwise."),
			"time_slots": schema.SetNestedAttribute{
				Required:            true,
				MarkdownDescription: "Time windows in which the schedule is active (1-256).",
				Validators:          []validator.Set{setvalidator.SizeBetween(1, 256)},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"day_of_week": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "Day or days the slot applies to. " + framework.OneOfMarkdown(Days...),
							Validators:          []validator.String{stringvalidator.OneOf(Days...)},
						},
						"start_time": timeAttribute("Start of the slot, formatted `HH:MM` (24-hour)."),
						"end_time":   timeAttribute("End of the slot, formatted `HH:MM` (24-hour). Must be after `start_time`."),
					},
				},
			},
		},
	},
	CreateOnly: []string{"type"},
	Validate:   validateSchedule,
	Expand: func(_ context.Context, m *scheduleModel, _ *diag.Diagnostics) *schedule {
		s := &schedule{
			Name:        m.Name.ValueString(),
			Description: framework.StringPtr(m.Description),
			Type:        m.Type.ValueString(),
			StartDate:   framework.StringPtr(m.StartDate),
			EndDate:     framework.StringPtr(m.EndDate),
			TimeSlots:   make([]timeSlot, 0, len(m.TimeSlots)),
		}
		for _, t := range m.TimeSlots {
			s.TimeSlots = append(s.TimeSlots, timeSlot{
				DayOfWeek: t.DayOfWeek.ValueString(),
				StartTime: t.StartTime.ValueString(),
				EndTime:   t.EndTime.ValueString(),
			})
		}
		return s
	},
	Flatten: func(_ context.Context, a *schedule, _ *scheduleModel, _ *diag.Diagnostics) *scheduleModel {
		m := &scheduleModel{
			ID:          types.StringValue(a.ID),
			Name:        types.StringValue(a.Name),
			Description: framework.StringOr(a.Description, ""),
			Type:        types.StringValue(a.Type),
			StartDate:   types.StringNull(),
			EndDate:     types.StringNull(),
		}
		if a.StartDate != nil {
			m.StartDate = framework.NonEmpty(*a.StartDate)
		}
		if a.EndDate != nil {
			m.EndDate = framework.NonEmpty(*a.EndDate)
		}
		for _, t := range a.TimeSlots {
			m.TimeSlots = append(m.TimeSlots, timeSlotModel{
				DayOfWeek: types.StringValue(t.DayOfWeek),
				StartTime: types.StringValue(t.StartTime),
				EndTime:   types.StringValue(t.EndTime),
			})
		}
		return m
	},
}

func validateSchedule(_ context.Context, m *scheduleModel, diags *diag.Diagnostics) {
	if !m.Type.IsUnknown() {
		oneTime := m.Type.ValueString() == scheduleOneTime
		for _, a := range []struct {
			name string
			v    types.String
		}{{"start_date", m.StartDate}, {"end_date", m.EndDate}} {
			switch {
			case oneTime && a.v.IsNull():
				diags.AddAttributeError(path.Root(a.name), "Missing attribute", fmt.Sprintf("%q is required when type is %q.", a.name, scheduleOneTime))
			case !oneTime && !a.v.IsNull():
				diags.AddAttributeError(path.Root(a.name), "Unexpected attribute", fmt.Sprintf("%q can only be set when type is %q.", a.name, scheduleOneTime))
			}
		}
	}
	if known(m.StartDate) && known(m.EndDate) {
		start, err1 := time.Parse(dateLayout, m.StartDate.ValueString())
		end, err2 := time.Parse(dateLayout, m.EndDate.ValueString())
		if err1 == nil && err2 == nil && !end.After(start) {
			diags.AddAttributeError(path.Root("end_date"), "Invalid date range",
				fmt.Sprintf("end_date %q must be after start_date %q.", m.EndDate.ValueString(), m.StartDate.ValueString()))
		}
	}
	for _, t := range m.TimeSlots {
		// Fixed-width HH:MM strings compare chronologically.
		if known(t.StartTime) && known(t.EndTime) && timeRe.MatchString(t.StartTime.ValueString()) &&
			timeRe.MatchString(t.EndTime.ValueString()) && t.EndTime.ValueString() <= t.StartTime.ValueString() {
			diags.AddAttributeError(path.Root("time_slots"), "Invalid time slot",
				fmt.Sprintf("end_time %q must be after start_time %q (day_of_week %q).",
					t.EndTime.ValueString(), t.StartTime.ValueString(), t.DayOfWeek.ValueString()))
		}
	}
}

func known(v types.String) bool { return !v.IsNull() && !v.IsUnknown() }

func dateAttribute(description string) schema.StringAttribute {
	return schema.StringAttribute{
		Optional:            true,
		MarkdownDescription: description,
		Validators:          []validator.String{validDate{}},
	}
}

func timeAttribute(description string) schema.StringAttribute {
	return schema.StringAttribute{
		Required:            true,
		MarkdownDescription: description,
		Validators: []validator.String{
			stringvalidator.RegexMatches(timeRe, "must be a 24-hour time formatted HH:MM, e.g. 09:00"),
		},
	}
}

// validDate checks the YYYY-MM-DD HH:MM:SS format and that the date exists.
type validDate struct{}

func (validDate) Description(context.Context) string {
	return "must be a date and time formatted YYYY-MM-DD HH:MM:SS"
}
func (v validDate) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (validDate) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	s := req.ConfigValue.ValueString()
	if _, err := time.Parse(dateLayout, s); err != nil || !dateRe.MatchString(s) {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid value",
			fmt.Sprintf("%q is not a valid date and time formatted YYYY-MM-DD HH:MM:SS, e.g. 2026-04-25 06:00:00", s))
	}
}
