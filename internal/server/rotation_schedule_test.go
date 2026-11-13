package server

import (
	"testing"
	"time"
)

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestRotationScheduleWindows(t *testing.T) {
	cases := []struct {
		name            string
		days            int
		expr, dur       string
		after           string
		start, end      string
		wantExpr        string
		wantDurationOut string
	}{
		{name: "default 30 days", after: "2026-01-10T15:04:00Z", start: "2026-02-09T00:00:00Z", end: "2026-02-10T00:00:00Z"},
		{name: "AutomaticallyAfterDays", days: 7, after: "2026-01-31T23:59:00Z", start: "2026-02-07T00:00:00Z", end: "2026-02-08T00:00:00Z"},
		{name: "days with duration", days: 1, dur: "3h", after: "2026-03-01T10:00:00Z", start: "2026-03-02T00:00:00Z", end: "2026-03-02T03:00:00Z", wantDurationOut: "3h"},
		{name: "rate days", expr: "rate(10 days)", after: "2026-01-01T12:00:00Z", start: "2026-01-11T00:00:00Z", end: "2026-01-12T00:00:00Z", wantExpr: "rate(10 days)"},
		{name: "rate 1 day", expr: "rate(1 day)", after: "2026-01-01T12:00:00Z", start: "2026-01-02T00:00:00Z", end: "2026-01-03T00:00:00Z", wantExpr: "rate(1 day)"},
		{name: "rate hours", expr: "rate(4 hours)", after: "2026-01-01T12:34:56Z", start: "2026-01-01T16:00:00Z", end: "2026-01-01T17:00:00Z"},
		{name: "rate hours duration", expr: "rate(6 hours)", dur: "2h", after: "2026-01-01T23:10:00Z", start: "2026-01-02T05:00:00Z", end: "2026-01-02T07:00:00Z"},
		{name: "cron daily fixed hour", expr: "cron(0 16 * * ? *)", after: "2026-01-01T16:00:00Z", start: "2026-01-02T16:00:00Z", end: "2026-01-03T00:00:00Z"},
		{name: "cron daily same day", expr: "cron(0 16 * * ? *)", after: "2026-01-01T09:00:00Z", start: "2026-01-01T16:00:00Z", end: "2026-01-02T00:00:00Z"},
		{name: "cron 1st and 15th", expr: "cron(0 8 1,15 * ? *)", dur: "2h", after: "2026-01-02T00:00:00Z", start: "2026-01-15T08:00:00Z", end: "2026-01-15T10:00:00Z"},
		{name: "cron every 4 hours", expr: "cron(0 */4 * * ? *)", after: "2026-01-01T05:00:00Z", start: "2026-01-01T08:00:00Z", end: "2026-01-01T09:00:00Z"},
		{name: "cron last day", expr: "cron(0 0 L * ? *)", after: "2026-02-03T00:00:00Z", start: "2026-02-28T00:00:00Z", end: "2026-03-01T00:00:00Z"},
		{name: "cron leap year last day", expr: "cron(0 0 L 2 ? *)", after: "2027-03-01T00:00:00Z", start: "2028-02-29T00:00:00Z", end: "2028-03-01T00:00:00Z"},
		{name: "cron weekdays by name", expr: "cron(0 9 ? * MON-FRI *)", after: "2026-01-02T10:00:00Z", start: "2026-01-05T09:00:00Z", end: "2026-01-06T00:00:00Z"}, // Fri -> Mon
		{name: "cron sunday is 1", expr: "cron(0 1 ? * 1 *)", after: "2026-01-01T00:00:00Z", start: "2026-01-04T01:00:00Z", end: "2026-01-05T00:00:00Z"},
		{name: "cron first monday", expr: "cron(0 3 ? * 2#1 *)", after: "2026-01-06T00:00:00Z", start: "2026-02-02T03:00:00Z", end: "2026-02-03T00:00:00Z"},
		{name: "cron last friday", expr: "cron(0 3 ? * 6L *)", after: "2026-01-01T00:00:00Z", start: "2026-01-30T03:00:00Z", end: "2026-01-31T00:00:00Z"},
		{name: "cron month names", expr: "cron(0 0 1 JAN,JUL ? *)", after: "2026-01-01T00:00:00Z", start: "2026-07-01T00:00:00Z", end: "2026-07-02T00:00:00Z"},
		{name: "cron year list", expr: "cron(0 0 1 1 ? 2030)", after: "2026-05-01T00:00:00Z", start: "2030-01-01T00:00:00Z", end: "2030-01-02T00:00:00Z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sch, err := parseRotationSchedule(tc.days, tc.expr, tc.dur)
			if err != nil {
				t.Fatal(err)
			}
			start, end := sch.nextWindow(mustTime(t, tc.after))
			if !start.Equal(mustTime(t, tc.start)) || !end.Equal(mustTime(t, tc.end)) {
				t.Fatalf("window = %s .. %s, want %s .. %s", start.Format(time.RFC3339), end.Format(time.RFC3339), tc.start, tc.end)
			}
			if !sch.windowEnd(start).Equal(end) {
				t.Fatalf("windowEnd = %s", sch.windowEnd(start))
			}
			if tc.wantExpr != "" && sch.expr != tc.wantExpr {
				t.Fatalf("expr = %q", sch.expr)
			}
			if sch.durationString() != tc.wantDurationOut && tc.wantDurationOut != "" {
				t.Fatalf("duration = %q", sch.durationString())
			}
		})
	}
}

func TestRotationScheduleRejects(t *testing.T) {
	for _, tc := range []struct {
		days      int
		expr, dur string
	}{
		{days: 7, expr: "rate(7 days)"},
		{days: 1001},
		{days: -1},
		{expr: "rate(0 days)"},
		{expr: "rate(1001 days)"},
		{expr: "rate(3 hours)"},
		{expr: "rate(24 hours)"},
		{expr: "rate(2 weeks)"},
		{expr: "rate(days)"},
		{expr: "every day"},
		{expr: "cron(0 16 * * * *)"},   // neither ? nor
		{expr: "cron(0 16 ? * ? *)"},   // both ?
		{expr: "cron(0 16 * *)"},       // too few fields
		{expr: "cron(60 16 * * ? *)"},  // minute out of range
		{expr: "cron(0 24 * * ? *)"},   // hour out of range
		{expr: "cron(0 1 32 * ? *)"},   // day out of range
		{expr: "cron(0 1 ? * 8 *)"},    // dow out of range
		{expr: "cron(0 1 ? * 2#6 *)"},  // nth out of range
		{expr: "cron(0 1 * * ? 1969)"}, // year out of range
		{expr: "cron(0 5-2 * * ? *)"},  // backwards range
		{expr: "rate(1 day)", dur: "25h"},
		{expr: "rate(1 day)", dur: "0h"},
		{expr: "rate(1 day)", dur: "90m"},
		{expr: "rate(4 hours)", dur: "5h"},
		{expr: "cron(0 22 * * ? *)", dur: "3h"},  // past midnight
		{expr: "cron(0 */4 * * ? *)", dur: "5h"}, // into the next window
	} {
		if _, err := parseRotationSchedule(tc.days, tc.expr, tc.dur); err == nil {
			t.Errorf("parseRotationSchedule(%d, %q, %q) accepted", tc.days, tc.expr, tc.dur)
		}
	}
}
