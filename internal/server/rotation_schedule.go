package server

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Rotation schedules, with AWS Secrets Manager's semantics:
//
//   - RotationRules.AutomaticallyAfterDays N, or ScheduleExpression
//     "rate(N days)" (1 to 1000): the window opens at 00:00 UTC on the day N
//     days after the last rotation (or after the schedule was set) and, without
//     a Duration, closes at the end of that UTC day.
//   - "rate(N hours)" (4 to 23): the window opens on the hour N hours after
//     the last rotation and lasts one hour by default.
//   - "cron(Minutes Hours Day-of-month Month Day-of-week Year)": the window
//     opens at each match. Without a Duration it lasts one hour when Hours
//     repeats within the day (* or a step) and runs to the end of the UTC day
//     otherwise.
//   - Duration "Nh" (1 to 24) sets the window length. It must not run past
//     the end of the UTC day (for daily schedules) or into the next window.
//
// Citadel starts a rotation as soon as its window opens (the rotation job
// runs every minute). A window that passed while no replica was running is
// caught up at the next tick rather than skipped, so a secret is never left
// unrotated for a whole period.

const (
	maxRotationDays    = 1000
	minRotationHours   = 4
	maxRotationHours   = 23
	maxRotationWindowH = 24
)

type rotationSchedule struct {
	// kind is "days", "hours" or "cron".
	kind     string
	n        int
	cron     *cronExpr
	duration time.Duration // 0: AWS's default window
	// expr is the normalized ScheduleExpression ("" for AutomaticallyAfterDays).
	expr string
}

// parseRotationSchedule validates a schedule given as AutomaticallyAfterDays
// or a ScheduleExpression (not both) and an optional Duration. With neither,
// AWS's default of 30 days applies.
func parseRotationSchedule(afterDays int, expression, duration string) (rotationSchedule, error) {
	expression = strings.TrimSpace(expression)
	var sch rotationSchedule
	switch {
	case afterDays != 0 && expression != "":
		return sch, errors.New("specify AutomaticallyAfterDays or ScheduleExpression, not both")
	case expression == "":
		if afterDays == 0 {
			afterDays = 30
		}
		if afterDays < 1 || afterDays > maxRotationDays {
			return sch, fmt.Errorf("AutomaticallyAfterDays must be between 1 and %d", maxRotationDays)
		}
		sch = rotationSchedule{kind: "days", n: afterDays}
	case strings.HasPrefix(expression, "rate(") && strings.HasSuffix(expression, ")"):
		fields := strings.Fields(expression[len("rate(") : len(expression)-1])
		if len(fields) != 2 {
			return sch, errors.New("ScheduleExpression rate() must be rate(N days) or rate(N hours)")
		}
		n, err := strconv.Atoi(fields[0])
		if err != nil {
			return sch, errors.New("ScheduleExpression rate() must start with a whole number")
		}
		switch fields[1] {
		case "day", "days":
			if n < 1 || n > maxRotationDays {
				return sch, fmt.Errorf("ScheduleExpression rate(N days) must be between 1 and %d days", maxRotationDays)
			}
			sch = rotationSchedule{kind: "days", n: n, expr: fmt.Sprintf("rate(%d %s)", n, plural(n, "day"))}
		case "hour", "hours":
			if n < minRotationHours || n > maxRotationHours {
				return sch, fmt.Errorf("ScheduleExpression rate(N hours) must be between %d and %d hours", minRotationHours, maxRotationHours)
			}
			sch = rotationSchedule{kind: "hours", n: n, expr: fmt.Sprintf("rate(%d hours)", n)}
		default:
			return sch, errors.New("ScheduleExpression rate() unit must be days or hours")
		}
	case strings.HasPrefix(expression, "cron(") && strings.HasSuffix(expression, ")"):
		c, err := parseCron(expression[len("cron(") : len(expression)-1])
		if err != nil {
			return sch, fmt.Errorf("ScheduleExpression %v", err)
		}
		sch = rotationSchedule{kind: "cron", cron: c, expr: "cron(" + c.src + ")"}
	default:
		return sch, errors.New("ScheduleExpression must be rate(...) or cron(...)")
	}
	if d := strings.TrimSpace(duration); d != "" {
		if !strings.HasSuffix(d, "h") {
			return sch, errors.New("Duration must be a number of hours, such as 3h")
		}
		h, err := strconv.Atoi(strings.TrimSuffix(d, "h"))
		if err != nil || h < 1 || h > maxRotationWindowH {
			return sch, fmt.Errorf("Duration must be between 1h and %dh", maxRotationWindowH)
		}
		sch.duration = time.Duration(h) * time.Hour
		switch sch.kind {
		case "hours":
			if h > sch.n {
				return sch, errors.New("Duration must not extend into the next rotation window")
			}
		case "cron":
			if sch.cron.dailyFixedHours() {
				if last := sch.cron.lastHour(); last+h > 24 {
					return sch, errors.New("Duration must not extend the rotation window into the next UTC day")
				}
			} else if h > 1 && sch.cron.hourRepeats() {
				if gap := sch.cron.minHourGap(); h > gap {
					return sch, errors.New("Duration must not extend into the next rotation window")
				}
			}
		}
	}
	return sch, nil
}

// durationString is the Duration as AWS returns it ("" for the default).
func (sch rotationSchedule) durationString() string {
	if sch.duration == 0 {
		return ""
	}
	return fmt.Sprintf("%dh", int(sch.duration/time.Hour))
}

func plural(n int, unit string) string {
	if n == 1 {
		return unit
	}
	return unit + "s"
}

// nextWindow returns the first rotation window opening after `after`.
func (sch rotationSchedule) nextWindow(after time.Time) (start, end time.Time) {
	after = after.UTC()
	switch sch.kind {
	case "days":
		d := after.AddDate(0, 0, sch.n)
		start = time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, time.UTC)
		end = start.AddDate(0, 0, 1)
	case "hours":
		start = after.Add(time.Duration(sch.n) * time.Hour).Truncate(time.Hour)
		end = start.Add(time.Hour)
	default:
		start = sch.cron.next(after)
		if start.IsZero() {
			return start, start
		}
		if sch.cron.dailyFixedHours() {
			end = time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1)
		} else {
			end = start.Add(time.Hour)
		}
	}
	if sch.duration > 0 {
		end = start.Add(sch.duration)
	}
	return start, end
}

// windowEnd returns the end of the window that opens at start.
func (sch rotationSchedule) windowEnd(start time.Time) time.Time {
	start = start.UTC()
	if sch.duration > 0 {
		return start.Add(sch.duration)
	}
	if sch.kind == "hours" || (sch.kind == "cron" && !sch.cron.dailyFixedHours()) {
		return start.Add(time.Hour)
	}
	return time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1)
}

// ---- cron ------------------------------------------------------------------

// cronExpr is an AWS cron expression: Minutes Hours Day-of-month Month
// Day-of-week Year. Day-of-month or Day-of-week (exactly one) is "?".
// Supported: numbers, names (JAN-DEC, SUN-SAT), ranges, lists, steps, "*",
// "L" (last day of the month), "nL" (last weekday n of the month) and "n#k"
// (k-th weekday n of the month). Day-of-week numbers run 1 (SUN) to 7 (SAT).
type cronExpr struct {
	src             string
	minutes, hours  uint64 // bit i set: value i allowed
	dom             uint64 // bits 1..31
	domLast         bool
	domAny          bool   // "?"
	months          uint64 // bits 1..12
	dow             uint64 // bits 0..6 (Sunday = 0)
	dowAny          bool   // "?"
	dowLast         int    // nL: weekday+1, 0 when unused
	dowNth, dowNthK int    // n#k: weekday+1 and k, 0 when unused
	years           map[int]bool
	allYears        bool
	hourField       string
}

var monthNames = map[string]int{"JAN": 1, "FEB": 2, "MAR": 3, "APR": 4, "MAY": 5, "JUN": 6, "JUL": 7, "AUG": 8, "SEP": 9, "OCT": 10, "NOV": 11, "DEC": 12}
var dowNames = map[string]int{"SUN": 1, "MON": 2, "TUE": 3, "WED": 4, "THU": 5, "FRI": 6, "SAT": 7}

func parseCron(src string) (*cronExpr, error) {
	f := strings.Fields(strings.ToUpper(src))
	if len(f) != 6 {
		return nil, errors.New("cron() needs 6 fields: Minutes Hours Day-of-month Month Day-of-week Year")
	}
	c := &cronExpr{src: strings.Join(f, " "), hourField: f[1]}
	var err error
	if c.minutes, err = cronField(f[0], 0, 59, nil); err != nil {
		return nil, fmt.Errorf("cron() minutes: %v", err)
	}
	if c.hours, err = cronField(f[1], 0, 23, nil); err != nil {
		return nil, fmt.Errorf("cron() hours: %v", err)
	}
	if c.months, err = cronField(f[3], 1, 12, monthNames); err != nil {
		return nil, fmt.Errorf("cron() month: %v", err)
	}
	c.domAny, c.dowAny = f[2] == "?", f[4] == "?"
	if c.domAny == c.dowAny {
		return nil, errors.New("cron() needs ? in exactly one of day-of-month and day-of-week")
	}
	if !c.domAny {
		if f[2] == "L" {
			c.domLast = true
		} else if c.dom, err = cronField(f[2], 1, 31, nil); err != nil {
			return nil, fmt.Errorf("cron() day-of-month: %v", err)
		}
	}
	if !c.dowAny {
		switch {
		case strings.HasSuffix(f[4], "L") && len(f[4]) > 1:
			n, err := cronValue(strings.TrimSuffix(f[4], "L"), 1, 7, dowNames)
			if err != nil {
				return nil, fmt.Errorf("cron() day-of-week: %v", err)
			}
			c.dowLast = n
		case strings.Contains(f[4], "#"):
			a, b, _ := strings.Cut(f[4], "#")
			n, err := cronValue(a, 1, 7, dowNames)
			if err != nil {
				return nil, fmt.Errorf("cron() day-of-week: %v", err)
			}
			k, err := strconv.Atoi(b)
			if err != nil || k < 1 || k > 5 {
				return nil, errors.New("cron() day-of-week: n#k needs k from 1 to 5")
			}
			c.dowNth, c.dowNthK = n, k
		default:
			bits, err := cronField(f[4], 1, 7, dowNames)
			if err != nil {
				return nil, fmt.Errorf("cron() day-of-week: %v", err)
			}
			c.dow = bits >> 1 // 1..7 -> 0..6
		}
	}
	if f[5] == "*" {
		c.allYears = true
	} else {
		bits := map[int]bool{}
		for _, part := range strings.Split(f[5], ",") {
			lo, hi, ok := strings.Cut(part, "-")
			a, err1 := strconv.Atoi(lo)
			b := a
			var err2 error
			if ok {
				b, err2 = strconv.Atoi(hi)
			}
			if err1 != nil || err2 != nil || a < 1970 || b > 2199 || a > b {
				return nil, errors.New("cron() year must be * or years from 1970 to 2199")
			}
			for y := a; y <= b; y++ {
				bits[y] = true
			}
		}
		c.years = bits
	}
	return c, nil
}

// cronField parses a list of values, ranges and steps into a bitset.
func cronField(s string, lo, hi int, names map[string]int) (uint64, error) {
	var bits uint64
	for _, part := range strings.Split(s, ",") {
		if part == "" {
			return 0, errors.New("empty list item")
		}
		rangePart, stepPart, hasStep := strings.Cut(part, "/")
		step := 1
		if hasStep {
			n, err := strconv.Atoi(stepPart)
			if err != nil || n < 1 || n > hi {
				return 0, fmt.Errorf("invalid step %q", stepPart)
			}
			step = n
		}
		a, b := lo, hi
		switch {
		case rangePart == "*":
		case strings.Contains(rangePart, "-"):
			x, y, _ := strings.Cut(rangePart, "-")
			var err error
			if a, err = cronValue(x, lo, hi, names); err != nil {
				return 0, err
			}
			if b, err = cronValue(y, lo, hi, names); err != nil {
				return 0, err
			}
			if a > b {
				return 0, fmt.Errorf("range %q runs backwards", rangePart)
			}
		default:
			v, err := cronValue(rangePart, lo, hi, names)
			if err != nil {
				return 0, err
			}
			a = v
			if !hasStep {
				b = v
			}
		}
		for v := a; v <= b; v += step {
			bits |= 1 << uint(v)
		}
	}
	return bits, nil
}

func cronValue(s string, lo, hi int, names map[string]int) (int, error) {
	if v, ok := names[s]; ok {
		return v, nil
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < lo || v > hi {
		return 0, fmt.Errorf("value %q must be from %d to %d", s, lo, hi)
	}
	return v, nil
}

// hourRepeats reports whether the hours field repeats within a day (* or a
// step), which makes AWS's default window one hour.
func (c *cronExpr) hourRepeats() bool {
	return strings.ContainsAny(c.hourField, "*/")
}

func (c *cronExpr) dailyFixedHours() bool { return !c.hourRepeats() }

func (c *cronExpr) lastHour() int {
	for h := 23; h >= 0; h-- {
		if c.hours&(1<<uint(h)) != 0 {
			return h
		}
	}
	return 0
}

// minHourGap is the smallest gap, in hours, between allowed hours
// (wrapping around midnight).
func (c *cronExpr) minHourGap() int {
	var hs []int
	for h := 0; h < 24; h++ {
		if c.hours&(1<<uint(h)) != 0 {
			hs = append(hs, h)
		}
	}
	if len(hs) < 2 {
		return 24
	}
	gap := 24 - hs[len(hs)-1] + hs[0]
	for i := 1; i < len(hs); i++ {
		if d := hs[i] - hs[i-1]; d < gap {
			gap = d
		}
	}
	return gap
}

func (c *cronExpr) yearOK(y int) bool { return c.allYears || c.years[y] }

func daysIn(y int, m time.Month) int {
	return time.Date(y, m+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

func (c *cronExpr) dayOK(t time.Time) bool {
	d := t.Day()
	if c.dowAny {
		if c.domLast {
			return d == daysIn(t.Year(), t.Month())
		}
		return c.dom&(1<<uint(d)) != 0
	}
	wd := int(t.Weekday())
	switch {
	case c.dowLast != 0:
		return wd == c.dowLast-1 && d+7 > daysIn(t.Year(), t.Month())
	case c.dowNth != 0:
		return wd == c.dowNth-1 && (d-1)/7+1 == c.dowNthK
	}
	return c.dow&(1<<uint(wd)) != 0
}

// next returns the first match strictly after t (zero if none before 2200).
func (c *cronExpr) next(t time.Time) time.Time {
	t = t.UTC().Truncate(time.Minute).Add(time.Minute)
	for i := 0; i < 1_000_000; i++ {
		if t.Year() > 2199 {
			return time.Time{}
		}
		switch {
		case !c.yearOK(t.Year()):
			t = time.Date(t.Year()+1, 1, 1, 0, 0, 0, 0, time.UTC)
		case c.months&(1<<uint(t.Month())) == 0:
			t = time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, time.UTC)
		case !c.dayOK(t):
			t = time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, time.UTC)
		case c.hours&(1<<uint(t.Hour())) == 0:
			t = t.Truncate(time.Hour).Add(time.Hour)
		case c.minutes&(1<<uint(t.Minute())) == 0:
			t = t.Add(time.Minute)
		default:
			return t
		}
	}
	return time.Time{}
}
