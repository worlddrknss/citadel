package config

import "testing"

func TestParseAuditRetentionDays(t *testing.T) {
	for raw, want := range map[string]int{"": 0, " ": 0, "0": 0, "7": 7, " 90 ": 90, "3650": 3650} {
		got, err := ParseAuditRetentionDays(raw)
		if err != nil || got != want {
			t.Errorf("%q = %d %v, want %d", raw, got, err, want)
		}
	}
	for _, raw := range []string{"1", "6", "3651", "-7", "30d", "1.5"} {
		if _, err := ParseAuditRetentionDays(raw); err == nil {
			t.Errorf("%q accepted", raw)
		}
	}
}
