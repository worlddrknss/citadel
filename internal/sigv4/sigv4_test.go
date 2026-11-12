package sigv4

import (
	"testing"
	"time"
)

func TestCheckAmzDate(t *testing.T) {
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name, amz, scope string
		ok               bool
	}{
		{"current", "20261112T120000Z", "20261112", true},
		{"within skew", "20261112T115000Z", "20261112", true},
		{"too old", "20261112T113000Z", "20261112", false},
		{"future", "20261112T123000Z", "20261112", false},
		{"scope mismatch", "20261112T120000Z", "20261111", false},
		{"malformed", "yesterday", "20261112", false},
		{"missing", "", "20261112", false},
	}
	for _, c := range cases {
		if err := CheckAmzDate(c.amz, c.scope, now); (err == nil) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", c.name, err, c.ok)
		}
	}
}
