package config

import "testing"

func TestParsePublicURL(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"", "", true},
		{"https://citadel.example.com", "https://citadel.example.com", true},
		{"https://citadel.example.com/", "https://citadel.example.com", true},
		{"http://localhost:8080/base/", "http://localhost:8080/base", true},
		{"citadel.example.com", "", false},
		{"ftp://citadel.example.com", "", false},
		{"https://citadel.example.com/?x=1", "", false},
		{"https://user:pw@citadel.example.com", "", false},
	}
	for _, c := range cases {
		got, err := ParsePublicURL(c.in)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("ParsePublicURL(%q) = %q, %v; want %q ok=%v", c.in, got, err, c.want, c.ok)
		}
	}
}
