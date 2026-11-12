package config

import (
	"testing"

	"github.com/worlddrknss/citadel/internal/store"
)

func TestCheckSecurityPosture(t *testing.T) {
	users := map[string]store.UIUser{"admin": {Username: "admin", Role: "admin"}}
	cases := []struct {
		name      string
		cfg       Config
		dbBacked  bool
		ok        bool
		bootstrap bool
	}{
		{"insecure dev allows anything", Config{InsecureDev: true}, false, true, false},
		{"memory store without users", Config{ExpectedAccessKey: "a", SecretAccessKey: "b"}, false, false, false},
		{"db store without users bootstraps", Config{}, true, true, true},
		{"memory store without static key", Config{UIUsers: users}, false, false, false},
		{"memory store with static key", Config{UIUsers: users, ExpectedAccessKey: "a", SecretAccessKey: "b"}, false, true, false},
		{"db store with users", Config{UIUsers: users}, true, true, false},
		{"insecure dev never bootstraps", Config{InsecureDev: true}, true, true, false},
	}
	for _, c := range cases {
		p, err := CheckSecurityPosture(c.cfg, c.dbBacked)
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", c.name, err, c.ok)
		}
		if p.Bootstrap != c.bootstrap {
			t.Errorf("%s: bootstrap=%v, want %v", c.name, p.Bootstrap, c.bootstrap)
		}
	}
}
