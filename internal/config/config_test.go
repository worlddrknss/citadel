package config

import (
	"testing"

	"github.com/worlddrknss/citadel/internal/store"
)

func TestCheckSecurityPosture(t *testing.T) {
	users := map[string]store.UIUser{"admin": {Username: "admin", Role: "admin"}}
	cases := []struct {
		name     string
		cfg      Config
		dbBacked bool
		ok       bool
	}{
		{"insecure dev allows anything", Config{InsecureDev: true}, false, true},
		{"no users", Config{ExpectedAccessKey: "a", SecretAccessKey: "b"}, true, false},
		{"memory store without static key", Config{UIUsers: users}, false, false},
		{"memory store with static key", Config{UIUsers: users, ExpectedAccessKey: "a", SecretAccessKey: "b"}, false, true},
		{"db store with users", Config{UIUsers: users}, true, true},
	}
	for _, c := range cases {
		if err := CheckSecurityPosture(c.cfg, c.dbBacked); (err == nil) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", c.name, err, c.ok)
		}
	}
}
