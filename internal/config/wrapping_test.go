package config

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestParsePreviousWrappingKeys(t *testing.T) {
	a := bytes.Repeat([]byte{1}, 32)
	b := bytes.Repeat([]byte{2}, 32)
	raw := base64.StdEncoding.EncodeToString(a) + " , ," + base64.StdEncoding.EncodeToString(b)
	keys, err := parsePreviousWrappingKeys(raw)
	if err != nil || len(keys) != 2 || !bytes.Equal(keys[0], a) || !bytes.Equal(keys[1], b) {
		t.Fatalf("keys %d %v", len(keys), err)
	}
	if keys, err := parsePreviousWrappingKeys(""); err != nil || len(keys) != 0 {
		t.Fatalf("empty: %v %v", keys, err)
	}
	short := base64.StdEncoding.EncodeToString([]byte("short"))
	for _, bad := range []string{"not base64!", short} {
		_, err := parsePreviousWrappingKeys(bad)
		if err == nil {
			t.Fatalf("accepted %q", bad)
		}
		if strings.Contains(err.Error(), bad) {
			t.Fatalf("error echoes key material: %v", err)
		}
	}
}
