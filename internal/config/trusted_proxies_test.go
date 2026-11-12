package config

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestParseTrustedProxies(t *testing.T) {
	got, err := ParseTrustedProxies(" 10.0.0.0/8, 192.168.1.7 ,::1,")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0/8", "192.168.1.7/32", "::1/128"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	for _, bad := range []string{"10.0.0.0/33", "not-an-ip", "10.0.0.1/"} {
		if _, err := ParseTrustedProxies(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestAuditHMACKeyIsAlwaysSet(t *testing.T) {
	t.Setenv("KMS_MASTER_KEY_B64", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)))
	t.Setenv("KMS_AUDIT_HMAC_KEY_B64", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.AuditHMACKey) != 32 {
		t.Fatalf("derived audit key length %d", len(cfg.AuditHMACKey))
	}
	t.Setenv("KMS_AUDIT_HMAC_KEY_B64", base64.StdEncoding.EncodeToString([]byte("short")))
	if _, err := Load(); err == nil {
		t.Fatal("short audit key accepted")
	}
	t.Setenv("KMS_AUDIT_HMAC_KEY_B64", "")
	t.Setenv("KMS_TRUSTED_PROXIES", "nope")
	if _, err := Load(); err == nil {
		t.Fatal("bad KMS_TRUSTED_PROXIES accepted")
	}
}
