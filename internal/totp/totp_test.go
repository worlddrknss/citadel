package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func fipsOnly() bool { return strings.Contains(os.Getenv("GODEBUG"), "fips140=only") }

// RFC 6238 Appendix B, SHA256 mode: 32-byte ASCII seed, 8 digits.
func TestRFC6238SHA256Vectors(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	for _, tc := range []struct {
		unix int64
		want string
	}{
		{59, "46119246"},
		{1111111109, "68084774"},
		{1111111111, "67062674"},
		{1234567890, "91819424"},
		{2000000000, "90698825"},
		{20000000000, "77737706"},
	} {
		step := Step(time.Unix(tc.unix, 0))
		if got := hotp(sha256.New, key, uint64(step), 8); got != tc.want {
			t.Errorf("T=%d: got %s want %s", tc.unix, got, tc.want)
		}
		// The 6-digit code is the same truncation mod 10^6.
		if got := Code(key, step); got != tc.want[2:] {
			t.Errorf("T=%d: 6-digit got %s want %s", tc.unix, got, tc.want[2:])
		}
	}
}

// RFC 4226 Appendix D vectors check the HOTP truncation itself. They are
// HMAC-SHA-1, which only runs outside FIPS 140-only mode (and only here:
// Citadel never uses SHA-1).
func TestRFC4226HOTPVectors(t *testing.T) {
	if fipsOnly() {
		t.Skip("HMAC-SHA-1 is refused in fips140=only mode")
	}
	key := []byte("12345678901234567890")
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for i, w := range want {
		if got := hotp(sha1.New, key, uint64(i), 6); got != w {
			t.Errorf("counter %d: got %s want %s", i, got, w)
		}
	}
}

// TestSHA1RefusedInFIPSOnlyMode documents why Citadel's TOTP uses SHA-256:
// with GODEBUG=fips140=only, Go's crypto/hmac refuses SHA-1.
func TestSHA1RefusedInFIPSOnlyMode(t *testing.T) {
	if !fipsOnly() {
		t.Skip("only meaningful with GODEBUG=fips140=only")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("HMAC-SHA-1 worked in fips140=only mode; SHA-1 TOTP would be possible")
		}
	}()
	m := hmac.New(sha1.New, []byte("12345678901234567890"))
	m.Write([]byte{0})
	_ = m.Sum(nil)
}

func TestVerifySkewAndReplay(t *testing.T) {
	key, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != SecretSize {
		t.Fatalf("secret is %d bytes", len(key))
	}
	now := time.Unix(1_700_000_000, 0)
	cur := Step(now)
	for _, d := range []int64{-1, 0, 1} {
		if s, ok := Verify(key, Code(key, cur+d), now, 0); !ok || s != cur+d {
			t.Errorf("skew %d refused (step %d ok %v)", d, s, ok)
		}
	}
	for _, d := range []int64{-2, 2, 10} {
		if _, ok := Verify(key, Code(key, cur+d), now, 0); ok {
			t.Errorf("skew %d accepted", d)
		}
	}
	// Replay: the step already used, and older ones, are refused.
	if _, ok := Verify(key, Code(key, cur), now, cur); ok {
		t.Error("replayed step accepted")
	}
	if _, ok := Verify(key, Code(key, cur-1), now, cur); ok {
		t.Error("older step accepted after a newer one")
	}
	if s, ok := Verify(key, Code(key, cur+1), now, cur); !ok || s != cur+1 {
		t.Error("next step refused")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef", "12 456"} {
		if _, ok := Verify(key, bad, now, 0); ok {
			t.Errorf("malformed %q accepted", bad)
		}
	}
}

func TestSecretEncodingAndURI(t *testing.T) {
	key := []byte("12345678901234567890")
	enc := EncodeSecret(key)
	if enc != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" {
		t.Fatalf("encode: %s", enc)
	}
	dec, err := DecodeSecret(strings.ToLower(enc[:8]) + " " + enc[8:])
	if err != nil || string(dec) != string(key) {
		t.Fatalf("decode: %q %v", dec, err)
	}
	u, err := url.Parse(URI("Citadel", "alice@example", key))
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" || u.Path != "/Citadel:alice@example" {
		t.Fatalf("uri: %s", u)
	}
	q := u.Query()
	if q.Get("secret") != enc || q.Get("algorithm") != "SHA256" || q.Get("digits") != "6" || q.Get("period") != "30" || q.Get("issuer") != "Citadel" {
		t.Fatalf("query: %v", q)
	}
}
