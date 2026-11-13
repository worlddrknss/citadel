package providertoken

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/totp"
)

// RFC 6238 Appendix B vectors (8 digits, 30-second period).
var rfc6238 = []struct {
	unix           int64
	sha256, sha512 string
}{
	{59, "46119246", "90693936"},
	{1111111109, "68084774", "25091201"},
	{1111111111, "67062674", "99943326"},
	{1234567890, "91819424", "93441116"},
	{2000000000, "90698825", "38618901"},
	{20000000000, "77737706", "47863826"},
}

var (
	seed256 = []byte("12345678901234567890123456789012")
	seed512 = []byte("1234567890123456789012345678901234567890123456789012345678901234")
)

func TestTOTPRFC6238Vectors(t *testing.T) {
	g256, err := NewTOTP(TOTPConfig{Secret: seed256, Algorithm: "SHA256", Digits: 8})
	if err != nil {
		t.Fatal(err)
	}
	g512, err := NewTOTP(TOTPConfig{Secret: seed512, Algorithm: "sha-512", Digits: 8})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range rfc6238 {
		at := time.Unix(v.unix, 0)
		if got, _ := g256.Code(at); got != v.sha256 {
			t.Errorf("SHA256 T=%d: %s, want %s", v.unix, got, v.sha256)
		}
		if got, _ := g512.Code(at); got != v.sha512 {
			t.Errorf("SHA512 T=%d: %s, want %s", v.unix, got, v.sha512)
		}
	}
}

func TestTOTPURI(t *testing.T) {
	enc := totp.EncodeSecret(seed512)
	uri := "otpauth://totp/Example:agent@example.com?secret=" + enc + "&issuer=Example&algorithm=SHA512&digits=8&period=30"
	g, err := ParseTOTPURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := g.Mint(context.Background(), Params{At: time.Unix(1111111109, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if tok.Value != "25091201" || tok.Kind != KindTOTP || !tok.ExpiresAt.Equal(time.Unix(1111111110, 0)) {
		t.Fatalf("token = %v value=%s", tok, tok.Value)
	}
	if tok.Metadata["algorithm"] != "SHA512" || tok.Metadata["digits"] != "8" || tok.Metadata["period"] != "30" {
		t.Fatalf("metadata = %v", tok.Metadata)
	}
	for _, v := range tok.Metadata {
		if strings.Contains(v, enc) {
			t.Fatal("metadata holds the seed")
		}
	}

	// A 60-second period, 7 digits: same HOTP counter math.
	g, err = ParseTOTPURI("otpauth://totp/x?secret=" + totp.EncodeSecret(seed256) + "&algorithm=SHA256&digits=7&period=60")
	if err != nil {
		t.Fatal(err)
	}
	code, exp := g.Code(time.Unix(119, 0))
	if len(code) != 7 || !exp.Equal(time.Unix(120, 0)) {
		t.Fatalf("code=%s exp=%v", code, exp)
	}
	if want := totp.CodeWith(g.h, seed256, 1, 7); code != want {
		t.Fatalf("code=%s want %s", code, want)
	}

	// The current code is the default.
	tok, err = g.Mint(context.Background(), Params{})
	if err != nil || len(tok.Value) != 7 || !tok.ExpiresAt.After(time.Now()) {
		t.Fatalf("current code: %v %v", tok, err)
	}
}

func TestTOTPSHA1Refused(t *testing.T) {
	enc := totp.EncodeSecret(seed256)
	for name, fn := range map[string]func() (*TOTP, error){
		"URI default algorithm": func() (*TOTP, error) { return ParseTOTPURI("otpauth://totp/x?secret=" + enc) },
		"URI explicit SHA1":     func() (*TOTP, error) { return ParseTOTPURI("otpauth://totp/x?secret=" + enc + "&algorithm=SHA1") },
		"bare seed":             func() (*TOTP, error) { return ParseTOTPSeed(enc, "", 0, 0) },
		"bare seed SHA-1":       func() (*TOTP, error) { return ParseTOTPSeed(enc, "sha-1", 0, 0) },
		"config":                func() (*TOTP, error) { return NewTOTP(TOTPConfig{Secret: seed256, Algorithm: "SHA1"}) },
	} {
		_, err := fn()
		if !errors.Is(err, ErrSHA1Unsupported) {
			t.Errorf("%s: err = %v, want ErrSHA1Unsupported", name, err)
		}
		if err != nil && !strings.Contains(err.Error(), "FIPS") {
			t.Errorf("%s: error does not explain FIPS mode: %v", name, err)
		}
	}
}

func TestTOTPValidation(t *testing.T) {
	enc := totp.EncodeSecret(seed256)
	good, err := ParseTOTPSeed(strings.ToLower(enc), "SHA256", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if good.cfg.Digits != 6 || good.cfg.Period != 30 {
		t.Fatalf("defaults = %+v", good.cfg)
	}
	for name, uri := range map[string]string{
		"hotp":          "otpauth://hotp/x?secret=" + enc + "&algorithm=SHA256&counter=1",
		"not otpauth":   "https://example.com/?secret=" + enc,
		"bad secret":    "otpauth://totp/x?secret=!!!&algorithm=SHA256",
		"short secret":  "otpauth://totp/x?secret=" + totp.EncodeSecret([]byte("short")) + "&algorithm=SHA256",
		"80-bit secret": "otpauth://totp/x?secret=" + totp.EncodeSecret([]byte("0123456789")) + "&algorithm=SHA256",
		"digits 5":      "otpauth://totp/x?secret=" + enc + "&algorithm=SHA256&digits=5",
		"digits 9":      "otpauth://totp/x?secret=" + enc + "&algorithm=SHA256&digits=9",
		"digits nan":    "otpauth://totp/x?secret=" + enc + "&algorithm=SHA256&digits=six",
		"period 0 text": "otpauth://totp/x?secret=" + enc + "&algorithm=SHA256&period=x",
		"period 5":      "otpauth://totp/x?secret=" + enc + "&algorithm=SHA256&period=5",
		"md5":           "otpauth://totp/x?secret=" + enc + "&algorithm=MD5",
	} {
		_, err := ParseTOTPURI(uri)
		if err == nil {
			t.Errorf("%s accepted", name)
			continue
		}
		if strings.Contains(err.Error(), enc) || strings.Contains(err.Error(), url.QueryEscape(enc)) {
			t.Errorf("%s: error leaks the secret: %v", name, err)
		}
	}
}
