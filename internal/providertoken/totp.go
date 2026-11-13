package providertoken

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/totp"
)

// ErrSHA1Unsupported is returned for TOTP seeds that use HMAC-SHA-1, the
// default of the otpauth:// format and of most sites. Citadel runs Go's FIPS
// 140-3 module with fips140=only, where HMAC-SHA-1 is not an approved
// algorithm (the standard library panics if it is used), so such seeds
// cannot produce codes. Re-enrol the site's authenticator with SHA-256 or
// SHA-512 if it offers that.
var ErrSHA1Unsupported = errors.New("providertoken: totp: SHA-1 TOTP seeds are not supported: HMAC-SHA-1 is not an approved algorithm in FIPS 140-3 mode; re-enrol with SHA-256 or SHA-512 if the site supports it")

// TOTP parameter bounds.
const (
	minTOTPDigits    = 6
	maxTOTPDigits    = 8
	minTOTPPeriod    = 10
	maxTOTPPeriod    = 300
	minTOTPKeyBytes  = 14 // 112 bits: FIPS 140-only mode refuses shorter HMAC keys
	maxTOTPKeyBytes  = 128
	defaultTOTPDigit = 6
	defaultTOTPStep  = 30
)

// TOTPConfig is a parsed TOTP seed.
type TOTPConfig struct {
	Secret    []byte
	Algorithm string // "SHA256" or "SHA512"
	Digits    int    // 6–8
	Period    int    // seconds, 10–300
	Issuer    string // informational
}

// TOTP generates RFC 6238 codes for an agent login credential. It reads
// Params.At.
type TOTP struct {
	cfg TOTPConfig
	h   func() hash.Hash
	now func() time.Time
}

// ParseTOTPURI parses an otpauth://totp/ key URI. A missing algorithm means
// SHA1 (the format's default) and returns ErrSHA1Unsupported, as does an
// explicit SHA1. Errors never include the secret.
func ParseTOTPURI(raw string) (*TOTP, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "otpauth" {
		return nil, errors.New("providertoken: totp: not an otpauth:// URI")
	}
	if !strings.EqualFold(u.Host, "totp") {
		return nil, errors.New("providertoken: totp: only otpauth://totp/ URIs are supported")
	}
	q := u.Query()
	cfg := TOTPConfig{Algorithm: q.Get("algorithm"), Issuer: q.Get("issuer")}
	if cfg.Algorithm == "" {
		cfg.Algorithm = "SHA1"
	}
	if d := q.Get("digits"); d != "" {
		n, err := strconv.Atoi(d)
		if err != nil {
			return nil, errors.New("providertoken: totp: invalid digits")
		}
		cfg.Digits = n
	}
	if p := q.Get("period"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, errors.New("providertoken: totp: invalid period")
		}
		cfg.Period = n
	}
	secret, err := totp.DecodeSecret(q.Get("secret"))
	if err != nil {
		return nil, errors.New("providertoken: totp: invalid base32 secret")
	}
	cfg.Secret = secret
	return NewTOTP(cfg)
}

// ParseTOTPSeed builds a TOTP from a bare base32 seed. A bare seed carries
// no algorithm, and sites that hand one out almost always mean SHA1, so the
// algorithm must be given explicitly; empty means SHA1 and returns
// ErrSHA1Unsupported. Zero digits or period take the defaults (6, 30).
func ParseTOTPSeed(seed, algorithm string, digits, period int) (*TOTP, error) {
	secret, err := totp.DecodeSecret(seed)
	if err != nil {
		return nil, errors.New("providertoken: totp: invalid base32 secret")
	}
	if algorithm == "" {
		algorithm = "SHA1"
	}
	return NewTOTP(TOTPConfig{Secret: secret, Algorithm: algorithm, Digits: digits, Period: period})
}

// NewTOTP validates cfg.
func NewTOTP(cfg TOTPConfig) (*TOTP, error) {
	var h func() hash.Hash
	switch strings.ToUpper(strings.ReplaceAll(cfg.Algorithm, "-", "")) {
	case "SHA1", "":
		// Never construct HMAC-SHA-1: it panics under fips140=only.
		return nil, ErrSHA1Unsupported
	case "SHA256":
		h, cfg.Algorithm = sha256.New, "SHA256"
	case "SHA512":
		h, cfg.Algorithm = sha512.New, "SHA512"
	default:
		return nil, errors.New("providertoken: totp: unsupported algorithm (SHA256 or SHA512)")
	}
	if cfg.Digits == 0 {
		cfg.Digits = defaultTOTPDigit
	}
	if cfg.Digits < minTOTPDigits || cfg.Digits > maxTOTPDigits {
		return nil, errors.New("providertoken: totp: digits must be 6 to 8")
	}
	if cfg.Period == 0 {
		cfg.Period = defaultTOTPStep
	}
	if cfg.Period < minTOTPPeriod || cfg.Period > maxTOTPPeriod {
		return nil, errors.New("providertoken: totp: period must be 10 to 300 seconds")
	}
	if len(cfg.Secret) < minTOTPKeyBytes || len(cfg.Secret) > maxTOTPKeyBytes {
		return nil, errors.New("providertoken: totp: secret must be 112 to 1024 bits (FIPS 140-3 mode refuses shorter HMAC keys)")
	}
	cfg.Secret = append([]byte(nil), cfg.Secret...)
	return &TOTP{cfg: cfg, h: h, now: time.Now}, nil
}

// Code returns the code for time t and when it stops being current (the end
// of its time step).
func (t *TOTP) Code(at time.Time) (string, time.Time) {
	period := int64(t.cfg.Period)
	step := at.Unix() / period
	if at.Unix() < 0 {
		step = 0
	}
	code := totp.CodeWith(t.h, t.cfg.Secret, uint64(step), t.cfg.Digits)
	return code, time.Unix((step+1)*period, 0).UTC()
}

// Mint returns the current code. ExpiresAt is the end of the time step;
// Metadata carries the algorithm, digits and period.
func (t *TOTP) Mint(ctx context.Context, p Params) (Token, error) {
	if err := ctx.Err(); err != nil {
		return Token{}, err
	}
	at := p.At
	if at.IsZero() {
		at = t.now()
	}
	code, exp := t.Code(at)
	meta := map[string]string{
		"algorithm": t.cfg.Algorithm,
		"digits":    strconv.Itoa(t.cfg.Digits),
		"period":    strconv.Itoa(t.cfg.Period),
	}
	return Token{Value: code, ExpiresAt: exp, Kind: KindTOTP, Metadata: meta}, nil
}
