// Package totp implements time-based one-time passwords (RFC 6238) on top of
// HOTP (RFC 4226) for console multi-factor authentication.
//
// The HMAC is HMAC-SHA-256 (RFC 6238's "SHA256" mode), not the SHA-1 most
// authenticator apps default to: Go's FIPS 140-3 module refuses HMAC with
// SHA-1 in fips140=only mode ("use of hash functions other than SHA-2 or
// SHA-3 is not allowed"), and Citadel runs that way in production. The
// otpauth:// URI therefore carries algorithm=SHA256, which the authenticator
// app must honour (1Password, Authy and Microsoft Authenticator do).
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"net/url"
	"strings"
	"time"
)

const (
	// Digits is the code length.
	Digits = 6
	// Period is the time step in seconds.
	Period = 30
	// Skew is how many steps either side of the current one are accepted.
	Skew = 1
	// SecretSize is the shared secret length in bytes (160 bits).
	SecretSize = 20
	// Algorithm is the otpauth algorithm parameter.
	Algorithm = "SHA256"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// hotp computes an RFC 4226 HOTP value with the given HMAC hash, using
// dynamic truncation, as a zero-padded decimal string of digits length.
func hotp(h func() hash.Hash, key []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(h, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	v := bin % mod
	out := make([]byte, digits)
	for i := digits - 1; i >= 0; i-- {
		out[i] = byte('0' + v%10)
		v /= 10
	}
	return string(out)
}

// Step returns the RFC 6238 time step containing t.
func Step(t time.Time) int64 {
	return t.Unix() / Period
}

// Code returns the TOTP code for a time step.
func Code(key []byte, step int64) string {
	return hotp(sha256.New, key, uint64(step), Digits)
}

// CodeWith returns the HOTP value for counter with an arbitrary HMAC hash
// and digit count, for one-time passwords whose parameters are set by a
// third-party site rather than by Citadel (agent login credentials). The
// caller must only pass a SHA-2 or SHA-3 constructor: HMAC-SHA-1 panics
// under fips140=only. digits must be between 1 and 9.
func CodeWith(h func() hash.Hash, key []byte, counter uint64, digits int) string {
	return hotp(h, key, counter, digits)
}

// Verify checks code against the steps within Skew of now and returns the
// matching step. Steps at or before lastStep are refused, so a code (or an
// older one) can never be used twice. Every candidate is compared, in
// constant time, whether or not an earlier one matched.
func Verify(key []byte, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != Digits {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	cur := Step(now)
	matched := int64(0)
	found := 0
	for s := cur - Skew; s <= cur+Skew; s++ {
		eq := subtle.ConstantTimeCompare([]byte(Code(key, s)), []byte(code))
		if eq == 1 && s > lastStep && found == 0 {
			matched, found = s, 1
		}
	}
	return matched, found == 1
}

// NewSecret returns a fresh random shared secret.
func NewSecret() ([]byte, error) {
	b := make([]byte, SecretSize)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// EncodeSecret is the unpadded base32 form authenticator apps take.
func EncodeSecret(key []byte) string {
	return b32.EncodeToString(key)
}

// DecodeSecret parses EncodeSecret's output (case-insensitive, spaces
// ignored).
func DecodeSecret(s string) ([]byte, error) {
	s = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
	s = strings.TrimRight(s, "=")
	b, err := b32.DecodeString(s)
	if err != nil {
		return nil, errors.New("invalid base32 secret")
	}
	return b, nil
}

// URI builds the otpauth:// key URI authenticator apps import (usually from
// a QR code).
func URI(issuer, account string, key []byte) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", EncodeSecret(key))
	q.Set("issuer", issuer)
	q.Set("algorithm", Algorithm)
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/" + label + "?" + q.Encode()
}
