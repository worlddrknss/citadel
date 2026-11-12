package main

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Password hashing: PBKDF2-HMAC-SHA256 (FIPS 140-3 approved, via Go's
// validated crypto module), PHC-style string format.
// ---------------------------------------------------------------------------

const (
	// OWASP's current recommendation for PBKDF2-HMAC-SHA256.
	pbkdf2Iterations    = 600_000
	pbkdf2KeyLen        = 32
	pbkdf2SaltLen       = 16
	pbkdf2Prefix        = "$pbkdf2-sha256$"
	pbkdf2MaxIterations = 10_000_000 // refuse absurd stored values
)

func readRandom(b []byte) error {
	_, err := io.ReadFull(rand.Reader, b)
	return err
}

// hashPassword returns a PBKDF2-HMAC-SHA256 hash string for the password:
// $pbkdf2-sha256$i=<iterations>$<salt b64>$<hash b64>
func hashPassword(password string) (string, error) {
	salt := make([]byte, pbkdf2SaltLen)
	if err := readRandom(salt); err != nil {
		return "", err
	}
	digest, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, pbkdf2KeyLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%si=%d$%s$%s", pbkdf2Prefix, pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest),
	), nil
}

func looksLikePBKDF2Hash(stored string) bool {
	return strings.HasPrefix(stored, pbkdf2Prefix)
}

// needsRehash reports whether a stored credential that just verified should be
// replaced with a current PBKDF2 hash: legacy plaintext values, and PBKDF2
// hashes with fewer iterations than today's setting.
func needsRehash(stored string) bool {
	if !looksLikePBKDF2Hash(stored) {
		return true
	}
	iterations, _, _, err := parsePBKDF2(stored)
	return err != nil || iterations < pbkdf2Iterations
}

// verifyPassword compares a candidate password against a stored credential:
// PBKDF2 hashes are verified cryptographically; anything
// else is treated as a legacy plaintext secret and compared in constant time.
// Verification always performs constant-time work to limit username-enumeration
// timing side channels.
func verifyPassword(stored, candidate string) bool {
	switch {
	case looksLikePBKDF2Hash(stored):
		ok, err := verifyPBKDF2(stored, candidate)
		return err == nil && ok
	}
	return compareSecret(stored, candidate)
}

func parsePBKDF2(encoded string) (iterations int, salt, want []byte, err error) {
	parts := strings.Split(encoded, "$")
	// ["", "pbkdf2-sha256", "i=600000", "<salt>", "<hash>"]
	if len(parts) != 5 || parts[1] != "pbkdf2-sha256" || !strings.HasPrefix(parts[2], "i=") {
		return 0, nil, nil, errors.New("invalid pbkdf2 hash format")
	}
	iterations, err = strconv.Atoi(strings.TrimPrefix(parts[2], "i="))
	if err != nil || iterations < 1 || iterations > pbkdf2MaxIterations {
		return 0, nil, nil, errors.New("invalid pbkdf2 iteration count")
	}
	if salt, err = base64.RawStdEncoding.DecodeString(parts[3]); err != nil {
		return 0, nil, nil, err
	}
	if want, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return 0, nil, nil, err
	}
	return iterations, salt, want, nil
}

func verifyPBKDF2(encoded, candidate string) (bool, error) {
	iterations, salt, want, err := parsePBKDF2(encoded)
	if err != nil {
		return false, err
	}
	got, err := pbkdf2.Key(sha256.New, candidate, salt, iterations, len(want))
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// ---------------------------------------------------------------------------
// HKDF-SHA256 (RFC 5869), stdlib-only
// ---------------------------------------------------------------------------

func hkdfSHA256(secret, salt, info []byte, length int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	// Extract
	extractor := hmac.New(sha256.New, salt)
	extractor.Write(secret)
	prk := extractor.Sum(nil)

	// Expand
	var out []byte
	var prev []byte
	counter := byte(1)
	for len(out) < length {
		h := hmac.New(sha256.New, prk)
		h.Write(prev)
		h.Write(info)
		h.Write([]byte{counter})
		prev = h.Sum(nil)
		out = append(out, prev...)
		counter++
	}
	return out[:length]
}

// deriveWrappingKeyHKDF derives a 32-byte wrapping key from a master key using
// HKDF-SHA256 with a fixed info label. This replaces a bare single SHA-256 so a
// leaked master key does not trivially reveal the wrapping key.
func deriveWrappingKeyHKDF(masterKey []byte) []byte {
	return hkdfSHA256(masterKey, []byte("go-kms/wrap/salt/v2"), []byte("go-kms-wrapping-key-v2"), 32)
}

// ---------------------------------------------------------------------------
// HTTP middleware
// ---------------------------------------------------------------------------

// withPanicRecovery converts unhandled panics into a generic 500 and logs the
// stack server-side, preventing a single bad request from crashing the process.
func withPanicRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic recovered: %v\n%s", rec, debug.Stack())
				w.Header().Set("Content-Type", "application/x-amz-json-1.1")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"__type":"InternalFailure","message":"internal error"}`))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// withSecurityHeaders adds defensive headers, primarily for the admin UI.
func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/login" || r.URL.Path == "/logout" || r.URL.Path == "/secrets" || r.URL.Path == "/audit" || strings.HasPrefix(r.URL.Path, "/admin") {
			h := w.Header()
			h.Set("X-Frame-Options", "DENY")
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		}
		next.ServeHTTP(w, r)
	})
}

// sessionExpired reports whether a UI session has exceeded its idle or absolute
// lifetime.
func sessionExpired(sess uiSession, now time.Time, idleTTL, absoluteTTL time.Duration) bool {
	if absoluteTTL > 0 && now.Sub(sess.CreatedAt) > absoluteTTL {
		return true
	}
	if idleTTL > 0 && now.Sub(sess.LastSeenAt) > idleTTL {
		return true
	}
	return false
}
