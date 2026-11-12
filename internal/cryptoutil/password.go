package cryptoutil

// Password hashing: PBKDF2-HMAC-SHA256 (FIPS 140-3 approved, via Go's
// validated crypto module), PHC-style string format.

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	// OWASP's current recommendation for PBKDF2-HMAC-SHA256.
	pbkdf2Iterations    = 600_000
	pbkdf2KeyLen        = 32
	pbkdf2SaltLen       = 16
	pbkdf2Prefix        = "$pbkdf2-sha256$"
	pbkdf2MaxIterations = 10_000_000 // refuse absurd stored values
)

// HashPassword returns a PBKDF2-HMAC-SHA256 hash string for the password:
// $pbkdf2-sha256$i=<iterations>$<salt b64>$<hash b64>
func HashPassword(password string) (string, error) {
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

// NeedsRehash reports whether a stored credential that just verified should be
// replaced with a current PBKDF2 hash: legacy plaintext values, and PBKDF2
// hashes with fewer iterations than today's setting.
func NeedsRehash(stored string) bool {
	if !looksLikePBKDF2Hash(stored) {
		return true
	}
	iterations, _, _, err := parsePBKDF2(stored)
	return err != nil || iterations < pbkdf2Iterations
}

// VerifyPassword compares a candidate password against a stored credential:
// PBKDF2 hashes are verified cryptographically; anything
// else is treated as a legacy plaintext secret and compared in constant time.
// Verification always performs constant-time work to limit username-enumeration
// timing side channels.
func VerifyPassword(stored, candidate string) bool {
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
