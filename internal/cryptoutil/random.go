// Package cryptoutil holds Citadel's low-level cryptographic helpers: password
// hashing, key derivation, AES-GCM sealing and random values. It only uses
// primitives from Go's FIPS 140-3 module (SHA-256, HMAC, PBKDF2, AES-GCM).
package cryptoutil

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"time"
)

func RandomHex(n int) string {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func compareSecret(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func readRandom(b []byte) error {
	_, err := io.ReadFull(rand.Reader, b)
	return err
}
