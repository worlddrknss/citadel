package cryptoutil

// HKDF-SHA256 (RFC 5869), stdlib-only, and wrapping-key derivation.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

func DeriveDeterministicLegacyKeyID(masterKey []byte) string {
	sum := sha256.Sum256(masterKey)
	return hex.EncodeToString(sum[:8])
}

func DeriveWrappingKey(legacyMasterKey []byte) []byte {
	seed := append([]byte("go-kms-wrap-v1|"), legacyMasterKey...)
	sum := sha256.Sum256(seed)
	out := make([]byte, 32)
	copy(out, sum[:])
	return out
}

func HKDFSHA256(secret, salt, info []byte, length int) []byte {
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

// DeriveWrappingKeyHKDF derives a 32-byte wrapping key from a master key using
// HKDF-SHA256 with a fixed info label. This replaces a bare single SHA-256 so a
// leaked master key does not trivially reveal the wrapping key.
func DeriveWrappingKeyHKDF(masterKey []byte) []byte {
	return HKDFSHA256(masterKey, []byte("go-kms/wrap/salt/v2"), []byte("go-kms-wrapping-key-v2"), 32)
}
