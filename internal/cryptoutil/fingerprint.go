package cryptoutil

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// FingerprintHexLen is the length of a value fingerprint in hex characters
// (48 bits): enough to tell values apart at a glance, too short to be a
// useful oracle.
const FingerprintHexLen = 12

// DeriveFingerprintKey derives the per-deployment key that keys value
// fingerprints, from the deployment's root key material (the KMS wrapping
// key) with HKDF-SHA256 under a dedicated label, so it is independent of
// every other key derived from the same root.
func DeriveFingerprintKey(root []byte) []byte {
	return hkdfSHA256(root, []byte("citadel/value-fingerprint/salt/v1"), []byte("citadel-value-fingerprint-v1"), 32)
}

// ValueFingerprint returns a keyed fingerprint of a secret value:
// HMAC-SHA256(key, value) truncated to FingerprintHexLen hex characters.
//
// It is deliberately NOT sha256(value). A plain hash shown to viewers lets
// anyone who can read it brute-force low-entropy secrets offline; without the
// deployment key the HMAC output reveals nothing about the value, while two
// equal values still share a fingerprint within one deployment.
func ValueFingerprint(key, value []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write(value)
	return hex.EncodeToString(m.Sum(nil))[:FingerprintHexLen]
}
