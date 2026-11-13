package cryptoutil

// DeriveRotationSigningKeySealKey derives the AES-256-GCM key that seals the
// webhook rotators' HMAC signing secrets at rest.
func DeriveRotationSigningKeySealKey(secret []byte) []byte {
	return hkdfSHA256(secret, []byte("citadel/rotation/salt/v1"), []byte("citadel-rotation-signing-key-v1"), 32)
}
