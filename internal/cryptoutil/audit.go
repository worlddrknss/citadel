package cryptoutil

// DeriveAuditHMACKey derives the audit hash-chain HMAC key from the
// deployment's wrapping (or master) key, used when KMS_AUDIT_HMAC_KEY_B64 is
// not set. HKDF with a dedicated label keeps it independent of every other
// key derived from the same secret.
func DeriveAuditHMACKey(secret []byte) []byte {
	return hkdfSHA256(secret, []byte("citadel/audit/salt/v1"), []byte("citadel-audit-chain-hmac-v1"), 32)
}

// DeriveAuditStreamKey derives the AES-256-GCM key that seals SIEM stream
// bearer tokens at rest.
func DeriveAuditStreamKey(secret []byte) []byte {
	return hkdfSHA256(secret, []byte("citadel/audit/salt/v1"), []byte("citadel-audit-stream-token-v1"), 32)
}
