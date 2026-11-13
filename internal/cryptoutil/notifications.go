package cryptoutil

// DeriveNotificationSealKey derives the AES-256-GCM key that seals
// notification channel secrets (webhook signing secrets, Slack webhook URLs)
// at rest.
func DeriveNotificationSealKey(secret []byte) []byte {
	return hkdfSHA256(secret, []byte("citadel/notifications/salt/v1"), []byte("citadel-notification-secret-v1"), 32)
}
