package cryptoutil

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// DeriveMFASecretKey derives the AES-256-GCM key that seals console users'
// TOTP secrets at rest from the deployment root secret.
func DeriveMFASecretKey(root []byte) []byte {
	return hkdfSHA256(root, []byte("citadel/mfa/salt/v1"), []byte("citadel-mfa-totp-secret-v1"), 32)
}

// DeriveMFATokenKey derives the HMAC-SHA256 key that signs pending-login
// (second factor) tokens from the deployment root secret.
func DeriveMFATokenKey(root []byte) []byte {
	return hkdfSHA256(root, []byte("citadel/mfa/salt/v1"), []byte("citadel-mfa-login-token-v1"), 32)
}

// recoveryCodeIterations is the PBKDF2 work factor for MFA recovery codes.
// They are generated from 60+ random bits, not chosen by people, so they do
// not need the password work factor; a lower count keeps checking a code
// against all ten stored hashes fast.
const recoveryCodeIterations = 20_000

// agentTokenIterations is the PBKDF2 work factor for agent token secrets.
// They are 256 random bits, so the hash only has to be one-way, not slow;
// a low count keeps every agent request cheap.
const agentTokenIterations = 10_000

// HashAgentToken returns a PBKDF2-HMAC-SHA256 hash of an agent token's
// secret part in the same format as HashPassword; VerifyPassword checks it.
func HashAgentToken(secret string) (string, error) {
	salt := make([]byte, pbkdf2SaltLen)
	if err := readRandom(salt); err != nil {
		return "", err
	}
	digest, err := pbkdf2.Key(sha256.New, secret, salt, agentTokenIterations, pbkdf2KeyLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%si=%d$%s$%s", pbkdf2Prefix, agentTokenIterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest),
	), nil
}

// HashRecoveryCode returns a PBKDF2-HMAC-SHA256 hash of a generated MFA
// recovery code in the same format as HashPassword; VerifyPassword checks it.
func HashRecoveryCode(code string) (string, error) {
	salt := make([]byte, pbkdf2SaltLen)
	if err := readRandom(salt); err != nil {
		return "", err
	}
	digest, err := pbkdf2.Key(sha256.New, code, salt, recoveryCodeIterations, pbkdf2KeyLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%si=%d$%s$%s", pbkdf2Prefix, recoveryCodeIterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest),
	), nil
}
