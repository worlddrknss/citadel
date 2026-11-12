package store

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var (
	ErrAccessKeyNotFound = errors.New("access key not found")
	ErrMaxAccessKeys     = errors.New("maximum access keys per account reached (limit: 2)")
)

// AccessKeyInfo represents metadata about an access key.
type AccessKeyInfo struct {
	AccessKeyID string
	Username    string
	AccountID   string
	Status      string
	CreatedAt   time.Time
	LastUsedAt  *time.Time
}

// AccessKeySecret is the sensitive secret that's shown once to the user.
type AccessKeySecret struct {
	AccessKeyID string
	SecretKey   string
}

// GenerateAccessKeyID generates an AWS-style access key ID (AKIA + 16 chars).
// The suffix uses the RFC 4648 base32 alphabet (A-Z, 2-7) so the ID only ever
// contains characters that are safe inside a SigV4 "Credential=" scope, which
// is slash-delimited. base64 (with '+' and '/') must not be used here: a '/'
// in the access key ID corrupts Authorization-header parsing.
func GenerateAccessKeyID() string {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "AKIA" + base32.StdEncoding.EncodeToString(b)
}

// GenerateAccessKeySecret generates a 40-character secret key.
func GenerateAccessKeySecret() string {
	b := make([]byte, 30)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)[:40]
}

var ErrUIAccountNotFound = errors.New("ui account not found")

// UIAccountInfo represents an account with its ID and display name.
type UIAccountInfo struct {
	AccountID string
	Name      string
	CreatedAt string
	UpdatedAt string
}

func NormalizeAccountName(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

// UserAccountInfo represents a user's membership in an account.
type UserAccountInfo struct {
	AccountID string
	Role      string
}

// ErrUIUserNotFound is returned when a UI user lookup or delete targets an
// unknown username.
var ErrUIUserNotFound = errors.New("ui user not found")

func DecodeAccountsJSON(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var accounts []string
	if err := json.Unmarshal([]byte(raw), &accounts); err != nil {
		return nil
	}
	return NormalizeAccounts(accounts)
}

func EncodeAccountsJSON(accounts []string) (string, error) {
	if len(accounts) == 0 {
		return "[]", nil
	}
	b, err := json.Marshal(NormalizeAccounts(accounts))
	if err != nil {
		return "", err
	}
	return string(b), nil
}
