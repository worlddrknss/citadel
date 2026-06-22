package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	errAccessKeyNotFound = errors.New("access key not found")
	errMaxAccessKeys     = errors.New("maximum access keys per account reached (limit: 2)")
)

// accessKeyInfo represents metadata about an access key.
type accessKeyInfo struct {
	AccessKeyID string
	Username    string
	AccountID   string
	Status      string
	CreatedAt   time.Time
	LastUsedAt  *time.Time
}

// accessKeySecret is the sensitive secret that's shown once to the user.
type accessKeySecret struct {
	AccessKeyID string
	SecretKey   string
}

// generateAccessKeyID generates an AWS-style access key ID (AKIA + 16 chars).
func generateAccessKeyID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "AKIA" + base64.RawStdEncoding.EncodeToString(b)[:16]
}

// generateAccessKeySecret generates a 40-character secret key.
func generateAccessKeySecret() string {
	b := make([]byte, 30)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)[:40]
}

// CreateAccessKey creates a new access key for a user in an account.
// Returns the access key ID and secret (only shown once).
// Max 2 keys per (user, account) pair.
func (s *dbStore) CreateAccessKey(ctx context.Context, username, accountID string) (accessKeySecret, error) {
	username = strings.TrimSpace(username)
	accountID = strings.TrimSpace(accountID)
	if username == "" || accountID == "" {
		return accessKeySecret{}, errors.New("username and accountID are required")
	}

	// Check current key count
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM iam_access_keys WHERE username = $1 AND account_id = $2 AND status = 'Active'`,
		username, accountID,
	).Scan(&count)
	if err != nil {
		return accessKeySecret{}, err
	}
	if count >= 2 {
		return accessKeySecret{}, errMaxAccessKeys
	}

	keyID := generateAccessKeyID()
	secret := generateAccessKeySecret()

	// Wrap the secret with the store's wrapping key
	wrappedB64, nonceB64, err := s.wrapKeyMaterial(keyID, []byte(secret))
	if err != nil {
		return accessKeySecret{}, fmt.Errorf("wrap secret: %w", err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO iam_access_keys (access_key_id, username, account_id, secret_wrapped_b64, secret_nonce_b64, status, created_at)
VALUES ($1, $2, $3, $4, $5, 'Active', NOW())`,
		keyID, username, accountID, wrappedB64, nonceB64,
	)
	if err != nil {
		return accessKeySecret{}, err
	}

	return accessKeySecret{AccessKeyID: keyID, SecretKey: secret}, nil
}

// ListAccessKeys returns all access keys for a user in an account.
func (s *dbStore) ListAccessKeys(ctx context.Context, username, accountID string) ([]accessKeyInfo, error) {
	username = strings.TrimSpace(username)
	accountID = strings.TrimSpace(accountID)
	if username == "" || accountID == "" {
		return nil, errors.New("username and accountID are required")
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT access_key_id, username, account_id, status, created_at, last_used_at
FROM iam_access_keys
WHERE username = $1 AND account_id = $2
ORDER BY created_at DESC`,
		username, accountID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []accessKeyInfo
	for rows.Next() {
		var info accessKeyInfo
		if err := rows.Scan(&info.AccessKeyID, &info.Username, &info.AccountID, &info.Status, &info.CreatedAt, &info.LastUsedAt); err != nil {
			return nil, err
		}
		keys = append(keys, info)
	}
	return keys, rows.Err()
}

// GetAccessKeyByID retrieves an access key by its ID (used for SigV4 verification).
// Returns the unwrapped secret for HMAC verification.
func (s *dbStore) GetAccessKeyByID(ctx context.Context, keyID string) (username, accountID, secret string, status string, err error) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return "", "", "", "", errors.New("keyID is required")
	}

	var wrappedB64, nonceB64 string
	err = s.db.QueryRowContext(ctx,
		`SELECT username, account_id, secret_wrapped_b64, secret_nonce_b64, status
FROM iam_access_keys
WHERE access_key_id = $1`,
		keyID,
	).Scan(&username, &accountID, &wrappedB64, &nonceB64, &status)
	if err == sql.ErrNoRows {
		return "", "", "", "", errAccessKeyNotFound
	}
	if err != nil {
		return "", "", "", "", err
	}

	// Unwrap the secret
	secretBytes, err := s.unwrapKeyMaterial(keyID, wrappedB64, nonceB64)
	if err != nil {
		return "", "", "", "", fmt.Errorf("unwrap secret: %w", err)
	}

	return username, accountID, string(secretBytes), status, nil
}

// SetAccessKeyStatus activates or deactivates an access key.
func (s *dbStore) SetAccessKeyStatus(ctx context.Context, keyID, newStatus string) error {
	keyID = strings.TrimSpace(keyID)
	newStatus = strings.TrimSpace(newStatus)
	if keyID == "" || (newStatus != "Active" && newStatus != "Inactive") {
		return errors.New("invalid keyID or status")
	}

	res, err := s.db.ExecContext(ctx,
		`UPDATE iam_access_keys SET status = $1 WHERE access_key_id = $2`,
		newStatus, keyID,
	)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errAccessKeyNotFound
	}
	return nil
}

// DeleteAccessKey deletes an access key.
func (s *dbStore) DeleteAccessKey(ctx context.Context, keyID string) error {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return errors.New("keyID is required")
	}

	res, err := s.db.ExecContext(ctx,
		`DELETE FROM iam_access_keys WHERE access_key_id = $1`,
		keyID,
	)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errAccessKeyNotFound
	}
	return nil
}

// TouchAccessKeyLastUsed updates the last_used_at timestamp.
func (s *dbStore) TouchAccessKeyLastUsed(ctx context.Context, keyID string) error {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return errors.New("keyID is required")
	}

	_, err := s.db.ExecContext(ctx,
		`UPDATE iam_access_keys SET last_used_at = NOW() WHERE access_key_id = $1`,
		keyID,
	)
	return err
}

// In-memory store implementations

func (s *inMemoryStore) CreateAccessKey(_ context.Context, username, accountID string) (accessKeySecret, error) {
	return accessKeySecret{}, errUnsupported
}

func (s *inMemoryStore) ListAccessKeys(_ context.Context, username, accountID string) ([]accessKeyInfo, error) {
	return nil, errUnsupported
}

func (s *inMemoryStore) GetAccessKeyByID(_ context.Context, keyID string) (username, accountID, secret string, status string, err error) {
	return "", "", "", "", errUnsupported
}

func (s *inMemoryStore) SetAccessKeyStatus(_ context.Context, keyID, newStatus string) error {
	return errUnsupported
}

func (s *inMemoryStore) DeleteAccessKey(_ context.Context, keyID string) error {
	return errUnsupported
}

func (s *inMemoryStore) TouchAccessKeyLastUsed(_ context.Context, keyID string) error {
	return errUnsupported
}
