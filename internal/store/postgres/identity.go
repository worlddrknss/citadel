package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/worlddrknss/citadel/internal/arn"
	"github.com/worlddrknss/citadel/internal/store"
)

// ListUIUsers returns the admin-console users persisted in the database.
func (s *Store) ListUIUsers(ctx context.Context) ([]store.UIUser, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT username, password_hash, role, display_name, accounts_json, platform_admin FROM ui_users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []store.UIUser
	for rows.Next() {
		var (
			user         store.UIUser
			accountsJSON string
		)
		if err := rows.Scan(&user.Username, &user.PasswordHash, &user.Role, &user.DisplayName, &accountsJSON, &user.PlatformAdmin); err != nil {
			return nil, err
		}
		user.Accounts = store.DecodeAccountsJSON(accountsJSON)
		users = append(users, user)
	}
	return users, rows.Err()
}

// UpsertUIUser inserts or updates an admin-console user. The PasswordHash field
// must already contain a password hash; plaintext passwords are never stored.
func (s *Store) UpsertUIUser(ctx context.Context, user store.UIUser) error {
	username := strings.TrimSpace(user.Username)
	if username == "" {
		return errors.New("ui user requires a username")
	}
	if strings.TrimSpace(user.PasswordHash) == "" {
		return errors.New("ui user requires a password hash")
	}
	accountsJSON, err := store.EncodeAccountsJSON(user.Accounts)
	if err != nil {
		return err
	}
	const q = `INSERT INTO ui_users (username, password_hash, role, display_name, accounts_json, platform_admin, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, NOW())
ON CONFLICT (username) DO UPDATE SET
	password_hash = EXCLUDED.password_hash,
	role = EXCLUDED.role,
	display_name = EXCLUDED.display_name,
	accounts_json = EXCLUDED.accounts_json,
	platform_admin = EXCLUDED.platform_admin,
	updated_at = NOW()`
	_, err = s.db.ExecContext(ctx, q, username, user.PasswordHash, store.NormalizeUIRole(user.Role), user.DisplayName, accountsJSON, user.PlatformAdmin)
	return err
}

// DeleteUIUser removes an admin-console user.
func (s *Store) DeleteUIUser(ctx context.Context, username string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM ui_users WHERE username = $1`, strings.TrimSpace(username))
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return store.ErrUIUserNotFound
	}
	return nil
}

// CreateUIAccount creates a new account with a generated account ID and the given display name.
func (s *Store) CreateUIAccount(ctx context.Context, name string) (string, error) {
	name = store.NormalizeAccountName(name)
	if name == "" {
		return "", errors.New("account name is required")
	}
	accountID := arn.GenerateAccountID()
	// Ensure uniqueness (retry if collision, though very unlikely)
	for {
		var exists int
		err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ui_accounts WHERE account_id = $1`, accountID).Scan(&exists)
		if err != nil {
			return "", err
		}
		if exists == 0 {
			break
		}
		accountID = arn.GenerateAccountID()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO ui_accounts (account_id, account, created_at, updated_at) VALUES ($1, $2, NOW(), NOW())`,
		accountID, name,
	)
	if err != nil {
		if strings.Contains(err.Error(), "unique constraint") {
			return "", fmt.Errorf("account name already exists")
		}
		return "", err
	}
	return accountID, nil
}

// GetUIAccount retrieves an account by its account ID.
func (s *Store) GetUIAccount(ctx context.Context, accountID string) (store.UIAccountInfo, error) {
	var info store.UIAccountInfo
	err := s.db.QueryRowContext(ctx,
		`SELECT account_id, account, created_at, updated_at FROM ui_accounts WHERE account_id = $1`,
		accountID,
	).Scan(&info.AccountID, &info.Name, &info.CreatedAt, &info.UpdatedAt)
	if err == sql.ErrNoRows {
		return info, store.ErrUIAccountNotFound
	}
	return info, err
}

// ListUIAccounts retrieves all accounts sorted by name.
func (s *Store) ListUIAccounts(ctx context.Context) ([]store.UIAccountInfo, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT account_id, account, created_at, updated_at FROM ui_accounts ORDER BY account`)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var accounts []store.UIAccountInfo
	for rows.Next() {
		var info store.UIAccountInfo
		if err := rows.Scan(&info.AccountID, &info.Name, &info.CreatedAt, &info.UpdatedAt); err != nil {
			return nil, err
		}
		accounts = append(accounts, info)
	}
	return accounts, rows.Err()
}

// DeleteUIAccount deletes an account by its account ID.
func (s *Store) DeleteUIAccount(ctx context.Context, accountID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM ui_accounts WHERE account_id = $1`, accountID)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return store.ErrUIAccountNotFound
	}
	return nil
}

// UpsertUIAccount updates an account's name (legacy method, kept for compatibility).
func (s *Store) UpsertUIAccount(ctx context.Context, account string) error {
	account = store.NormalizeAccountName(account)
	if account == "" {
		return errors.New("account is required")
	}
	// This is a legacy method. For now, try to insert; if account already exists, do nothing.
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO ui_accounts (account_id, account, created_at, updated_at)
VALUES ($1, $2, NOW(), NOW())
ON CONFLICT (account) DO NOTHING`,
		arn.GenerateAccountID(), account,
	)
	return err
}

// AddUserAccount adds a user to an account with a specific role.
func (s *Store) AddUserAccount(ctx context.Context, username, accountID, role string) error {
	username = strings.TrimSpace(username)
	accountID = strings.TrimSpace(accountID)
	role = strings.TrimSpace(role)
	if username == "" || accountID == "" {
		return errors.New("username and accountID are required")
	}
	if role == "" {
		role = "Viewer"
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO user_accounts (username, account_id, role, created_at, updated_at)
VALUES ($1, $2, $3, NOW(), NOW())
ON CONFLICT (username, account_id) DO UPDATE SET role = EXCLUDED.role, updated_at = NOW()`,
		username, accountID, role,
	)
	return err
}

// RemoveUserAccount removes a user from an account.
func (s *Store) RemoveUserAccount(ctx context.Context, username, accountID string) error {
	username = strings.TrimSpace(username)
	accountID = strings.TrimSpace(accountID)
	if username == "" || accountID == "" {
		return errors.New("username and accountID are required")
	}
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM user_accounts WHERE username = $1 AND account_id = $2`,
		username, accountID,
	)
	return err
}

// ListUserAccounts returns all accounts a user belongs to.
func (s *Store) ListUserAccounts(ctx context.Context, username string) ([]store.UserAccountInfo, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, errors.New("username is required")
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT account_id, role FROM user_accounts WHERE username = $1 ORDER BY account_id`,
		username,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var accounts []store.UserAccountInfo
	for rows.Next() {
		var info store.UserAccountInfo
		if err := rows.Scan(&info.AccountID, &info.Role); err != nil {
			return nil, err
		}
		accounts = append(accounts, info)
	}
	return accounts, rows.Err()
}

// ListAccountUsers returns all users in an account.
func (s *Store) ListAccountUsers(ctx context.Context, accountID string) ([]struct{ Username, Role string }, error) {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return nil, errors.New("accountID is required")
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT username, role FROM user_accounts WHERE account_id = $1 ORDER BY username`,
		accountID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []struct{ Username, Role string }
	for rows.Next() {
		var u struct{ Username, Role string }
		if err := rows.Scan(&u.Username, &u.Role); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// CreateAccessKey creates a new access key for a user in an account.
// Returns the access key ID and secret (only shown once).
// Max 2 keys per (user, account) pair.
func (s *Store) CreateAccessKey(ctx context.Context, username, accountID string) (store.AccessKeySecret, error) {
	username = strings.TrimSpace(username)
	accountID = strings.TrimSpace(accountID)
	if username == "" || accountID == "" {
		return store.AccessKeySecret{}, errors.New("username and accountID are required")
	}

	// Check current key count
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM iam_access_keys WHERE username = $1 AND account_id = $2 AND status = 'Active'`,
		username, accountID,
	).Scan(&count)
	if err != nil {
		return store.AccessKeySecret{}, err
	}
	if count >= 2 {
		return store.AccessKeySecret{}, store.ErrMaxAccessKeys
	}

	keyID := store.GenerateAccessKeyID()
	secret := store.GenerateAccessKeySecret()

	// Wrap the secret with the store's wrapping key
	wrappedB64, nonceB64, err := s.wrapKeyMaterial(keyID, []byte(secret))
	if err != nil {
		return store.AccessKeySecret{}, fmt.Errorf("wrap secret: %w", err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO iam_access_keys (access_key_id, username, account_id, secret_wrapped_b64, secret_nonce_b64, status, created_at)
VALUES ($1, $2, $3, $4, $5, 'Active', NOW())`,
		keyID, username, accountID, wrappedB64, nonceB64,
	)
	if err != nil {
		return store.AccessKeySecret{}, err
	}

	return store.AccessKeySecret{AccessKeyID: keyID, SecretKey: secret}, nil
}

// ListAccessKeys returns all access keys for a user in an account.
func (s *Store) ListAccessKeys(ctx context.Context, username, accountID string) ([]store.AccessKeyInfo, error) {
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

	var keys []store.AccessKeyInfo
	for rows.Next() {
		var info store.AccessKeyInfo
		if err := rows.Scan(&info.AccessKeyID, &info.Username, &info.AccountID, &info.Status, &info.CreatedAt, &info.LastUsedAt); err != nil {
			return nil, err
		}
		keys = append(keys, info)
	}
	return keys, rows.Err()
}

// GetAccessKeyByID retrieves an access key by its ID (used for SigV4 verification).
// Returns the unwrapped secret for HMAC verification.
func (s *Store) GetAccessKeyByID(ctx context.Context, keyID string) (username, accountID, secret string, status string, err error) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return "", "", "", "", errors.New("keyID is required")
	}

	// Temporary STS credentials (ASIA-prefixed) live in sts_sessions, not
	// iam_access_keys. Resolve them here so the same SigV4 verification path
	// validates long-lived and temporary credentials uniformly. An expired
	// session is reported as Inactive so callers reject it.
	if store.IsTempAccessKeyID(keyID) {
		acct, sec, _, _, serr := s.GetSTSSessionSecret(ctx, keyID)
		if serr == store.ErrSTSSessionExpired {
			return "", "", "", "Inactive", nil
		}
		if serr == store.ErrSTSSessionNotFound {
			return "", "", "", "", store.ErrAccessKeyNotFound
		}
		if serr != nil {
			return "", "", "", "", serr
		}
		return keyID, acct, sec, "Active", nil
	}

	var wrappedB64, nonceB64 string
	err = s.db.QueryRowContext(ctx,
		`SELECT username, account_id, secret_wrapped_b64, secret_nonce_b64, status
FROM iam_access_keys
WHERE access_key_id = $1`,
		keyID,
	).Scan(&username, &accountID, &wrappedB64, &nonceB64, &status)
	if err == sql.ErrNoRows {
		return "", "", "", "", store.ErrAccessKeyNotFound
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
func (s *Store) SetAccessKeyStatus(ctx context.Context, keyID, newStatus string) error {
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
		return store.ErrAccessKeyNotFound
	}
	return nil
}

// DeleteAccessKey deletes an access key.
func (s *Store) DeleteAccessKey(ctx context.Context, keyID string) error {
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
		return store.ErrAccessKeyNotFound
	}
	return nil
}

// TouchAccessKeyLastUsed updates the last_used_at timestamp.
func (s *Store) TouchAccessKeyLastUsed(ctx context.Context, keyID string) error {
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
