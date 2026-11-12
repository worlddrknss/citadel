package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/worlddrknss/citadel/internal/arn"
	"github.com/worlddrknss/citadel/internal/store"
)

// CreateUIAccount creates a new account with a generated account ID and the given display name.
func (s *dbStore) CreateUIAccount(ctx context.Context, name string) (string, error) {
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
func (s *dbStore) GetUIAccount(ctx context.Context, accountID string) (store.UIAccountInfo, error) {
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
func (s *dbStore) ListUIAccounts(ctx context.Context) ([]store.UIAccountInfo, error) {
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
func (s *dbStore) DeleteUIAccount(ctx context.Context, accountID string) error {
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
func (s *dbStore) UpsertUIAccount(ctx context.Context, account string) error {
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

// In-memory store implementations

// User-Account Junction Table methods

// AddUserAccount adds a user to an account with a specific role.
func (s *dbStore) AddUserAccount(ctx context.Context, username, accountID, role string) error {
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
func (s *dbStore) RemoveUserAccount(ctx context.Context, username, accountID string) error {
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
func (s *dbStore) ListUserAccounts(ctx context.Context, username string) ([]store.UserAccountInfo, error) {
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
func (s *dbStore) ListAccountUsers(ctx context.Context, accountID string) ([]struct{ Username, Role string }, error) {
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

// In-memory store implementations for user_accounts
