package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
)

var errUIAccountNotFound = errors.New("ui account not found")

// uiAccountInfo represents an account with its ID and display name.
type uiAccountInfo struct {
	AccountID string
	Name      string
	CreatedAt string
	UpdatedAt string
}

func normalizeAccountName(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

// CreateUIAccount creates a new account with a generated account ID and the given display name.
func (s *dbStore) CreateUIAccount(ctx context.Context, name string) (string, error) {
	name = normalizeAccountName(name)
	if name == "" {
		return "", errors.New("account name is required")
	}
	accountID := generateAccountID()
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
		accountID = generateAccountID()
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
func (s *dbStore) GetUIAccount(ctx context.Context, accountID string) (uiAccountInfo, error) {
	var info uiAccountInfo
	err := s.db.QueryRowContext(ctx,
		`SELECT account_id, account, created_at, updated_at FROM ui_accounts WHERE account_id = $1`,
		accountID,
	).Scan(&info.AccountID, &info.Name, &info.CreatedAt, &info.UpdatedAt)
	if err == sql.ErrNoRows {
		return info, errUIAccountNotFound
	}
	return info, err
}

// ListUIAccounts retrieves all accounts sorted by name.
func (s *dbStore) ListUIAccounts(ctx context.Context) ([]uiAccountInfo, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT account_id, account, created_at, updated_at FROM ui_accounts ORDER BY account`)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var accounts []uiAccountInfo
	for rows.Next() {
		var info uiAccountInfo
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
		return errUIAccountNotFound
	}
	return nil
}

// UpsertUIAccount updates an account's name (legacy method, kept for compatibility).
func (s *dbStore) UpsertUIAccount(ctx context.Context, account string) error {
	account = normalizeAccountName(account)
	if account == "" {
		return errors.New("account is required")
	}
	// This is a legacy method. For now, try to insert; if account already exists, do nothing.
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO ui_accounts (account_id, account, created_at, updated_at)
VALUES ($1, $2, NOW(), NOW())
ON CONFLICT (account) DO NOTHING`,
		generateAccountID(), account,
	)
	return err
}

// In-memory store implementations

func (s *inMemoryStore) CreateUIAccount(_ context.Context, name string) (string, error) {
	name = normalizeAccountName(name)
	if name == "" {
		return "", errors.New("account name is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uiAccounts == nil {
		s.uiAccounts = map[string]struct{}{}
	}
	// Check if account name already exists
	for _, user := range s.uiUsers {
		for _, acct := range user.Accounts {
			if normalizeAccountName(acct) == name {
				return "", fmt.Errorf("account name already exists")
			}
		}
	}
	accountID := generateAccountID()
	// In-memory: just track the existence; real accounts are in the in-memory accounts map.
	// For now, we'll return the generated ID.
	s.uiAccounts[accountID] = struct{}{}
	return accountID, nil
}

func (s *inMemoryStore) GetUIAccount(_ context.Context, accountID string) (uiAccountInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uiAccounts == nil {
		s.uiAccounts = map[string]struct{}{}
	}
	if _, ok := s.uiAccounts[accountID]; !ok {
		return uiAccountInfo{}, errUIAccountNotFound
	}
	// In-memory store doesn't have detailed account info; return minimal info.
	return uiAccountInfo{AccountID: accountID, Name: accountID}, nil
}

func (s *inMemoryStore) ListUIAccounts(_ context.Context) ([]uiAccountInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uiAccounts == nil {
		s.uiAccounts = map[string]struct{}{}
	}
	// Derive accounts from users' account lists.
	accountSet := make(map[string]struct{})
	for _, user := range s.uiUsers {
		for _, account := range user.Accounts {
			account = normalizeAccountName(account)
			if account != "" {
				accountSet[account] = struct{}{}
			}
		}
	}
	var accounts []uiAccountInfo
	for account := range accountSet {
		accounts = append(accounts, uiAccountInfo{AccountID: account, Name: account})
	}
	sort.Slice(accounts, func(i, j int) bool {
		return accounts[i].Name < accounts[j].Name
	})
	return accounts, nil
}

func (s *inMemoryStore) DeleteUIAccount(_ context.Context, accountID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uiAccounts == nil {
		s.uiAccounts = map[string]struct{}{}
	}
	if _, ok := s.uiAccounts[accountID]; !ok {
		return errUIAccountNotFound
	}
	delete(s.uiAccounts, accountID)
	return nil
}

func (s *inMemoryStore) UpsertUIAccount(_ context.Context, account string) error {
	account = normalizeAccountName(account)
	if account == "" {
		return errors.New("account is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uiAccounts == nil {
		s.uiAccounts = map[string]struct{}{}
	}
	s.uiAccounts[account] = struct{}{}
	return nil
}

// User-Account Junction Table methods

// userAccountInfo represents a user's membership in an account.
type userAccountInfo struct {
	AccountID string
	Role      string
}

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
func (s *dbStore) ListUserAccounts(ctx context.Context, username string) ([]userAccountInfo, error) {
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
	var accounts []userAccountInfo
	for rows.Next() {
		var info userAccountInfo
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

func (s *inMemoryStore) AddUserAccount(_ context.Context, username, accountID, role string) error {
	username = strings.TrimSpace(username)
	accountID = strings.TrimSpace(accountID)
	if username == "" || accountID == "" {
		return errors.New("username and accountID are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// In-memory: just track it in the uiUsers map via Accounts field
	if user, ok := s.uiUsers[username]; ok {
		// Add if not already present
		found := false
		for _, acct := range user.Accounts {
			if normalizeAccountName(acct) == accountID {
				found = true
				break
			}
		}
		if !found {
			user.Accounts = append(user.Accounts, accountID)
		}
	}
	return nil
}

func (s *inMemoryStore) RemoveUserAccount(_ context.Context, username, accountID string) error {
	username = strings.TrimSpace(username)
	accountID = strings.TrimSpace(accountID)
	if username == "" || accountID == "" {
		return errors.New("username and accountID are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if user, ok := s.uiUsers[username]; ok {
		filtered := make([]string, 0, len(user.Accounts))
		for _, acct := range user.Accounts {
			if normalizeAccountName(acct) != accountID {
				filtered = append(filtered, acct)
			}
		}
		user.Accounts = filtered
	}
	return nil
}

func (s *inMemoryStore) ListUserAccounts(_ context.Context, username string) ([]userAccountInfo, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, errors.New("username is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if user, ok := s.uiUsers[username]; ok {
		var accounts []userAccountInfo
		for _, acct := range user.Accounts {
			accounts = append(accounts, userAccountInfo{AccountID: acct, Role: "Owner"})
		}
		return accounts, nil
	}
	return nil, nil
}

func (s *inMemoryStore) ListAccountUsers(_ context.Context, accountID string) ([]struct{ Username, Role string }, error) {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return nil, errors.New("accountID is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var users []struct{ Username, Role string }
	for username, user := range s.uiUsers {
		for _, acct := range user.Accounts {
			if normalizeAccountName(acct) == accountID {
				users = append(users, struct{ Username, Role string }{username, "Owner"})
				break
			}
		}
	}
	sort.Slice(users, func(i, j int) bool {
		return users[i].Username < users[j].Username
	})
	return users, nil
}
