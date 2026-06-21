package main

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
)

var errUIAccountNotFound = errors.New("ui account not found")

func normalizeAccountName(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

func (s *dbStore) ListUIAccounts(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT account FROM ui_accounts ORDER BY account`)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var accounts []string
	for rows.Next() {
		var account string
		if err := rows.Scan(&account); err != nil {
			return nil, err
		}
		account = normalizeAccountName(account)
		if account != "" {
			accounts = append(accounts, account)
		}
	}
	return accounts, rows.Err()
}

func (s *dbStore) UpsertUIAccount(ctx context.Context, account string) error {
	account = normalizeAccountName(account)
	if account == "" {
		return errors.New("account is required")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO ui_accounts (account, updated_at) VALUES ($1, NOW()) ON CONFLICT (account) DO UPDATE SET updated_at = NOW()`, account)
	return err
}

func (s *dbStore) DeleteUIAccount(ctx context.Context, account string) error {
	account = normalizeAccountName(account)
	if account == "" {
		return errors.New("account is required")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM ui_accounts WHERE account = $1`, account)
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

func (s *inMemoryStore) ListUIAccounts(_ context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uiAccounts == nil {
		s.uiAccounts = map[string]struct{}{}
	}
	for _, user := range s.uiUsers {
		for _, account := range user.Accounts {
			account = normalizeAccountName(account)
			if account != "" {
				s.uiAccounts[account] = struct{}{}
			}
		}
	}
	accounts := make([]string, 0, len(s.uiAccounts))
	for account := range s.uiAccounts {
		accounts = append(accounts, account)
	}
	sort.Strings(accounts)
	return accounts, nil
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

func (s *inMemoryStore) DeleteUIAccount(_ context.Context, account string) error {
	account = normalizeAccountName(account)
	if account == "" {
		return errors.New("account is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uiAccounts == nil {
		s.uiAccounts = map[string]struct{}{}
	}
	if _, ok := s.uiAccounts[account]; !ok {
		return errUIAccountNotFound
	}
	delete(s.uiAccounts, account)
	return nil
}
