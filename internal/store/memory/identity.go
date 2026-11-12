package memory

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/worlddrknss/citadel/internal/arn"
	"github.com/worlddrknss/citadel/internal/store"
)

// ListUIUsers returns admin-console users held in memory.
func (s *Store) ListUIUsers(_ context.Context) ([]store.UIUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	users := make([]store.UIUser, 0, len(s.uiUsers))
	for _, user := range s.uiUsers {
		users = append(users, user)
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
	return users, nil
}

// UpsertUIUser stores an admin-console user in memory.
func (s *Store) UpsertUIUser(_ context.Context, user store.UIUser) error {
	username := strings.TrimSpace(user.Username)
	if username == "" {
		return errors.New("ui user requires a username")
	}
	if strings.TrimSpace(user.PasswordHash) == "" {
		return errors.New("ui user requires a password hash")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uiUsers == nil {
		s.uiUsers = map[string]store.UIUser{}
	}
	user.Username = username
	user.Role = store.NormalizeUIRole(user.Role)
	s.uiUsers[username] = user
	return nil
}

// DeleteUIUser removes an admin-console user from memory.
func (s *Store) DeleteUIUser(_ context.Context, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	username = strings.TrimSpace(username)
	if _, ok := s.uiUsers[username]; !ok {
		return store.ErrUIUserNotFound
	}
	delete(s.uiUsers, username)
	return nil
}

func (s *Store) CreateUIAccount(_ context.Context, name string) (string, error) {
	name = store.NormalizeAccountName(name)
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
			if store.NormalizeAccountName(acct) == name {
				return "", fmt.Errorf("account name already exists")
			}
		}
	}
	accountID := arn.GenerateAccountID()
	// In-memory: just track the existence; real accounts are in the in-memory accounts map.
	// For now, we'll return the generated ID.
	s.uiAccounts[accountID] = struct{}{}
	return accountID, nil
}

func (s *Store) GetUIAccount(_ context.Context, accountID string) (store.UIAccountInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uiAccounts == nil {
		s.uiAccounts = map[string]struct{}{}
	}
	if _, ok := s.uiAccounts[accountID]; !ok {
		return store.UIAccountInfo{}, store.ErrUIAccountNotFound
	}
	// In-memory store doesn't have detailed account info; return minimal info.
	return store.UIAccountInfo{AccountID: accountID, Name: accountID}, nil
}

func (s *Store) ListUIAccounts(_ context.Context) ([]store.UIAccountInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uiAccounts == nil {
		s.uiAccounts = map[string]struct{}{}
	}
	// Derive accounts from users' account lists.
	accountSet := make(map[string]struct{})
	for _, user := range s.uiUsers {
		for _, account := range user.Accounts {
			account = store.NormalizeAccountName(account)
			if account != "" {
				accountSet[account] = struct{}{}
			}
		}
	}
	var accounts []store.UIAccountInfo
	for account := range accountSet {
		accounts = append(accounts, store.UIAccountInfo{AccountID: account, Name: account})
	}
	sort.Slice(accounts, func(i, j int) bool {
		return accounts[i].Name < accounts[j].Name
	})
	return accounts, nil
}

func (s *Store) DeleteUIAccount(_ context.Context, accountID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uiAccounts == nil {
		s.uiAccounts = map[string]struct{}{}
	}
	if _, ok := s.uiAccounts[accountID]; !ok {
		return store.ErrUIAccountNotFound
	}
	delete(s.uiAccounts, accountID)
	return nil
}

func (s *Store) UpsertUIAccount(_ context.Context, account string) error {
	account = store.NormalizeAccountName(account)
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

func (s *Store) AddUserAccount(_ context.Context, username, accountID, role string) error {
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
			if store.NormalizeAccountName(acct) == accountID {
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

func (s *Store) RemoveUserAccount(_ context.Context, username, accountID string) error {
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
			if store.NormalizeAccountName(acct) != accountID {
				filtered = append(filtered, acct)
			}
		}
		user.Accounts = filtered
	}
	return nil
}

func (s *Store) ListUserAccounts(_ context.Context, username string) ([]store.UserAccountInfo, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, errors.New("username is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if user, ok := s.uiUsers[username]; ok {
		var accounts []store.UserAccountInfo
		for _, acct := range user.Accounts {
			accounts = append(accounts, store.UserAccountInfo{AccountID: acct, Role: "Owner"})
		}
		return accounts, nil
	}
	return nil, nil
}

func (s *Store) ListAccountUsers(_ context.Context, accountID string) ([]struct{ Username, Role string }, error) {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return nil, errors.New("accountID is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var users []struct{ Username, Role string }
	for username, user := range s.uiUsers {
		for _, acct := range user.Accounts {
			if store.NormalizeAccountName(acct) == accountID {
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

func (s *Store) CreateAccessKey(_ context.Context, username, accountID string) (store.AccessKeySecret, error) {
	return store.AccessKeySecret{}, store.ErrUnsupported
}

func (s *Store) ListAccessKeys(_ context.Context, username, accountID string) ([]store.AccessKeyInfo, error) {
	return nil, store.ErrUnsupported
}

func (s *Store) GetAccessKeyByID(_ context.Context, keyID string) (username, accountID, secret string, status string, err error) {
	return "", "", "", "", store.ErrUnsupported
}

func (s *Store) SetAccessKeyStatus(_ context.Context, keyID, newStatus string) error {
	return store.ErrUnsupported
}

func (s *Store) DeleteAccessKey(_ context.Context, keyID string) error {
	return store.ErrUnsupported
}

func (s *Store) TouchAccessKeyLastUsed(_ context.Context, keyID string) error {
	return store.ErrUnsupported
}
