package memory

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

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
	delete(s.members, username)
	for id, sess := range s.sessions {
		if sess.Username == username {
			delete(s.sessions, id)
		}
	}
	return nil
}

func (s *Store) CreateUIAccount(_ context.Context, name string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createUIAccountLocked(name)
}

// createUIAccountLocked creates an account; s.mu must be held.
func (s *Store) createUIAccountLocked(name string) (string, error) {
	name = store.NormalizeAccountName(name)
	if name == "" {
		return "", errors.New("account name is required")
	}
	if s.uiAccounts == nil {
		s.uiAccounts = map[string]store.UIAccountInfo{}
	}
	for _, a := range s.uiAccounts {
		if a.Name == name {
			return "", fmt.Errorf("account name already exists")
		}
	}
	for _, user := range s.uiUsers {
		for _, acct := range user.Accounts {
			if store.NormalizeAccountName(acct) == name {
				return "", fmt.Errorf("account name already exists")
			}
		}
	}
	accountID := arn.GenerateAccountID()
	for _, taken := s.uiAccounts[accountID]; taken; _, taken = s.uiAccounts[accountID] {
		accountID = arn.GenerateAccountID()
	}
	now := time.Now().UTC().Format(time.RFC3339)
	s.uiAccounts[accountID] = store.UIAccountInfo{AccountID: accountID, Name: name, CreatedAt: now, UpdatedAt: now}
	return accountID, nil
}

func (s *Store) GetUIAccount(_ context.Context, accountID string) (store.UIAccountInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.uiAccounts[accountID]
	if !ok {
		return store.UIAccountInfo{}, store.ErrUIAccountNotFound
	}
	return a, nil
}

// ListUIAccounts returns the created accounts plus, for env-configured users,
// the accounts named in their account lists.
func (s *Store) ListUIAccounts(_ context.Context) ([]store.UIAccountInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]struct{}{}
	var accounts []store.UIAccountInfo
	for _, a := range s.uiAccounts {
		seen[a.AccountID] = struct{}{}
		accounts = append(accounts, a)
	}
	for _, user := range s.uiUsers {
		for _, account := range user.Accounts {
			account = store.NormalizeAccountName(account)
			if _, dup := seen[account]; account == "" || dup {
				continue
			}
			seen[account] = struct{}{}
			accounts = append(accounts, store.UIAccountInfo{AccountID: account, Name: account})
		}
	}
	sort.Slice(accounts, func(i, j int) bool {
		return accounts[i].Name < accounts[j].Name
	})
	return accounts, nil
}

func (s *Store) DeleteUIAccount(_ context.Context, accountID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.uiAccounts[accountID]; !ok {
		return store.ErrUIAccountNotFound
	}
	delete(s.uiAccounts, accountID)
	for _, m := range s.members {
		delete(m, accountID)
	}
	return nil
}

func (s *Store) UpsertUIAccount(_ context.Context, account string) error {
	account = store.NormalizeAccountName(account)
	if account == "" {
		return errors.New("account is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.uiAccounts {
		if a.Name == account {
			return nil
		}
	}
	_, err := s.createUIAccountLocked(account)
	return err
}

// AddUserAccount grants username the role in accountID, replacing any role
// already held there.
func (s *Store) AddUserAccount(_ context.Context, username, accountID, role string) error {
	username = strings.TrimSpace(username)
	accountID = strings.TrimSpace(accountID)
	if username == "" || accountID == "" {
		return errors.New("username and accountID are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addMemberLocked(username, accountID, role)
	return nil
}

func (s *Store) addMemberLocked(username, accountID, role string) {
	if s.members == nil {
		s.members = map[string]map[string]string{}
	}
	if s.members[username] == nil {
		s.members[username] = map[string]string{}
	}
	role = strings.TrimSpace(role)
	if role == "" {
		role = "viewer"
	}
	s.members[username][accountID] = role
}

func (s *Store) RemoveUserAccount(_ context.Context, username, accountID string) error {
	username = strings.TrimSpace(username)
	accountID = strings.TrimSpace(accountID)
	if username == "" || accountID == "" {
		return errors.New("username and accountID are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.members[username], accountID)
	if user, ok := s.uiUsers[username]; ok {
		filtered := make([]string, 0, len(user.Accounts))
		for _, acct := range user.Accounts {
			if store.NormalizeAccountName(acct) != store.NormalizeAccountName(accountID) {
				filtered = append(filtered, acct)
			}
		}
		user.Accounts = filtered
		s.uiUsers[username] = user
	}
	return nil
}

// ListUserAccounts returns username's memberships: explicit ones with their
// role, and accounts from the user's static account list with role "Owner"
// (the legacy marker for "use the user's global role").
func (s *Store) ListUserAccounts(_ context.Context, username string) ([]store.UserAccountInfo, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, errors.New("username is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var accounts []store.UserAccountInfo
	for acct, role := range s.members[username] {
		accounts = append(accounts, store.UserAccountInfo{AccountID: acct, Role: role})
	}
	if user, ok := s.uiUsers[username]; ok {
		for _, acct := range user.Accounts {
			if _, explicit := s.members[username][acct]; !explicit {
				accounts = append(accounts, store.UserAccountInfo{AccountID: acct, Role: "Owner"})
			}
		}
	}
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].AccountID < accounts[j].AccountID })
	return accounts, nil
}

func (s *Store) ListAccountUsers(_ context.Context, accountID string) ([]struct{ Username, Role string }, error) {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return nil, errors.New("accountID is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var users []struct{ Username, Role string }
	seen := map[string]bool{}
	for username, m := range s.members {
		if role, ok := m[accountID]; ok {
			seen[username] = true
			users = append(users, struct{ Username, Role string }{username, role})
		}
	}
	for username, user := range s.uiUsers {
		if seen[username] {
			continue
		}
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
