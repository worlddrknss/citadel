package memory

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// GetUIUser returns one console user.
func (s *Store) GetUIUser(_ context.Context, username string) (store.UIUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.uiUsers[strings.TrimSpace(username)]
	if !ok {
		return store.UIUser{}, store.ErrUIUserNotFound
	}
	u.Accounts = slices.Clone(u.Accounts)
	return u, nil
}

// CountUIUsers returns how many console users the store holds.
func (s *Store) CountUIUsers(_ context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.uiUsers), nil
}

// Bootstrap performs first-run setup under the store mutex, so concurrent
// calls are serialized and only the first succeeds.
func (s *Store) Bootstrap(_ context.Context, req store.BootstrapRequest) (string, error) {
	username := strings.TrimSpace(req.Username)
	if username == "" || strings.TrimSpace(req.PasswordHash) == "" {
		return "", errors.New("bootstrap requires a username and password hash")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.uiUsers) > 0 {
		return "", store.ErrAlreadyBootstrapped
	}
	accountID, err := s.createUIAccountLocked(req.AccountName)
	if err != nil {
		return "", err
	}
	if s.uiUsers == nil {
		s.uiUsers = map[string]store.UIUser{}
	}
	display := strings.TrimSpace(req.DisplayName)
	if display == "" {
		display = username
	}
	s.uiUsers[username] = store.UIUser{
		Username:      username,
		PasswordHash:  req.PasswordHash,
		Role:          "admin",
		DisplayName:   display,
		PlatformAdmin: true,
	}
	s.addMemberLocked(username, accountID, "admin")
	s.orgSettings.OrganizationName = strings.TrimSpace(req.OrganizationName)
	return accountID, nil
}

func (s *Store) CreateConsoleSession(_ context.Context, sess store.ConsoleSession) error {
	if sess.ID == "" || sess.TokenHash == "" || sess.Username == "" {
		return errors.New("console session requires an id, token hash and username")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions == nil {
		s.sessions = map[string]store.ConsoleSession{}
	}
	for _, existing := range s.sessions {
		if existing.TokenHash == sess.TokenHash {
			return errors.New("duplicate session token")
		}
	}
	s.sessions[sess.ID] = sess
	return nil
}

func (s *Store) GetConsoleSessionByTokenHash(_ context.Context, tokenHash string) (store.ConsoleSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.sessions {
		if sess.TokenHash == tokenHash {
			return sess, nil
		}
	}
	return store.ConsoleSession{}, store.ErrConsoleSessionNotFound
}

func (s *Store) TouchConsoleSession(_ context.Context, id string, lastSeen time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return store.ErrConsoleSessionNotFound
	}
	if lastSeen.After(sess.LastSeenAt) {
		sess.LastSeenAt = lastSeen
		s.sessions[id] = sess
	}
	return nil
}

func (s *Store) SetConsoleSessionAccount(_ context.Context, id, accountID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return store.ErrConsoleSessionNotFound
	}
	sess.AccountID = accountID
	s.sessions[id] = sess
	return nil
}

func (s *Store) ListConsoleSessions(_ context.Context, username string) ([]store.ConsoleSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []store.ConsoleSession
	for _, sess := range s.sessions {
		if sess.Username == username {
			out = append(out, sess)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *Store) DeleteConsoleSession(_ context.Context, username, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok || sess.Username != username {
		return store.ErrConsoleSessionNotFound
	}
	delete(s.sessions, id)
	return nil
}

func (s *Store) DeleteUserConsoleSessions(_ context.Context, username, keepID string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for id, sess := range s.sessions {
		if sess.Username == username && id != keepID {
			delete(s.sessions, id)
			n++
		}
	}
	return n, nil
}

func (s *Store) DeleteExpiredConsoleSessions(_ context.Context, now, idleCutoff time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for id, sess := range s.sessions {
		if !now.Before(sess.ExpiresAt) || (!idleCutoff.IsZero() && sess.LastSeenAt.Before(idleCutoff)) {
			delete(s.sessions, id)
			n++
		}
	}
	return n, nil
}

func (s *Store) GetOrgSettings(_ context.Context) (store.OrgSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.orgSettings
	out.ApprovalEnvironments = slices.Clone(out.ApprovalEnvironments)
	if out.ApprovalMinApprovers == 0 {
		out.ApprovalMinApprovers = 1
	}
	return out, nil
}

func (s *Store) PutOrgSettings(_ context.Context, settings store.OrgSettings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	settings.ApprovalEnvironments = slices.Clone(settings.ApprovalEnvironments)
	s.orgSettings = settings
	return nil
}

func (s *Store) ListSSOProviders(_ context.Context, enabledOnly bool) ([]store.SSOProvider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []store.SSOProvider{}
	for _, p := range s.ssoProviders {
		if enabledOnly && !p.Enabled {
			continue
		}
		p.Scopes = slices.Clone(p.Scopes)
		p.RoleMappings = slices.Clone(p.RoleMappings)
		out = append(out, p)
	}
	return out, nil
}
