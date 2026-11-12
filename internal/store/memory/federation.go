package memory

import (
	"context"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// In-memory identity federation: OIDC providers, IAM roles and STS sessions,
// with the same semantics as the Postgres store (so STS can be exercised
// end to end without a database).

type memSTSSession struct {
	sess         store.STSSession
	secret       string
	sessionToken string
}

var _ store.STSSessionResolver = (*Store)(nil)

func (s *Store) CreateOIDCProvider(_ context.Context, p store.OIDCProvider) error {
	s.fedMu.Lock()
	defer s.fedMu.Unlock()
	p.URL = store.NormalizeIssuerURL(p.URL)
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	for i := range s.oidc {
		if s.oidc[i].ProviderARN == p.ProviderARN {
			s.oidc[i].URL, s.oidc[i].ClientIDs, s.oidc[i].Thumbprints = p.URL, p.ClientIDs, p.Thumbprints
			return nil
		}
	}
	s.oidc = append(s.oidc, p)
	return nil
}

func (s *Store) ListOIDCProviders(_ context.Context, accountID string) ([]store.OIDCProvider, error) {
	s.fedMu.Lock()
	defer s.fedMu.Unlock()
	out := []store.OIDCProvider{}
	for _, p := range s.oidc {
		if p.AccountID == strings.TrimSpace(accountID) {
			out = append(out, p)
		}
	}
	return out, nil
}

func (s *Store) GetOIDCProviderByURL(_ context.Context, accountID, url string) (store.OIDCProvider, error) {
	s.fedMu.Lock()
	defer s.fedMu.Unlock()
	url = store.NormalizeIssuerURL(url)
	for _, p := range s.oidc {
		if p.AccountID == strings.TrimSpace(accountID) && p.URL == url {
			return p, nil
		}
	}
	return store.OIDCProvider{}, store.ErrOIDCProviderNotFound
}

func (s *Store) DeleteOIDCProvider(_ context.Context, accountID, providerARN string) error {
	s.fedMu.Lock()
	defer s.fedMu.Unlock()
	for i, p := range s.oidc {
		if p.AccountID == accountID && p.ProviderARN == providerARN {
			s.oidc = append(s.oidc[:i], s.oidc[i+1:]...)
			return nil
		}
	}
	return store.ErrOIDCProviderNotFound
}

func (s *Store) CreateIAMRole(_ context.Context, role store.IAMRole) error {
	s.fedMu.Lock()
	defer s.fedMu.Unlock()
	now := time.Now().UTC()
	role.UpdatedAt = now
	for i := range s.roles {
		if s.roles[i].RoleARN == role.RoleARN {
			role.CreatedAt = s.roles[i].CreatedAt
			s.roles[i] = role
			return nil
		}
	}
	if role.CreatedAt.IsZero() {
		role.CreatedAt = now
	}
	s.roles = append(s.roles, role)
	return nil
}

func (s *Store) ListIAMRoles(_ context.Context, accountID string) ([]store.IAMRole, error) {
	s.fedMu.Lock()
	defer s.fedMu.Unlock()
	out := []store.IAMRole{}
	for _, r := range s.roles {
		if r.AccountID == strings.TrimSpace(accountID) {
			out = append(out, r)
		}
	}
	return out, nil
}

func (s *Store) GetIAMRole(_ context.Context, accountID, roleName string) (store.IAMRole, error) {
	s.fedMu.Lock()
	defer s.fedMu.Unlock()
	for _, r := range s.roles {
		if r.AccountID == strings.TrimSpace(accountID) && r.RoleName == roleName {
			return r, nil
		}
	}
	return store.IAMRole{}, store.ErrIAMRoleNotFound
}

func (s *Store) GetIAMRoleByARN(_ context.Context, roleARN string) (store.IAMRole, error) {
	s.fedMu.Lock()
	defer s.fedMu.Unlock()
	for _, r := range s.roles {
		if r.RoleARN == strings.TrimSpace(roleARN) {
			return r, nil
		}
	}
	return store.IAMRole{}, store.ErrIAMRoleNotFound
}

func (s *Store) DeleteIAMRole(_ context.Context, accountID, roleName string) error {
	s.fedMu.Lock()
	defer s.fedMu.Unlock()
	for i, r := range s.roles {
		if r.AccountID == accountID && r.RoleName == roleName {
			s.roles = append(s.roles[:i], s.roles[i+1:]...)
			return nil
		}
	}
	return store.ErrIAMRoleNotFound
}

func (s *Store) CreateSTSSession(_ context.Context, sess store.STSSession, secret, sessionToken string) error {
	s.fedMu.Lock()
	defer s.fedMu.Unlock()
	if s.stsSessions == nil {
		s.stsSessions = map[string]memSTSSession{}
	}
	if sess.CreatedAt.IsZero() {
		sess.CreatedAt = time.Now().UTC()
	}
	s.stsSessions[sess.AccessKeyID] = memSTSSession{sess: sess, secret: secret, sessionToken: sessionToken}
	return nil
}

func (s *Store) GetSTSSessionSecret(_ context.Context, keyID string) (accountID, secret, sessionToken string, expiresAt time.Time, err error) {
	s.fedMu.Lock()
	defer s.fedMu.Unlock()
	m, ok := s.stsSessions[keyID]
	if !ok {
		return "", "", "", time.Time{}, store.ErrSTSSessionNotFound
	}
	if time.Now().UTC().After(m.sess.ExpiresAt.UTC()) {
		return "", "", "", m.sess.ExpiresAt, store.ErrSTSSessionExpired
	}
	return m.sess.AccountID, m.secret, m.sessionToken, m.sess.ExpiresAt, nil
}

func (s *Store) DeleteExpiredSTSSessions(_ context.Context) (int64, error) {
	s.fedMu.Lock()
	defer s.fedMu.Unlock()
	var n int64
	now := time.Now().UTC()
	for id, m := range s.stsSessions {
		if now.After(m.sess.ExpiresAt.UTC()) {
			delete(s.stsSessions, id)
			n++
		}
	}
	return n, nil
}
