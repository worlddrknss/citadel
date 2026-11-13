package memory

import (
	"context"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// memIdentity is the in-memory state behind store.IdentityStore. It is
// guarded by Store.mu.
type memIdentity struct {
	ssoSecrets map[string][]byte
	identities map[string]store.ExternalIdentity // provider \x00 subject
	consumed   map[string]time.Time
	keys       []store.WorkloadSigningKey // newest first
	settings   store.WorkloadIssuerSettings
	clients    map[string]store.WorkloadClient
}

func (s *Store) identityLocked() *memIdentity {
	if s.idn == nil {
		s.idn = &memIdentity{
			ssoSecrets: map[string][]byte{},
			identities: map[string]store.ExternalIdentity{},
			consumed:   map[string]time.Time{},
			clients:    map[string]store.WorkloadClient{},
		}
	}
	return s.idn
}

func cloneSSOProvider(p store.SSOProvider) store.SSOProvider {
	p.Scopes = slices.Clone(p.Scopes)
	p.RoleMappings = slices.Clone(p.RoleMappings)
	p.AllowedEmailDomains = slices.Clone(p.AllowedEmailDomains)
	return p
}

func (s *Store) ssoIndexLocked(id string) int {
	for i, p := range s.ssoProviders {
		if p.ID == id {
			return i
		}
	}
	return -1
}

func (s *Store) sortSSOLocked() {
	sort.SliceStable(s.ssoProviders, func(i, j int) bool {
		a, b := s.ssoProviders[i], s.ssoProviders[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.ID < b.ID
	})
}

func (s *Store) GetSSOProvider(_ context.Context, id string) (store.SSOProvider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.ssoIndexLocked(id)
	if i < 0 {
		return store.SSOProvider{}, store.ErrSSOProviderNotFound
	}
	return cloneSSOProvider(s.ssoProviders[i]), nil
}

func (s *Store) GetSSOProviderSecret(_ context.Context, id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ssoIndexLocked(id) < 0 {
		return nil, store.ErrSSOProviderNotFound
	}
	return slices.Clone(s.identityLocked().ssoSecrets[id]), nil
}

func (s *Store) CreateSSOProvider(_ context.Context, p store.SSOProvider, sealedSecret []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ssoIndexLocked(p.ID) >= 0 {
		return store.ErrSSOProviderExists
	}
	p = cloneSSOProvider(p)
	p.ClientSecretSet = len(sealedSecret) > 0
	s.ssoProviders = append(s.ssoProviders, p)
	s.sortSSOLocked()
	if len(sealedSecret) > 0 {
		s.identityLocked().ssoSecrets[p.ID] = slices.Clone(sealedSecret)
	}
	return nil
}

func (s *Store) UpdateSSOProvider(_ context.Context, p store.SSOProvider, sealedSecret []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.ssoIndexLocked(p.ID)
	if i < 0 {
		return store.ErrSSOProviderNotFound
	}
	idn := s.identityLocked()
	if sealedSecret != nil {
		idn.ssoSecrets[p.ID] = slices.Clone(sealedSecret)
	}
	p = cloneSSOProvider(p)
	p.CreatedAt = s.ssoProviders[i].CreatedAt
	p.ClientSecretSet = len(idn.ssoSecrets[p.ID]) > 0
	s.ssoProviders[i] = p
	s.sortSSOLocked()
	return nil
}

func (s *Store) DeleteSSOProvider(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.ssoIndexLocked(id)
	if i < 0 {
		return store.ErrSSOProviderNotFound
	}
	s.ssoProviders = slices.Delete(s.ssoProviders, i, i+1)
	idn := s.identityLocked()
	delete(idn.ssoSecrets, id)
	for k, v := range idn.identities {
		if v.ProviderID == id {
			delete(idn.identities, k)
		}
	}
	return nil
}

func extIdentityKey(provider, subject string) string { return provider + "\x00" + subject }

func (s *Store) GetExternalIdentity(_ context.Context, providerID, subject string) (store.ExternalIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.identityLocked().identities[extIdentityKey(providerID, subject)]
	if !ok {
		return store.ExternalIdentity{}, store.ErrExternalIdentityNotFound
	}
	return v, nil
}

func (s *Store) CreateExternalIdentity(_ context.Context, id store.ExternalIdentity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ssoIndexLocked(id.ProviderID) < 0 {
		return store.ErrSSOProviderNotFound
	}
	idn := s.identityLocked()
	k := extIdentityKey(id.ProviderID, id.Subject)
	if _, ok := idn.identities[k]; ok {
		return store.ErrExternalIdentityExists
	}
	idn.identities[k] = id
	return nil
}

func (s *Store) TouchExternalIdentity(_ context.Context, providerID, subject, email string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	idn := s.identityLocked()
	k := extIdentityKey(providerID, subject)
	v, ok := idn.identities[k]
	if !ok {
		return store.ErrExternalIdentityNotFound
	}
	v.Email, v.LastLoginAt = email, at
	idn.identities[k] = v
	return nil
}

func (s *Store) ConsumeOnce(_ context.Context, id string, expires time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idn := s.identityLocked()
	if exp, ok := idn.consumed[id]; ok && time.Now().Before(exp) {
		return false, nil
	}
	idn.consumed[id] = expires
	return true, nil
}

func (s *Store) PurgeConsumed(_ context.Context, now time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	idn := s.identityLocked()
	for k, exp := range idn.consumed {
		if exp.Before(now) {
			delete(idn.consumed, k)
			n++
		}
	}
	return n, nil
}

func (s *Store) ListWorkloadSigningKeys(_ context.Context) ([]store.WorkloadSigningKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.identityLocked().keys), nil
}

func (s *Store) RotateWorkloadSigningKey(_ context.Context, next store.WorkloadSigningKey, expectCurrentKID string, retiredAt, unpublishAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	idn := s.identityLocked()
	current := ""
	for i, k := range idn.keys {
		if k.RetiredAt.IsZero() {
			current = k.KID
			if current == expectCurrentKID {
				idn.keys[i].RetiredAt, idn.keys[i].UnpublishAt = retiredAt, unpublishAt
			}
			break
		}
	}
	if current != expectCurrentKID {
		return store.ErrWorkloadRotationConflict
	}
	for _, k := range idn.keys {
		if k.KID == next.KID {
			return store.ErrWorkloadRotationConflict
		}
	}
	next.RetiredAt, next.UnpublishAt = time.Time{}, time.Time{}
	idn.keys = append([]store.WorkloadSigningKey{next}, idn.keys...)
	return nil
}

func (s *Store) DeleteUnpublishedWorkloadSigningKeys(_ context.Context, now time.Time) ([]store.WorkloadSigningKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idn := s.identityLocked()
	var gone []store.WorkloadSigningKey
	kept := idn.keys[:0:0]
	for _, k := range idn.keys {
		if !k.RetiredAt.IsZero() && k.UnpublishAt.Before(now) {
			gone = append(gone, k)
			continue
		}
		kept = append(kept, k)
	}
	idn.keys = kept
	return gone, nil
}

func (s *Store) GetWorkloadIssuerSettings(_ context.Context) (store.WorkloadIssuerSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.identityLocked().settings, nil
}

func (s *Store) PutWorkloadIssuerSettings(_ context.Context, settings store.WorkloadIssuerSettings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identityLocked().settings = settings
	return nil
}

func cloneWorkloadClient(c store.WorkloadClient) store.WorkloadClient {
	c.Audiences = slices.Clone(c.Audiences)
	c.AllowedUsers = slices.Clone(c.AllowedUsers)
	c.ServiceAccounts = slices.Clone(c.ServiceAccounts)
	return c
}

func (s *Store) CreateWorkloadClient(_ context.Context, c store.WorkloadClient) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	idn := s.identityLocked()
	if _, ok := idn.clients[c.ClientID]; ok {
		return store.ErrWorkloadClientExists
	}
	if workloadNameTakenLocked(idn.clients, c) {
		return store.ErrWorkloadClientNameTaken
	}
	idn.clients[c.ClientID] = cloneWorkloadClient(c)
	return nil
}

// workloadNameTakenLocked reports whether another client in c's account has
// c's name, ignoring case (the Postgres store's unique index).
func workloadNameTakenLocked(clients map[string]store.WorkloadClient, c store.WorkloadClient) bool {
	for id, o := range clients {
		if id != c.ClientID && o.AccountID == c.AccountID && strings.EqualFold(o.Name, c.Name) {
			return true
		}
	}
	return false
}

func (s *Store) GetWorkloadClient(_ context.Context, clientID string) (store.WorkloadClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.identityLocked().clients[clientID]
	if !ok {
		return store.WorkloadClient{}, store.ErrWorkloadClientNotFound
	}
	return cloneWorkloadClient(c), nil
}

func (s *Store) ListWorkloadClients(_ context.Context, accountID string) ([]store.WorkloadClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []store.WorkloadClient{}
	for _, c := range s.identityLocked().clients {
		if c.AccountID == accountID {
			out = append(out, cloneWorkloadClient(c))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if a, b := strings.ToLower(out[i].Name), strings.ToLower(out[j].Name); a != b {
			return a < b
		}
		return out[i].ClientID < out[j].ClientID
	})
	return out, nil
}

func (s *Store) UpdateWorkloadClient(_ context.Context, c store.WorkloadClient) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	idn := s.identityLocked()
	old, ok := idn.clients[c.ClientID]
	if !ok || old.AccountID != c.AccountID {
		return store.ErrWorkloadClientNotFound
	}
	if workloadNameTakenLocked(idn.clients, c) {
		return store.ErrWorkloadClientNameTaken
	}
	c.CreatedAt, c.LastIssuedAt = old.CreatedAt, old.LastIssuedAt
	idn.clients[c.ClientID] = cloneWorkloadClient(c)
	return nil
}

func (s *Store) DeleteWorkloadClient(_ context.Context, accountID, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	idn := s.identityLocked()
	old, ok := idn.clients[clientID]
	if !ok || old.AccountID != accountID {
		return store.ErrWorkloadClientNotFound
	}
	delete(idn.clients, clientID)
	return nil
}

func (s *Store) TouchWorkloadClientIssued(_ context.Context, clientID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	idn := s.identityLocked()
	c, ok := idn.clients[clientID]
	if !ok {
		return store.ErrWorkloadClientNotFound
	}
	c.LastIssuedAt = at
	idn.clients[clientID] = c
	return nil
}
