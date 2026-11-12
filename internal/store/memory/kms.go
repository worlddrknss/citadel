package memory

import (
	"context"
	"database/sql"
	"sort"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

func (s *Store) ResolveByID(_ context.Context, keyID string) (store.KMSKey, error) {
	for _, key := range s.keysSnapshot() {
		if keyID == "" || keyID == key.ID {
			return key, nil
		}
	}
	return store.KMSKey{}, sql.ErrNoRows
}

func (s *Store) ResolveDefault(_ context.Context) (store.KMSKey, error) {
	keys := s.keysSnapshot()
	if len(keys) == 0 {
		return store.KMSKey{}, sql.ErrNoRows
	}
	return keys[0], nil
}

func (s *Store) EnsureBootstrap(_ context.Context, _ store.KMSKey) error {
	return nil
}

func (s *Store) EnsureAccountDefaultKey(_ context.Context, _ string) (store.KMSKey, error) {
	return store.KMSKey{}, store.ErrUnsupported
}

func (s *Store) CreateKey(_ context.Context, _ string, _ string, _ string) (store.KMSKey, error) {
	return store.KMSKey{}, store.ErrUnsupported
}

func (s *Store) ImportSigningKey(_ context.Context, _ string, _, _ []byte, _ string) (store.KMSKey, error) {
	return store.KMSKey{}, store.ErrUnsupported
}

func (s *Store) ListKeys(_ context.Context) ([]store.KMSKey, error) {
	return s.keysSnapshot(), nil
}

func (s *Store) GetKeyPolicy(_ context.Context, keyID, policyName string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if keyID != "" && keyID != s.DefaultKey.ID {
		return "", sql.ErrNoRows
	}
	if policyName == "" {
		policyName = "default"
	}
	if s.policies == nil {
		s.policies = map[string]string{}
	}
	if doc, ok := s.policies[policyName]; ok {
		return doc, nil
	}
	return store.DefaultKeyPolicy(s.DefaultKey), nil
}

func (s *Store) PutKeyPolicy(_ context.Context, keyID, policyName, policyDocument string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if keyID != "" && keyID != s.DefaultKey.ID {
		return sql.ErrNoRows
	}
	if policyName == "" {
		policyName = "default"
	}
	if s.policies == nil {
		s.policies = map[string]string{}
	}
	s.policies[policyName] = policyDocument
	return nil
}

func (s *Store) CreateAlias(_ context.Context, _, _ string) error {
	return store.ErrUnsupported
}

func (s *Store) UpdateAlias(_ context.Context, _, _ string) error {
	return store.ErrUnsupported
}

func (s *Store) DeleteAlias(_ context.Context, _ string) error {
	return store.ErrUnsupported
}

func (s *Store) ListAliases(_ context.Context) ([]store.KMSAlias, error) {
	if len(s.Aliases) == 0 {
		return nil, nil
	}
	out := make([]store.KMSAlias, len(s.Aliases))
	copy(out, s.Aliases)
	return out, nil
}

func (s *Store) keysSnapshot() []store.KMSKey {
	if len(s.Keys) == 0 {
		if strings.TrimSpace(s.DefaultKey.ID) == "" {
			return nil
		}
		return []store.KMSKey{s.DefaultKey}
	}
	out := make([]store.KMSKey, len(s.Keys))
	copy(out, s.Keys)
	return out
}

func (s *Store) SetKeyEnabled(_ context.Context, _ string, _ bool) error {
	return store.ErrUnsupported
}

func (s *Store) ScheduleKeyDeletion(_ context.Context, _ string, _ int) (time.Time, error) {
	return time.Time{}, store.ErrUnsupported
}

func (s *Store) CancelKeyDeletion(_ context.Context, _ string) error {
	return store.ErrUnsupported
}

func (s *Store) ForceDeleteKey(_ context.Context, _ string) error {
	return store.ErrUnsupported
}

func (s *Store) CreateGrant(_ context.Context, req store.CreateGrantRequest) (store.KMSGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	grant := store.KMSGrant{
		GrantID:           "grant-" + cryptoutil.RandomHex(12),
		GrantToken:        cryptoutil.RandomHex(16),
		KeyID:             req.KeyID,
		GranteePrincipal:  strings.TrimSpace(req.GranteePrincipal),
		RetiringPrincipal: strings.TrimSpace(req.RetiringPrincipal),
		Operations:        append([]string(nil), req.Operations...),
		Name:              strings.TrimSpace(req.Name),
		CreatedAt:         time.Now().UTC(),
	}
	s.grants = append(s.grants, grant)
	return grant, nil
}

func (s *Store) ListGrants(_ context.Context, keyID string) ([]store.KMSGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]store.KMSGrant, 0)
	for _, grant := range s.grants {
		if grant.KeyID == keyID {
			grantCopy := grant
			grantCopy.Operations = append([]string(nil), grant.Operations...)
			out = append(out, grantCopy)
		}
	}
	return out, nil
}

func (s *Store) RevokeGrant(_ context.Context, keyID, grantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, grant := range s.grants {
		if grant.KeyID == keyID && grant.GrantID == grantID {
			s.grants = append(s.grants[:i], s.grants[i+1:]...)
			return nil
		}
	}
	return sql.ErrNoRows
}

func (s *Store) RetireGrant(_ context.Context, grantID, grantToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, grant := range s.grants {
		if (grantID != "" && grant.GrantID == grantID) || (grantToken != "" && grant.GrantToken == grantToken) {
			s.grants = append(s.grants[:i], s.grants[i+1:]...)
			return nil
		}
	}
	return sql.ErrNoRows
}

func (s *Store) RecordAudit(_ context.Context, event store.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditSeq++
	createdAt := time.Now().UTC()
	entry := store.AuditRecord{ID: s.auditSeq, Action: event.Action, KeyID: event.KeyID, Result: event.Result, ErrorType: event.ErrorType, Actor: event.Actor, CreatedAt: createdAt}
	if len(s.audit) > 0 {
		entry.PrevHash = s.audit[len(s.audit)-1].EventHash
	}
	entry.EventHash = store.HashAuditRecord(s.AuditHMACKey, entry.PrevHash, event, createdAt.Format(time.RFC3339Nano))
	s.audit = append(s.audit, entry)
	return nil
}

func (s *Store) ListAuditEvents(_ context.Context, limit int) ([]store.AuditRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	if len(s.audit) == 0 {
		return nil, nil
	}
	items := make([]store.AuditRecord, len(s.audit))
	copy(items, s.audit)
	sort.Slice(items, func(i, j int) bool {
		return items[i].ID > items[j].ID
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}
