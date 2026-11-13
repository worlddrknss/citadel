package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/worlddrknss/citadel/internal/store"
)

// awsCompatState is the in-memory state behind the KMS write path, the
// federation store and AWS list pagination. kmsMu is separate from Store.mu
// because the secret and parameter methods resolve keys while holding mu.
type awsCompatState struct {
	kmsMu       sync.Mutex
	keyAccounts map[string]string // run-time key ID -> owning account
	aliases     []memAlias

	fedMu       sync.Mutex
	oidc        []store.OIDCProvider
	roles       []store.IAMRole
	stsSessions map[string]memSTSSession
}

var _ store.AWSPageStore = (*Store)(nil)

func pageLimit(limit int) int {
	if limit <= 0 {
		return 100
	}
	return limit
}

func (s *Store) ListKeysPage(ctx context.Context, after string, limit int) ([]store.KMSKey, bool, error) {
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	limit = pageLimit(limit)
	var all []store.KMSKey
	for _, k := range s.keysLocked() {
		if s.keyVisibleLocked(ctx, k.ID) && k.ID > after {
			k.MasterKeyRaw = nil
			all = append(all, k)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	if len(all) > limit {
		return all[:limit], true, nil
	}
	return all, false, nil
}

func (s *Store) ListAliasesPage(ctx context.Context, q store.AliasPageQuery) ([]store.KMSAlias, bool, error) {
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	limit := pageLimit(q.Limit)
	var out []store.KMSAlias
	for _, a := range s.aliasesLocked(ctx) {
		if a.AliasName <= q.After || (q.TargetKeyID != "" && a.TargetKeyID != q.TargetKeyID) {
			continue
		}
		out = append(out, a)
	}
	if len(out) > limit {
		return out[:limit], true, nil
	}
	return out, false, nil
}

func (s *Store) ListSecretsPage(ctx context.Context, q store.SecretPageQuery) ([]store.SecretMetadataRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := pageLimit(q.Limit)
	account := s.accountForContext(ctx)
	var out []store.SecretMetadataRecord
	for _, secret := range s.secrets {
		m := secret.metadata
		if secret.account != account {
			continue
		}
		if q.After != "" && ((!q.Descending && m.Name <= q.After) || (q.Descending && m.Name >= q.After)) {
			continue
		}
		if m.DeletedDate != nil && !q.IncludeDeleted {
			continue
		}
		m.Tags = append([]store.SecretTag(nil), m.Tags...)
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		if q.Descending {
			return out[i].Name > out[j].Name
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > limit {
		return out[:limit], true, nil
	}
	return out, false, nil
}

func (s *Store) ListParametersPage(ctx context.Context, q store.ParameterPageQuery) ([]store.ParameterRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := pageLimit(q.Limit)
	prefix := store.ParameterPathPrefix(q.Path)
	account := s.accountForContext(ctx)
	var out []store.ParameterRecord
	// Map keys combine account and name; page and match on the name itself.
	for _, p := range s.params {
		name := p.rec.Name
		if p.account == account && name > q.After && store.ParameterInPath(name, prefix, q.Recursive) {
			out = append(out, p.rec)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if len(out) > limit {
		return out[:limit], true, nil
	}
	return out, false, nil
}
