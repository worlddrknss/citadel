// Package memory is the in-memory store.Store backend. It holds a single
// legacy KMS key (and any keys/aliases supplied at construction) and keeps
// secrets, parameters, users and audit records in process memory. Features
// that need durable state (PKI, ACME, STS federation) are unsupported.
package memory

import (
	"context"
	"sync"

	"github.com/worlddrknss/citadel/internal/arn"
	"github.com/worlddrknss/citadel/internal/store"
)

// Store is the in-memory backend. The exported fields configure it and must
// be set before first use; the zero value is usable.
type Store struct {
	mu           sync.Mutex
	DefaultKey   store.KMSKey
	Keys         []store.KMSKey
	Aliases      []store.KMSAlias
	grants       []store.KMSGrant
	policies     map[string]string
	secrets      map[string]*inMemorySecret
	audit        []store.AuditRecord
	auditSeq     int64
	AuditHMACKey []byte
	auditAux     *memAuditState
	uiUsers      map[string]store.UIUser
	uiAccounts   map[string]store.UIAccountInfo
	members      map[string]map[string]string // username -> accountID -> role
	sessions     map[string]store.ConsoleSession
	orgSettings  store.OrgSettings
	ssoProviders []store.SSOProvider
	Region       string
	AccountID    string
	hier         map[string]*memProject
	params       map[string]*memParameter
	appr         memApprovals
}

var _ store.Store = (*Store)(nil)

// DeploymentIdentity returns the region and account ID embedded in resource ARNs.
func (s *Store) DeploymentIdentity() (string, string) {
	return arn.EffectiveRegion(s.Region), arn.EffectiveAccountID(s.AccountID)
}

func (s *Store) keyARN(id string) string {
	r, a := s.DeploymentIdentity()
	return arn.Build("kms", r, a, "key/"+id)
}

func (s *Store) secretARNFor(name string) string {
	r, a := s.DeploymentIdentity()
	return arn.Build("secretsmanager", r, a, "secret:"+name)
}

// accountForContext returns the caller's account ID when present, otherwise the
// deployment's global account ID. The in-memory store mirrors the postgres store
// behaviour so per-account isolation is identical across both backends.
func (s *Store) accountForContext(ctx context.Context) string {
	if acct, ok := store.CallerAccountFromContext(ctx); ok {
		return acct
	}
	_, a := s.DeploymentIdentity()
	return a
}

// secretARNForCtx builds a Secrets Manager ARN for the in-memory store using
// the caller's account when available, falling back to the deployment account.
func (s *Store) SecretARNForCtx(ctx context.Context, name string) string {
	r, _ := s.DeploymentIdentity()
	return arn.Build("secretsmanager", r, s.accountForContext(ctx), "secret:"+name)
}
