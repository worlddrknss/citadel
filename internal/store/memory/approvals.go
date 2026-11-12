package memory

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// memApprovals holds approval policies, change requests and secrets settings,
// keyed by account. It has its own lock so it never nests under s.mu.
type memApprovals struct {
	mu       sync.Mutex
	policies map[string]store.ApprovalPolicy       // account\x00project\x00env
	requests map[string]*store.ChangeRequestRecord // account\x00id
	settings map[string]store.SecretSettings       // account
}

// approvals returns the store's approval state, initialising it on first use
// so the Store zero value stays usable.
func (s *Store) approvals() *memApprovals {
	a := &s.appr
	a.mu.Lock()
	if a.policies == nil {
		a.policies = map[string]store.ApprovalPolicy{}
		a.requests = map[string]*store.ChangeRequestRecord{}
		a.settings = map[string]store.SecretSettings{}
	}
	a.mu.Unlock()
	return a
}

func cloneChangeRequest(cr *store.ChangeRequestRecord) store.ChangeRequestRecord {
	out := *cr
	out.Approvals = append([]store.ChangeRequestApproval{}, cr.Approvals...)
	if cr.DecidedAt != nil {
		t := *cr.DecidedAt
		out.DecidedAt = &t
	}
	return out
}

func (s *Store) ListApprovalPolicies(ctx context.Context) ([]store.ApprovalPolicy, error) {
	a := s.approvals()
	prefix := s.accountForContext(ctx) + "\x00"
	a.mu.Lock()
	defer a.mu.Unlock()
	out := []store.ApprovalPolicy{}
	for k, p := range a.policies {
		if strings.HasPrefix(k, prefix) {
			p.ApproverRoles = append([]string(nil), p.ApproverRoles...)
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Project != out[j].Project {
			return out[i].Project < out[j].Project
		}
		return out[i].Env < out[j].Env
	})
	return out, nil
}

func (s *Store) GetApprovalPolicy(ctx context.Context, project, env string) (store.ApprovalPolicy, bool, error) {
	a := s.approvals()
	a.mu.Lock()
	defer a.mu.Unlock()
	p, ok := a.policies[store.FmtHierarchyKey(s.accountForContext(ctx), project, env)]
	p.ApproverRoles = append([]string(nil), p.ApproverRoles...)
	return p, ok, nil
}

func (s *Store) PutApprovalPolicy(ctx context.Context, p store.ApprovalPolicy) error {
	a := s.approvals()
	key := store.FmtHierarchyKey(s.accountForContext(ctx), p.Project, p.Env)
	a.mu.Lock()
	defer a.mu.Unlock()
	if p.ApprovalsRequired <= 0 {
		delete(a.policies, key)
		return nil
	}
	p.ApproverRoles = append([]string(nil), p.ApproverRoles...)
	p.UpdatedAt = time.Now().UTC()
	a.policies[key] = p
	return nil
}

func (s *Store) CreateChangeRequest(ctx context.Context, cr store.ChangeRequestRecord) (store.ChangeRequestRecord, error) {
	if strings.TrimSpace(cr.ID) == "" {
		return store.ChangeRequestRecord{}, errors.New("change request id is required")
	}
	a := s.approvals()
	key := store.FmtHierarchyKey(s.accountForContext(ctx), cr.ID)
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.requests[key]; exists {
		return store.ChangeRequestRecord{}, errors.New("change request id already exists")
	}
	if cr.CreatedAt.IsZero() {
		cr.CreatedAt = time.Now().UTC()
	}
	cr.Status = store.ChangeRequestPending
	cr.Approvals = []store.ChangeRequestApproval{}
	cr.DecidedAt = nil
	stored := cr
	a.requests[key] = &stored
	return cloneChangeRequest(&stored), nil
}

func (s *Store) GetChangeRequest(ctx context.Context, id string) (store.ChangeRequestRecord, error) {
	a := s.approvals()
	a.mu.Lock()
	defer a.mu.Unlock()
	cr, ok := a.requests[store.FmtHierarchyKey(s.accountForContext(ctx), id)]
	if !ok {
		return store.ChangeRequestRecord{}, store.ErrChangeRequestNotFound
	}
	return cloneChangeRequest(cr), nil
}

func (s *Store) ListChangeRequests(ctx context.Context) ([]store.ChangeRequestRecord, error) {
	a := s.approvals()
	prefix := s.accountForContext(ctx) + "\x00"
	a.mu.Lock()
	defer a.mu.Unlock()
	out := []store.ChangeRequestRecord{}
	for k, cr := range a.requests {
		if strings.HasPrefix(k, prefix) {
			out = append(out, cloneChangeRequest(cr))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

func (s *Store) AddChangeRequestApproval(ctx context.Context, id string, ap store.ChangeRequestApproval) (store.ChangeRequestRecord, error) {
	a := s.approvals()
	a.mu.Lock()
	defer a.mu.Unlock()
	cr, ok := a.requests[store.FmtHierarchyKey(s.accountForContext(ctx), id)]
	if !ok {
		return store.ChangeRequestRecord{}, store.ErrChangeRequestNotFound
	}
	if cr.Status != store.ChangeRequestPending {
		return store.ChangeRequestRecord{}, store.ErrChangeRequestDecided
	}
	for _, existing := range cr.Approvals {
		if existing.Username == ap.Username {
			return store.ChangeRequestRecord{}, store.ErrAlreadyApproved
		}
	}
	if ap.DecidedAt.IsZero() {
		ap.DecidedAt = time.Now().UTC()
	}
	cr.Approvals = append(cr.Approvals, ap)
	return cloneChangeRequest(cr), nil
}

func (s *Store) TransitionChangeRequest(ctx context.Context, id, from, to, decidedBy, comment string) (store.ChangeRequestRecord, error) {
	a := s.approvals()
	a.mu.Lock()
	defer a.mu.Unlock()
	cr, ok := a.requests[store.FmtHierarchyKey(s.accountForContext(ctx), id)]
	if !ok {
		return store.ChangeRequestRecord{}, store.ErrChangeRequestNotFound
	}
	if cr.Status != from {
		return store.ChangeRequestRecord{}, store.ErrChangeRequestDecided
	}
	cr.Status = to
	if to == store.ChangeRequestPending {
		cr.DecidedBy, cr.DecisionComment, cr.DecidedAt = "", "", nil
	} else {
		now := time.Now().UTC()
		cr.DecidedBy, cr.DecisionComment, cr.DecidedAt = decidedBy, comment, &now
	}
	return cloneChangeRequest(cr), nil
}

func (s *Store) GetSecretSettings(ctx context.Context) (store.SecretSettings, error) {
	a := s.approvals()
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.settings[s.accountForContext(ctx)], nil
}

func (s *Store) PutSecretSettings(ctx context.Context, in store.SecretSettings) error {
	a := s.approvals()
	a.mu.Lock()
	defer a.mu.Unlock()
	in.UpdatedAt = time.Now().UTC()
	a.settings[s.accountForContext(ctx)] = in
	return nil
}

// RenameSecret implements store.SecretLifecycleStore.
func (s *Store) RenameSecret(ctx context.Context, oldName, newName string) (store.SecretMetadataRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, oldName)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	newName = strings.TrimSpace(newName)
	newKey := memSecretKey(secret.account, newName)
	if _, taken := s.secrets[newKey]; taken {
		return store.SecretMetadataRecord{}, store.ErrSecretExists
	}
	delete(s.secrets, memSecretKey(secret.account, secret.metadata.Name))
	secret.metadata.Name = newName
	secret.metadata.ARN = s.SecretARNForCtx(ctx, newName)
	secret.metadata.LastChangedDate = time.Now().UTC()
	s.secrets[newKey] = secret
	return secret.snapshot(), nil
}

// PurgeExpiredSecrets implements store.SecretLifecycleStore (all accounts).
func (s *Store) PurgeExpiredSecrets(ctx context.Context, now time.Time) ([]store.PurgedSecret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []store.PurgedSecret{}
	for key, secret := range s.secrets {
		d := secret.metadata.DeletedDate
		if d == nil || d.After(now) {
			continue
		}
		delete(s.secrets, key)
		out = append(out, store.PurgedSecret{AccountID: secret.account, Name: secret.metadata.Name, KMSKeyID: secret.metadata.KMSKeyID})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
