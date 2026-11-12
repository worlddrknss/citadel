package memory

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// memKMS holds the in-memory KMS lifecycle state layered over the keys:
// rotated material, rotation schedules, tags, grant ownership and destroyed
// keys. It is guarded by kmsMu (not mu: secret and parameter methods resolve
// keys while holding mu).
type memKMS struct {
	materials    map[string][]store.KeyMaterial
	current      map[string]string
	rotation     map[string]memRotation
	tags         map[string]map[string]string // account\x00keyID -> key -> value
	grantAccount map[string]string            // grant ID -> account
}

type memRotation struct {
	enabled bool
	period  int
	next    *time.Time
}

// kmsState returns the lifecycle state, creating it. Callers hold kmsMu.
func (s *Store) kmsState() *memKMS {
	if s.kms == nil {
		s.kms = &memKMS{
			materials:    map[string][]store.KeyMaterial{},
			current:      map[string]string{},
			rotation:     map[string]memRotation{},
			tags:         map[string]map[string]string{},
			grantAccount: map[string]string{},
		}
	}
	return s.kms
}

// decorateKey applies lifecycle state to a key. Callers hold kmsMu.
func (s *Store) decorateKey(k store.KMSKey) store.KMSKey {
	st := s.kmsState()
	if mats := st.materials[k.ID]; len(mats) > 0 {
		k.Materials = append([]store.KeyMaterial(nil), mats...)
	}
	k.CurrentMaterialID = st.current[k.ID]
	if r, ok := st.rotation[k.ID]; ok {
		k.RotationEnabled = r.enabled
		k.RotationPeriodDays = r.period
		if r.next != nil {
			t := *r.next
			k.NextRotationAt = &t
		}
	}
	if k.Origin == "" {
		k.Origin = store.OriginAWSKMS
	}
	return k
}

func (s *Store) SetKeyRotation(ctx context.Context, keyID string, enabled bool, periodDays int) (store.KMSKey, error) {
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	key, err := s.resolveLocked(ctx, keyID)
	if err != nil {
		return store.KMSKey{}, err
	}
	if !key.IsSymmetric() {
		return store.KMSKey{}, store.ErrRotationUnsupported
	}
	if periodDays == 0 {
		periodDays = key.RotationPeriodDays
		if periodDays == 0 {
			periodDays = store.DefaultRotationPeriodDays
		}
	}
	if periodDays < store.MinRotationPeriodDays || periodDays > store.MaxRotationPeriodDays {
		return store.KMSKey{}, store.ErrInvalidRotationPeriod
	}
	now := time.Now().UTC()
	r := memRotation{enabled: enabled, period: periodDays}
	if enabled {
		t := now.Add(time.Duration(periodDays) * 24 * time.Hour)
		if key.RotationEnabled && key.NextRotationAt != nil && key.RotationPeriodDays > 0 {
			t = key.NextRotationAt.Add(time.Duration(periodDays-key.RotationPeriodDays) * 24 * time.Hour)
			if t.Before(now) {
				t = now
			}
		}
		r.next = &t
	}
	s.kmsState().rotation[key.ID] = r
	return s.resolveLocked(ctx, key.ID)
}

func (s *Store) RotateKeyMaterial(ctx context.Context, keyID, kind string, now time.Time) (store.KeyRotation, error) {
	if kind != store.RotationKindAutomatic && kind != store.RotationKindOnDemand {
		return store.KeyRotation{}, errors.New("invalid rotation kind")
	}
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	key, err := s.resolveLocked(ctx, keyID)
	if err != nil {
		return store.KeyRotation{}, err
	}
	if !key.IsSymmetric() {
		return store.KeyRotation{}, store.ErrRotationUnsupported
	}
	if !key.Enabled || key.DeletionDate != nil {
		return store.KeyRotation{}, store.ErrKeyNotUsable
	}
	st := s.kmsState()
	r := st.rotation[key.ID]
	switch kind {
	case store.RotationKindAutomatic:
		if !r.enabled || r.next == nil || r.next.After(now) {
			return store.KeyRotation{}, store.ErrRotationNotDue
		}
	case store.RotationKindOnDemand:
		n := 0
		for _, m := range st.materials[key.ID] {
			if m.Kind == store.RotationKindOnDemand {
				n++
			}
		}
		if n >= store.MaxOnDemandRotations {
			return store.KeyRotation{}, store.ErrRotationLimit
		}
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return store.KeyRotation{}, err
	}
	rotatedAt := now.UTC()
	m := store.KeyMaterial{ID: cryptoutil.RandomHex(16), Raw: raw, Kind: kind, CreatedAt: rotatedAt}
	st.materials[key.ID] = append(st.materials[key.ID], m)
	st.current[key.ID] = m.ID
	if kind == store.RotationKindAutomatic {
		period := r.period
		if period <= 0 {
			period = store.DefaultRotationPeriodDays
		}
		next := rotatedAt.Add(time.Duration(period) * 24 * time.Hour)
		r.next = &next
		st.rotation[key.ID] = r
	}
	return store.KeyRotation{KeyID: key.ID, MaterialID: m.ID, Kind: kind, RotatedAt: rotatedAt}, nil
}

func (s *Store) ListKeyRotations(ctx context.Context, keyID string) ([]store.KeyRotation, error) {
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	key, err := s.resolveLocked(ctx, keyID)
	if err != nil {
		return nil, err
	}
	mats := s.kmsState().materials[key.ID]
	out := make([]store.KeyRotation, 0, len(mats))
	for i := len(mats) - 1; i >= 0; i-- {
		out = append(out, store.KeyRotation{KeyID: key.ID, MaterialID: mats[i].ID, Kind: mats[i].Kind, RotatedAt: mats[i].CreatedAt})
	}
	return out, nil
}

// keyOwnerLocked is the account a key belongs to (the deployment account
// for bootstrap keys).
func (s *Store) keyOwnerLocked(id string) string {
	if owner, ok := s.keyAccounts[id]; ok {
		return owner
	}
	_, acct := s.DeploymentIdentity()
	return acct
}

func (s *Store) ListKeysDueForRotation(_ context.Context, now time.Time) ([]store.KeyRef, error) {
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	out := make([]store.KeyRef, 0)
	for _, k := range s.keysLocked() {
		r := s.kmsState().rotation[k.ID]
		if r.enabled && r.next != nil && !r.next.After(now) && k.Enabled && k.DeletionDate == nil {
			out = append(out, store.KeyRef{KeyID: k.ID, AccountID: s.keyOwnerLocked(k.ID)})
		}
	}
	return out, nil
}

func (s *Store) ListKeysPendingDeletion(_ context.Context, now time.Time) ([]store.KeyRef, error) {
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	out := make([]store.KeyRef, 0)
	for _, k := range s.keysLocked() {
		if k.DeletionDate != nil && !k.DeletionDate.After(now) && !k.Managed {
			out = append(out, store.KeyRef{KeyID: k.ID, AccountID: s.keyOwnerLocked(k.ID)})
		}
	}
	return out, nil
}

// DestroyKey removes a key and everything attached to it. The configured
// bootstrap key (DefaultKey) is treated as managed and refused.
func (s *Store) DestroyKey(ctx context.Context, keyID string) error {
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	key, err := s.resolveLocked(ctx, keyID)
	if err != nil {
		return err
	}
	if key.Managed || key.ID == s.DefaultKey.ID {
		return store.ErrImmutableManagedKey
	}
	keys := s.keysLocked()
	for i := range keys {
		if keys[i].ID == key.ID {
			// Wipe the material before dropping the reference.
			for j := range keys[i].MasterKeyRaw {
				keys[i].MasterKeyRaw[j] = 0
			}
			s.Keys = append(keys[:i:i], keys[i+1:]...)
			break
		}
	}
	st := s.kmsState()
	for _, m := range st.materials[key.ID] {
		for j := range m.Raw {
			m.Raw[j] = 0
		}
	}
	delete(st.materials, key.ID)
	delete(st.current, key.ID)
	delete(st.rotation, key.ID)
	for k := range st.tags {
		if strings.HasSuffix(k, "\x00"+key.ID) {
			delete(st.tags, k)
		}
	}
	kept := s.aliases[:0]
	for _, a := range s.aliases {
		if a.alias.TargetKeyID != key.ID {
			kept = append(kept, a)
		}
	}
	s.aliases = kept
	grants := s.grants[:0]
	for _, g := range s.grants {
		if g.KeyID != key.ID {
			grants = append(grants, g)
		} else {
			delete(st.grantAccount, g.GrantID)
		}
	}
	s.grants = grants
	for k := range s.policies {
		if strings.Contains(k, "\x00"+key.ID+"\x00") {
			delete(s.policies, k)
		}
	}
	// Keep the ID reserved (and invisible) so it is never reissued.
	if s.keyAccounts == nil {
		s.keyAccounts = map[string]string{}
	}
	s.keyAccounts[key.ID] = "\x00destroyed"
	return nil
}

func memTagKey(account, keyID string) string { return account + "\x00" + keyID }

func (s *Store) TagKey(ctx context.Context, keyID string, tags []store.KMSTag) error {
	tags, err := store.NormalizeTags(tags)
	if err != nil {
		return err
	}
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	key, err := s.resolveLocked(ctx, keyID)
	if err != nil {
		return err
	}
	st := s.kmsState()
	k := memTagKey(s.accountForContext(ctx), key.ID)
	merged := map[string]string{}
	for tk, tv := range st.tags[k] {
		merged[tk] = tv
	}
	for _, t := range tags {
		merged[t.Key] = t.Value
	}
	if len(merged) > store.MaxKeyTags {
		return fmt.Errorf("%w: at most 50 tags per key", store.ErrInvalidTags)
	}
	st.tags[k] = merged
	return nil
}

func (s *Store) UntagKey(ctx context.Context, keyID string, tagKeys []string) error {
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	key, err := s.resolveLocked(ctx, keyID)
	if err != nil {
		return err
	}
	m := s.kmsState().tags[memTagKey(s.accountForContext(ctx), key.ID)]
	for _, tk := range tagKeys {
		delete(m, tk)
	}
	return nil
}

func (s *Store) ListKeyTags(ctx context.Context, keyID string) ([]store.KMSTag, error) {
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	key, err := s.resolveLocked(ctx, keyID)
	if err != nil {
		return nil, err
	}
	m := s.kmsState().tags[memTagKey(s.accountForContext(ctx), key.ID)]
	out := make([]store.KMSTag, 0, len(m))
	for k, v := range m {
		out = append(out, store.KMSTag{Key: k, Value: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func (s *Store) CountKeyUsage(ctx context.Context, key store.KMSKey) (store.KeyUsageCounts, error) {
	refs := map[string]bool{key.ID: true}
	if key.ARN != "" {
		refs[key.ARN] = true
	}
	s.kmsMu.Lock()
	for _, a := range s.aliasesLocked(ctx) {
		if a.TargetKeyID == key.ID {
			refs[a.AliasName] = true
		}
	}
	s.kmsMu.Unlock()
	acct := s.accountForContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	var out store.KeyUsageCounts
	for _, sec := range s.secrets {
		if sec.account == acct && sec.metadata.DeletedDate == nil && refs[strings.TrimSpace(sec.metadata.KMSKeyID)] {
			out.Secrets++
		}
	}
	for _, p := range s.params {
		if p.rec.Type == "SecureString" && refs[strings.TrimSpace(p.rec.KMSKeyID)] && p.account == acct {
			out.Parameters++
		}
	}
	return out, nil
}

func (s *Store) FindGrant(ctx context.Context, grantID, grantToken string) (store.KMSGrant, error) {
	if grantID == "" && grantToken == "" {
		return store.KMSGrant{}, sql.ErrNoRows
	}
	acct := s.accountForContext(ctx)
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	for _, g := range s.grants {
		if s.kmsState().grantAccount[g.GrantID] != acct {
			continue
		}
		if (grantID != "" && g.GrantID == grantID) || (grantToken != "" && g.GrantToken == grantToken) {
			g.Operations = append([]string(nil), g.Operations...)
			return g, nil
		}
	}
	return store.KMSGrant{}, sql.ErrNoRows
}

// RewrapAll: the in-memory store keeps nothing wrapped.
func (s *Store) RewrapAll(context.Context) (store.RewrapReport, error) {
	return store.RewrapReport{}, nil
}

func (s *Store) CreateGrant(ctx context.Context, req store.CreateGrantRequest) (store.KMSGrant, error) {
	acct := s.accountForContext(ctx)
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	key, err := s.resolveLocked(ctx, req.KeyID)
	if err != nil {
		return store.KMSGrant{}, err
	}
	grant := store.KMSGrant{
		GrantID:           "grant-" + cryptoutil.RandomHex(12),
		GrantToken:        cryptoutil.RandomHex(16),
		KeyID:             key.ID,
		GranteePrincipal:  strings.TrimSpace(req.GranteePrincipal),
		RetiringPrincipal: strings.TrimSpace(req.RetiringPrincipal),
		Operations:        append([]string(nil), req.Operations...),
		Name:              strings.TrimSpace(req.Name),
		CreatedAt:         time.Now().UTC(),
	}
	s.grants = append(s.grants, grant)
	s.kmsState().grantAccount[grant.GrantID] = acct
	return grant, nil
}

func (s *Store) ListGrants(ctx context.Context, keyID string) ([]store.KMSGrant, error) {
	acct := s.accountForContext(ctx)
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	out := make([]store.KMSGrant, 0)
	for _, grant := range s.grants {
		if grant.KeyID == keyID && s.kmsState().grantAccount[grant.GrantID] == acct {
			grantCopy := grant
			grantCopy.Operations = append([]string(nil), grant.Operations...)
			out = append(out, grantCopy)
		}
	}
	return out, nil
}

func (s *Store) RevokeGrant(ctx context.Context, keyID, grantID string) error {
	acct := s.accountForContext(ctx)
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	for i, grant := range s.grants {
		if grant.KeyID == keyID && grant.GrantID == grantID && s.kmsState().grantAccount[grant.GrantID] == acct {
			s.grants = append(s.grants[:i], s.grants[i+1:]...)
			delete(s.kmsState().grantAccount, grantID)
			return nil
		}
	}
	return sql.ErrNoRows
}

func (s *Store) RetireGrant(ctx context.Context, grantID, grantToken string) error {
	acct := s.accountForContext(ctx)
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	for i, grant := range s.grants {
		if s.kmsState().grantAccount[grant.GrantID] != acct {
			continue
		}
		if (grantID != "" && grant.GrantID == grantID) || (grantToken != "" && grant.GrantToken == grantToken) {
			s.grants = append(s.grants[:i], s.grants[i+1:]...)
			delete(s.kmsState().grantAccount, grant.GrantID)
			return nil
		}
	}
	return sql.ErrNoRows
}
