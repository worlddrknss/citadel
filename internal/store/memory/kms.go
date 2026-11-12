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

// Keys and aliases supplied through the exported DefaultKey/Keys/Aliases
// fields are visible to every account (they model a deployment's bootstrap
// key). Keys and aliases created at run time belong to the creating caller's
// account, as in the Postgres store.

// memAlias is a run-time alias owned by one account.
type memAlias struct {
	account string
	alias   store.KMSAlias
}

// keyVisibleLocked reports whether the caller's account may see key id.
func (s *Store) keyVisibleLocked(ctx context.Context, id string) bool {
	owner, ok := s.keyAccounts[id]
	return !ok || owner == s.accountForContext(ctx)
}

// keysLocked returns the key list, seeding it from DefaultKey on first use.
func (s *Store) keysLocked() []store.KMSKey {
	if len(s.Keys) == 0 && strings.TrimSpace(s.DefaultKey.ID) != "" {
		s.Keys = []store.KMSKey{s.DefaultKey}
	}
	return s.Keys
}

// aliasTargetLocked resolves an alias visible to the caller's account.
func (s *Store) aliasTargetLocked(ctx context.Context, name string) (string, bool) {
	account := s.accountForContext(ctx)
	for _, a := range s.aliases {
		if a.account == account && a.alias.AliasName == name {
			return a.alias.TargetKeyID, true
		}
	}
	for _, a := range s.Aliases {
		if a.AliasName == name {
			return a.TargetKeyID, true
		}
	}
	return "", false
}

func (s *Store) resolveLocked(ctx context.Context, keyID string) (store.KMSKey, error) {
	if strings.HasPrefix(keyID, "alias/") {
		target, ok := s.aliasTargetLocked(ctx, keyID)
		if !ok {
			return store.KMSKey{}, sql.ErrNoRows
		}
		keyID = target
	}
	for _, key := range s.keysLocked() {
		if (keyID == "" || keyID == key.ID) && s.keyVisibleLocked(ctx, key.ID) {
			return s.decorateKey(key), nil
		}
	}
	return store.KMSKey{}, sql.ErrNoRows
}

func (s *Store) ResolveByID(ctx context.Context, keyID string) (store.KMSKey, error) {
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	return s.resolveLocked(ctx, keyID)
}

func (s *Store) ResolveDefault(ctx context.Context) (store.KMSKey, error) {
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	keys := s.keysLocked()
	if len(keys) == 0 {
		return store.KMSKey{}, sql.ErrNoRows
	}
	return s.decorateKey(keys[0]), nil
}

func (s *Store) EnsureBootstrap(_ context.Context, _ store.KMSKey) error {
	return nil
}

func (s *Store) EnsureAccountDefaultKey(_ context.Context, _ string) (store.KMSKey, error) {
	return store.KMSKey{}, store.ErrUnsupported
}

// CreateKey generates a key owned by the caller's account.
func (s *Store) CreateKey(ctx context.Context, description, keyUsage, keySpec string) (store.KMSKey, error) {
	raw, pub, usage, spec, err := store.GenerateKeyMaterial(keyUsage, keySpec)
	if err != nil {
		return store.KMSKey{}, err
	}
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	id := cryptoutil.RandomHex(16)
	id = id[0:8] + "-" + id[8:12] + "-" + id[12:16] + "-" + id[16:20] + "-" + id[20:32]
	r, _ := s.DeploymentIdentity()
	account := s.accountForContext(ctx)
	key := store.KMSKey{
		ID:           id,
		ARN:          "arn:aws:kms:" + r + ":" + account + ":key/" + id,
		MasterKeyRaw: raw,
		PublicKeyRaw: pub,
		Description:  description,
		CreatedAt:    time.Now().UTC(),
		Enabled:      true,
		KeyUsage:     usage,
		KeySpec:      spec,
	}
	s.keysLocked()
	s.Keys = append(s.Keys, key)
	if s.keyAccounts == nil {
		s.keyAccounts = map[string]string{}
	}
	s.keyAccounts[id] = account
	return key, nil
}

func (s *Store) ImportSigningKey(_ context.Context, _ string, _, _ []byte, _ string) (store.KMSKey, error) {
	return store.KMSKey{}, store.ErrUnsupported
}

func (s *Store) ListKeys(ctx context.Context) ([]store.KMSKey, error) {
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	var out []store.KMSKey
	for _, key := range s.keysLocked() {
		if s.keyVisibleLocked(ctx, key.ID) {
			out = append(out, s.decorateKey(key))
		}
	}
	return out, nil
}

func policyMapKey(account, keyID, policyName string) string {
	return account + "\x00" + keyID + "\x00" + policyName
}

func (s *Store) GetKeyPolicy(ctx context.Context, keyID, policyName string) (string, error) {
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	key, err := s.resolveLocked(ctx, keyID)
	if err != nil {
		return "", err
	}
	if policyName == "" {
		policyName = "default"
	}
	if doc, ok := s.policies[policyMapKey(s.accountForContext(ctx), key.ID, policyName)]; ok {
		return doc, nil
	}
	return store.DefaultKeyPolicy(key), nil
}

func (s *Store) PutKeyPolicy(ctx context.Context, keyID, policyName, policyDocument string) error {
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	key, err := s.resolveLocked(ctx, keyID)
	if err != nil {
		return err
	}
	if policyName == "" {
		policyName = "default"
	}
	if s.policies == nil {
		s.policies = map[string]string{}
	}
	s.policies[policyMapKey(s.accountForContext(ctx), key.ID, policyName)] = policyDocument
	return nil
}

func (s *Store) CreateAlias(ctx context.Context, aliasName, keyID string) error {
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	if aliasName == store.ManagedDefaultAlias {
		return store.ErrImmutableManagedKey
	}
	if _, ok := s.aliasTargetLocked(ctx, aliasName); ok {
		return store.ErrAliasExists
	}
	if _, err := s.resolveLocked(ctx, keyID); err != nil {
		return err
	}
	s.aliases = append(s.aliases, memAlias{account: s.accountForContext(ctx), alias: store.KMSAlias{AliasName: aliasName, TargetKeyID: keyID}})
	return nil
}

func (s *Store) UpdateAlias(ctx context.Context, aliasName, keyID string) error {
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	if aliasName == store.ManagedDefaultAlias {
		return store.ErrImmutableManagedKey
	}
	if _, err := s.resolveLocked(ctx, keyID); err != nil {
		return err
	}
	account := s.accountForContext(ctx)
	for i := range s.aliases {
		if s.aliases[i].account == account && s.aliases[i].alias.AliasName == aliasName {
			s.aliases[i].alias.TargetKeyID = keyID
			return nil
		}
	}
	// Configured (deployment-wide) aliases are read-only.
	return sql.ErrNoRows
}

func (s *Store) DeleteAlias(ctx context.Context, aliasName string) error {
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	if aliasName == store.ManagedDefaultAlias {
		return store.ErrImmutableManagedKey
	}
	account := s.accountForContext(ctx)
	for i := range s.aliases {
		if s.aliases[i].account == account && s.aliases[i].alias.AliasName == aliasName {
			s.aliases = append(s.aliases[:i], s.aliases[i+1:]...)
			return nil
		}
	}
	return sql.ErrNoRows
}

// aliasesLocked returns the aliases visible to the caller, sorted by name.
func (s *Store) aliasesLocked(ctx context.Context) []store.KMSAlias {
	account := s.accountForContext(ctx)
	out := make([]store.KMSAlias, 0, len(s.Aliases)+len(s.aliases))
	out = append(out, s.Aliases...)
	for _, a := range s.aliases {
		if a.account == account {
			out = append(out, a.alias)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AliasName < out[j].AliasName })
	return out
}

func (s *Store) ListAliases(ctx context.Context) ([]store.KMSAlias, error) {
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	out := s.aliasesLocked(ctx)
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// updateKeyLocked applies fn to the visible key with the given ID.
func (s *Store) updateKeyLocked(ctx context.Context, keyID string, fn func(*store.KMSKey) error) error {
	keys := s.keysLocked()
	for i := range keys {
		if keys[i].ID == keyID && s.keyVisibleLocked(ctx, keyID) {
			if err := fn(&keys[i]); err != nil {
				return err
			}
			if keys[i].ID == s.DefaultKey.ID {
				s.DefaultKey = keys[i]
			}
			return nil
		}
	}
	return sql.ErrNoRows
}

func (s *Store) SetKeyEnabled(ctx context.Context, keyID string, enabled bool) error {
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	return s.updateKeyLocked(ctx, keyID, func(k *store.KMSKey) error {
		if !enabled && k.Managed {
			return store.ErrImmutableManagedKey
		}
		k.Enabled = enabled
		return nil
	})
}

func (s *Store) ScheduleKeyDeletion(ctx context.Context, keyID string, windowDays int) (time.Time, error) {
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	deletionDate := time.Now().UTC().Add(time.Duration(windowDays) * 24 * time.Hour)
	err := s.updateKeyLocked(ctx, keyID, func(k *store.KMSKey) error {
		if k.Managed {
			return store.ErrImmutableManagedKey
		}
		d := deletionDate
		k.DeletionDate = &d
		return nil
	})
	if err != nil {
		return time.Time{}, err
	}
	return deletionDate, nil
}

func (s *Store) CancelKeyDeletion(ctx context.Context, keyID string) error {
	s.kmsMu.Lock()
	defer s.kmsMu.Unlock()
	return s.updateKeyLocked(ctx, keyID, func(k *store.KMSKey) error {
		k.DeletionDate = nil
		return nil
	})
}

func (s *Store) ForceDeleteKey(_ context.Context, _ string) error {
	return store.ErrUnsupported
}
