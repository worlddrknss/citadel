package memory

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// Built-in secret rotation (store.SecretRotationStore). The rotation row and
// history hang off the in-memory secret, so renames and deletes carry them.

func copyRotation(r *store.SecretRotation) store.SecretRotation {
	out := *r
	out.SigningKeySealed = append([]byte(nil), r.SigningKeySealed...)
	if len(out.SigningKeySealed) == 0 {
		out.SigningKeySealed = nil
	}
	return out
}

func (s *Store) GetSecretRotation(ctx context.Context, secretID string) (store.SecretRotation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, secretID)
	if err != nil {
		return store.SecretRotation{}, err
	}
	if secret.rotation == nil {
		return store.SecretRotation{}, store.ErrRotationNotConfigured
	}
	return copyRotation(secret.rotation), nil
}

func (s *Store) ConfigureSecretRotation(ctx context.Context, cfg store.SecretRotationConfig) (store.SecretMetadataRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, cfg.SecretID)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	m := &secret.metadata
	m.RotationEnabled = true
	m.RotationLambdaARN = strings.TrimSpace(cfg.LambdaARN)
	m.RotationDays = cfg.AfterDays
	m.NextRotationDate = cfg.NextRotationDate
	r := secret.rotation
	if r == nil {
		r = &store.SecretRotation{SecretName: m.Name}
		secret.rotation = r
	}
	r.RotatorType = cfg.RotatorType
	r.ConfigSecret = cfg.ConfigSecret
	r.Config = cfg.Config
	r.ScheduleExpression = cfg.ScheduleExpression
	r.Duration = cfg.Duration
	switch {
	case cfg.SigningKeySealed != nil:
		r.SigningKeySealed = append([]byte(nil), cfg.SigningKeySealed...)
	case cfg.ClearSigningKey:
		r.SigningKeySealed = nil
	}
	r.Attempts = 0
	r.NextAttemptAt = nil
	if r.Status == store.RotationStatusRetrying || r.Status == store.RotationStatusFailed {
		r.Status = store.RotationStatusNever
		r.LastError = ""
	}
	r.UpdatedAt = time.Now().UTC()
	r.UpdatedBy = store.ActorFromContext(ctx)
	return secret.snapshot(), nil
}

func (s *Store) PutPendingSecretVersion(ctx context.Context, secretID, token, secretString, secretBinary string) (store.SecretValueRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, secretID)
	if err != nil {
		return store.SecretValueRecord{}, err
	}
	if secret.metadata.DeletedDate != nil {
		return store.SecretValueRecord{}, store.ErrSecretPendingDeletion
	}
	if token == "" {
		token = cryptoutil.RandomHex(16)
	}
	if id, ok := secret.byToken[token]; ok {
		v := secret.versions[id]
		return store.BuildSecretValueRecord(ctx, s.ResolveByID, secret.metadata, store.SecretVersionRow{VersionID: v.VersionID, EncryptedPayloadB64: v.EncryptedPayloadB64, IsBinary: v.IsBinary, CreatedAt: v.CreatedAt})
	}
	if _, ok := secret.versions[token]; ok {
		return store.SecretValueRecord{}, store.ErrSecretExists
	}
	// Seal under the secret's key, so the pending version decrypts with
	// every other version.
	_, payload, isBinary, err := store.BuildSecretCiphertext(ctx, s.ResolveByID, s.ResolveDefault, secret.metadata.KMSKeyID, secretString, secretBinary)
	if err != nil {
		return store.SecretValueRecord{}, err
	}
	now := time.Now().UTC()
	actor := store.ActorFromContext(ctx)
	secret.versions[token] = inMemorySecretVersion{VersionID: token, ClientRequestToken: token, EncryptedPayloadB64: payload, IsBinary: isBinary, CreatedAt: now, CreatedBy: actor}
	secret.byToken[token] = token
	store.AssignSecretStage(&secret.metadata, store.PendingVersionStage, token)
	return store.BuildSecretValueRecord(ctx, s.ResolveByID, secret.metadata, store.SecretVersionRow{VersionID: token, EncryptedPayloadB64: payload, IsBinary: isBinary, CreatedAt: now})
}

func (s *Store) FinishSecretRotation(ctx context.Context, secretID, token string) (store.SecretMetadataRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, secretID)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	v, ok := secret.versions[token]
	if !ok {
		return store.SecretMetadataRecord{}, store.ErrInvalidSecretVersion
	}
	if store.FinishRotationStages(&secret.metadata, token) {
		secret.metadata.LastChangedDate = time.Now().UTC()
		secret.metadata.UpdatedBy = v.CreatedBy
	}
	return secret.snapshot(), nil
}

func (s *Store) ClaimSecretRotation(ctx context.Context, secretID, owner string, lease time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, secretID)
	if err != nil {
		return false, err
	}
	r := secret.rotation
	if r == nil {
		return false, store.ErrRotationNotConfigured
	}
	now := time.Now().UTC()
	if r.LeaseUntil != nil && r.LeaseUntil.After(now) {
		return false, nil
	}
	until := now.Add(lease)
	r.LeaseOwner, r.LeaseUntil = owner, &until
	return true, nil
}

func (s *Store) SaveSecretRotationState(ctx context.Context, secretID, owner string, upd store.SecretRotationStateUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, secretID)
	if err != nil {
		return err
	}
	r := secret.rotation
	if r == nil {
		return store.ErrRotationNotConfigured
	}
	if r.LeaseOwner != owner {
		return store.ErrRotationLeaseLost
	}
	r.Status, r.LastStep, r.LastError, r.Attempts = upd.Status, upd.LastStep, upd.LastError, upd.Attempts
	at := upd.LastAttemptAt
	r.LastAttemptAt = &at
	r.NextAttemptAt = cloneTime(upd.NextAttemptAt)
	if upd.LastRotatedAt != nil {
		r.LastRotatedAt = cloneTime(upd.LastRotatedAt)
	}
	if upd.NextRotationDate != nil {
		secret.metadata.NextRotationDate = cloneTime(upd.NextRotationDate)
	}
	if !upd.KeepLease {
		r.LeaseOwner, r.LeaseUntil = "", nil
	}
	return nil
}

func cloneTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}

func (s *Store) ListDueSecretRotations(ctx context.Context, now time.Time, limit int) ([]store.DueSecretRotation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []store.DueSecretRotation
	for _, secret := range s.secrets {
		if store.RotationIsDue(secret.metadata, secret.rotation, now) {
			out = append(out, store.DueSecretRotation{AccountID: secret.account, SecretName: secret.metadata.Name})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].AccountID != out[j].AccountID {
			return out[i].AccountID < out[j].AccountID
		}
		return out[i].SecretName < out[j].SecretName
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) AppendSecretRotationHistory(ctx context.Context, secretID string, e store.SecretRotationEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, secretID)
	if err != nil {
		return err
	}
	s.rotSeq++
	e.ID = s.rotSeq
	secret.rotHistory = append(secret.rotHistory, e)
	if n := len(secret.rotHistory); n > store.MaxRotationHistory {
		secret.rotHistory = append([]store.SecretRotationEvent(nil), secret.rotHistory[n-store.MaxRotationHistory:]...)
	}
	return nil
}

func (s *Store) ListSecretRotationHistory(ctx context.Context, secretID string, limit int) ([]store.SecretRotationEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, secretID)
	if err != nil {
		return nil, err
	}
	out := make([]store.SecretRotationEvent, 0, len(secret.rotHistory))
	for i := len(secret.rotHistory) - 1; i >= 0; i-- {
		out = append(out, secret.rotHistory[i])
		if limit > 0 && len(out) == limit {
			break
		}
	}
	return out, nil
}

func (s *Store) ListSecretRotationSummaries(ctx context.Context) (map[string]store.SecretRotationSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	account := s.accountForContext(ctx)
	out := map[string]store.SecretRotationSummary{}
	for _, secret := range s.secrets {
		if secret.account == account && secret.rotation != nil {
			out[secret.metadata.Name] = store.SecretRotationSummary{RotatorType: secret.rotation.RotatorType, Status: secret.rotation.Status}
		}
	}
	return out, nil
}
