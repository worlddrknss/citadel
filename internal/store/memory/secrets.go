package memory

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

type inMemorySecret struct {
	account  string
	metadata store.SecretMetadataRecord
	versions map[string]inMemorySecretVersion
	byToken  map[string]string
}

// memSecretKey builds the composite map key used by the in-memory store so two
// different accounts can hold a secret of the same name without colliding.
func memSecretKey(account, name string) string {
	return account + "\x00" + name
}

type inMemorySecretVersion struct {
	VersionID           string
	ClientRequestToken  string
	EncryptedPayloadB64 string
	IsBinary            bool
	CreatedAt           time.Time
	CreatedBy           string
}

func (s *Store) CreateSecret(ctx context.Context, req store.CreateSecretRequest) (store.SecretMetadataRecord, store.SecretValueRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.secrets == nil {
		s.secrets = map[string]*inMemorySecret{}
	}
	account := s.accountForContext(ctx)
	name := strings.TrimSpace(req.Name)
	if _, ok := s.secrets[memSecretKey(account, name)]; ok {
		return store.SecretMetadataRecord{}, store.SecretValueRecord{}, store.ErrSecretExists
	}
	versionID := req.ClientRequestToken
	if versionID == "" {
		versionID = cryptoutil.RandomHex(16)
	}
	kmsKeyID, encryptedPayloadB64, isBinary, err := store.BuildSecretCiphertext(ctx, s.ResolveByID, s.ResolveDefault, req.KMSKeyID, req.SecretString, req.SecretBinary)
	if err != nil {
		return store.SecretMetadataRecord{}, store.SecretValueRecord{}, err
	}
	now := time.Now().UTC()
	meta := store.SecretMetadataRecord{
		ARN:               s.SecretARNForCtx(ctx, name),
		Name:              name,
		Description:       strings.TrimSpace(req.Description),
		KMSKeyID:          kmsKeyID,
		CurrentVersionID:  versionID,
		PreviousVersionID: "",
		VersionStages:     map[string][]string{versionID: {store.CurrentVersionStage}},
		CreatedAt:         now,
		LastChangedDate:   now,
		UpdatedBy:         store.ActorFromContext(ctx),
	}
	secret := &inMemorySecret{
		account:  account,
		metadata: meta,
		versions: map[string]inMemorySecretVersion{},
		byToken:  map[string]string{},
	}
	secret.versions[versionID] = inMemorySecretVersion{VersionID: versionID, ClientRequestToken: versionID, EncryptedPayloadB64: encryptedPayloadB64, IsBinary: isBinary, CreatedAt: now, CreatedBy: store.ActorFromContext(ctx)}
	secret.byToken[versionID] = versionID
	s.secrets[memSecretKey(account, name)] = secret
	meta.VersionCount = 1
	value, err := store.BuildSecretValueRecord(ctx, s.ResolveByID, meta, store.SecretVersionRow{VersionID: versionID, EncryptedPayloadB64: encryptedPayloadB64, IsBinary: isBinary, CreatedAt: now})
	if err != nil {
		return store.SecretMetadataRecord{}, store.SecretValueRecord{}, err
	}
	return meta, value, nil
}

func (s *Store) DescribeSecret(ctx context.Context, secretID string) (store.SecretMetadataRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, secretID)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	return secret.snapshot(), nil
}

// snapshot returns the metadata with derived fields filled in.
func (sec *inMemorySecret) snapshot() store.SecretMetadataRecord {
	m := sec.metadata
	m.VersionCount = len(sec.versions)
	m.Tags = append([]store.SecretTag(nil), sec.metadata.Tags...)
	return m
}

func (s *Store) GetSecretValue(ctx context.Context, secretID, versionID, versionStage string) (store.SecretValueRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getSecretValueLocked(ctx, secretID, versionID, versionStage)
}

// getSecretValueLocked implements GetSecretValue. The caller must hold s.mu.
func (s *Store) getSecretValueLocked(ctx context.Context, secretID, versionID, versionStage string) (store.SecretValueRecord, error) {
	secret, err := s.findSecret(ctx, secretID)
	if err != nil {
		return store.SecretValueRecord{}, err
	}
	if secret.metadata.DeletedDate != nil {
		return store.SecretValueRecord{}, store.ErrSecretPendingDeletion
	}
	resolvedVersionID, err := store.ResolveSecretVersionID(secret.metadata, versionID, versionStage)
	if err != nil {
		return store.SecretValueRecord{}, err
	}
	version, ok := secret.versions[resolvedVersionID]
	if !ok {
		return store.SecretValueRecord{}, sql.ErrNoRows
	}
	return store.BuildSecretValueRecord(ctx, s.ResolveByID, secret.metadata, store.SecretVersionRow{VersionID: version.VersionID, EncryptedPayloadB64: version.EncryptedPayloadB64, IsBinary: version.IsBinary, CreatedAt: version.CreatedAt})
}

func (s *Store) PutSecretValue(ctx context.Context, req store.PutSecretValueRequest) (store.SecretValueRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putSecretValueLocked(ctx, req)
}

// putSecretValueLocked implements PutSecretValue. The caller must hold s.mu.
func (s *Store) putSecretValueLocked(ctx context.Context, req store.PutSecretValueRequest) (store.SecretValueRecord, error) {
	secret, err := s.findSecret(ctx, req.SecretID)
	if err != nil {
		return store.SecretValueRecord{}, err
	}
	if secret.metadata.DeletedDate != nil {
		return store.SecretValueRecord{}, store.ErrSecretPendingDeletion
	}
	versionID := req.ClientRequestToken
	if versionID == "" {
		versionID = cryptoutil.RandomHex(16)
	}
	if existingVersionID, ok := secret.byToken[versionID]; ok {
		version := secret.versions[existingVersionID]
		return store.BuildSecretValueRecord(ctx, s.ResolveByID, secret.metadata, store.SecretVersionRow{VersionID: version.VersionID, EncryptedPayloadB64: version.EncryptedPayloadB64, IsBinary: version.IsBinary, CreatedAt: version.CreatedAt})
	}
	kmsKeyID, encryptedPayloadB64, isBinary, err := store.BuildSecretCiphertext(ctx, s.ResolveByID, s.ResolveDefault, secret.metadata.KMSKeyID, req.SecretString, req.SecretBinary)
	if err != nil {
		return store.SecretValueRecord{}, err
	}
	now := time.Now().UTC()
	secret.metadata.KMSKeyID = kmsKeyID
	store.PromoteSecretVersion(&secret.metadata, versionID)
	secret.metadata.LastChangedDate = now
	secret.metadata.UpdatedBy = store.ActorFromContext(ctx)
	secret.byToken[versionID] = versionID
	secret.versions[versionID] = inMemorySecretVersion{VersionID: versionID, ClientRequestToken: versionID, EncryptedPayloadB64: encryptedPayloadB64, IsBinary: isBinary, CreatedAt: now, CreatedBy: store.ActorFromContext(ctx)}
	return store.BuildSecretValueRecord(ctx, s.ResolveByID, secret.metadata, store.SecretVersionRow{VersionID: versionID, EncryptedPayloadB64: encryptedPayloadB64, IsBinary: isBinary, CreatedAt: now})
}

func (s *Store) UpdateSecret(ctx context.Context, req store.UpdateSecretRequest) (store.SecretMetadataRecord, *store.SecretValueRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, req.SecretID)
	if err != nil {
		return store.SecretMetadataRecord{}, nil, err
	}
	if secret.metadata.DeletedDate != nil {
		return store.SecretMetadataRecord{}, nil, store.ErrSecretPendingDeletion
	}
	if strings.TrimSpace(req.Description) != "" {
		secret.metadata.Description = strings.TrimSpace(req.Description)
	}
	if strings.TrimSpace(req.KMSKeyID) != "" {
		resolved, err := s.ResolveByID(ctx, req.KMSKeyID)
		if err != nil {
			return store.SecretMetadataRecord{}, nil, err
		}
		secret.metadata.KMSKeyID = resolved.ID
	}
	secret.metadata.LastChangedDate = time.Now().UTC()
	store.EnsureSecretStageMap(&secret.metadata)
	var value *store.SecretValueRecord
	if req.SecretString != "" || req.SecretBinary != "" {
		putValue, err := s.putSecretValueLocked(ctx, store.PutSecretValueRequest{SecretID: secret.metadata.Name, ClientRequestToken: req.ClientRequestToken, SecretString: req.SecretString, SecretBinary: req.SecretBinary})
		if err != nil {
			return store.SecretMetadataRecord{}, nil, err
		}
		value = &putValue
	}
	return secret.metadata, value, nil
}

func (s *Store) DeleteSecret(ctx context.Context, secretID string, recoveryWindowDays int, forceDelete bool) (store.SecretMetadataRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, secretID)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	// Force delete purges the secret immediately, even when it is already
	// scheduled for deletion.
	if forceDelete {
		delete(s.secrets, memSecretKey(secret.account, secret.metadata.Name))
		now := time.Now().UTC()
		secret.metadata.DeletedDate = &now
		secret.metadata.LastChangedDate = now
		return secret.metadata, nil
	}
	deletionDate, err := store.NormalizeSecretDeletion(forceDelete, recoveryWindowDays)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	secret.metadata.DeletedDate = &deletionDate
	secret.metadata.LastChangedDate = time.Now().UTC()
	return secret.metadata, nil
}

func (s *Store) RestoreSecret(ctx context.Context, secretID string) (store.SecretMetadataRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, secretID)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	secret.metadata.DeletedDate = nil
	secret.metadata.LastChangedDate = time.Now().UTC()
	return secret.metadata, nil
}

func (s *Store) ListSecrets(ctx context.Context) ([]store.SecretMetadataRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.secrets) == 0 {
		return nil, nil
	}
	account := s.accountForContext(ctx)
	keys := make([]string, 0, len(s.secrets))
	for key, secret := range s.secrets {
		if secret.account != account {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]store.SecretMetadataRecord, 0, len(keys))
	for _, key := range keys {
		out = append(out, s.secrets[key].snapshot())
	}
	return out, nil
}

// findSecret resolves a secret within the caller's account by logical name or
// ARN. Scoping by account ensures one tenant can never resolve another's
// secret, even when they share the same name.
func (s *Store) findSecret(ctx context.Context, secretID string) (*inMemorySecret, error) {
	if len(s.secrets) == 0 {
		return nil, sql.ErrNoRows
	}
	account := s.accountForContext(ctx)
	secretID = strings.TrimSpace(secretID)
	if secret, ok := s.secrets[memSecretKey(account, secretID)]; ok {
		return secret, nil
	}
	for _, secret := range s.secrets {
		if secret.account == account && secret.metadata.ARN == secretID {
			return secret, nil
		}
	}
	return nil, sql.ErrNoRows
}

func (s *Store) ListSecretVersionIDs(ctx context.Context, secretID string) ([]store.SecretVersionListEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, secretID)
	if err != nil {
		return nil, err
	}
	entries := make([]store.SecretVersionListEntry, 0, len(secret.versions))
	for _, version := range secret.versions {
		entries = append(entries, store.SecretVersionListEntry{VersionID: version.VersionID, VersionStages: store.SecretStagesForVersion(secret.metadata, version.VersionID), CreatedDate: store.AWSTimestamp(version.CreatedAt), KMSKeyIDs: []string{secret.metadata.KMSKeyID}, CreatedBy: version.CreatedBy})
	}
	sort.Slice(entries, func(i, j int) bool {
		return time.Time(entries[i].CreatedDate).Before(time.Time(entries[j].CreatedDate))
	})
	return entries, nil
}

func (s *Store) TagSecret(ctx context.Context, secretID string, tags []store.SecretTag) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, secretID)
	if err != nil {
		return err
	}
	byKey := map[string]string{}
	for _, tag := range secret.metadata.Tags {
		byKey[tag.Key] = tag.Value
	}
	for _, tag := range tags {
		if strings.TrimSpace(tag.Key) == "" {
			continue
		}
		byKey[tag.Key] = tag.Value
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	secret.metadata.Tags = secret.metadata.Tags[:0]
	for _, key := range keys {
		secret.metadata.Tags = append(secret.metadata.Tags, store.SecretTag{Key: key, Value: byKey[key]})
	}
	return nil
}

func (s *Store) UntagSecret(ctx context.Context, secretID string, tagKeys []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, secretID)
	if err != nil {
		return err
	}
	remove := map[string]struct{}{}
	for _, key := range tagKeys {
		remove[key] = struct{}{}
	}
	filtered := make([]store.SecretTag, 0, len(secret.metadata.Tags))
	for _, tag := range secret.metadata.Tags {
		if _, ok := remove[tag.Key]; !ok {
			filtered = append(filtered, tag)
		}
	}
	secret.metadata.Tags = filtered
	return nil
}

func (s *Store) GetSecretResourcePolicy(ctx context.Context, secretID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, secretID)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(secret.metadata.PolicyDocument) == "" {
		return store.DefaultSecretResourcePolicy(secret.metadata), nil
	}
	return secret.metadata.PolicyDocument, nil
}

func (s *Store) PutSecretResourcePolicy(ctx context.Context, secretID, policyDocument string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, secretID)
	if err != nil {
		return err
	}
	secret.metadata.PolicyDocument = policyDocument
	return nil
}

func (s *Store) RotateSecret(ctx context.Context, secretID, rotationLambdaARN string, automaticallyAfterDays int, rotateImmediately bool, clientRequestToken string) (store.SecretRotationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, secretID)
	if err != nil {
		return store.SecretRotationResult{}, err
	}
	if automaticallyAfterDays == 0 {
		automaticallyAfterDays = 30
	}
	next := time.Now().UTC().Add(time.Duration(automaticallyAfterDays) * 24 * time.Hour)
	secret.metadata.RotationEnabled = true
	secret.metadata.RotationLambdaARN = strings.TrimSpace(rotationLambdaARN)
	secret.metadata.RotationDays = automaticallyAfterDays
	secret.metadata.NextRotationDate = &next
	versionID := ""
	if rotateImmediately {
		currentValue, err := s.getSecretValueLocked(ctx, secret.metadata.Name, secret.metadata.CurrentVersionID, "")
		if err != nil {
			return store.SecretRotationResult{}, err
		}
		versionID = clientRequestToken
		if versionID == "" {
			versionID = cryptoutil.RandomHex(16)
		}
		var putReq store.PutSecretValueRequest
		if currentValue.SecretString != nil {
			putReq = store.PutSecretValueRequest{SecretID: secret.metadata.Name, ClientRequestToken: versionID, SecretString: *currentValue.SecretString}
		} else {
			putReq = store.PutSecretValueRequest{SecretID: secret.metadata.Name, ClientRequestToken: versionID, SecretBinary: currentValue.SecretBinary}
		}
		if _, err := s.putSecretValueLocked(ctx, putReq); err != nil {
			return store.SecretRotationResult{}, err
		}
		store.AssignSecretStage(&secret.metadata, store.PendingVersionStage, versionID)
	}
	return store.SecretRotationResult{Metadata: secret.metadata, VersionID: versionID}, nil
}

func (s *Store) CancelRotateSecret(ctx context.Context, secretID string) (store.SecretMetadataRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, secretID)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	secret.metadata.RotationEnabled = false
	secret.metadata.RotationLambdaARN = ""
	secret.metadata.RotationDays = 0
	secret.metadata.NextRotationDate = nil
	store.RemoveSecretStage(&secret.metadata, store.PendingVersionStage, "")
	return secret.metadata, nil
}

func (s *Store) UpdateSecretVersionStage(ctx context.Context, secretID, versionStage, moveToVersionID, removeFromVersionID string) (store.SecretMetadataRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, err := s.findSecret(ctx, secretID)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	if strings.TrimSpace(moveToVersionID) == "" {
		return store.SecretMetadataRecord{}, errors.New("MoveToVersionId is required")
	}
	if _, ok := secret.versions[moveToVersionID]; !ok {
		return store.SecretMetadataRecord{}, sql.ErrNoRows
	}
	store.AssignSecretStage(&secret.metadata, versionStage, moveToVersionID)
	if removeFromVersionID != "" {
		store.RemoveSecretStage(&secret.metadata, versionStage, removeFromVersionID)
	}
	store.SyncPrimarySecretVersionFields(&secret.metadata)
	return secret.metadata, nil
}
