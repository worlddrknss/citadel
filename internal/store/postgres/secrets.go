package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

func mapSecretDBError(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "duplicate key value") {
		return store.ErrSecretExists
	}
	return err
}

func persistSecretStageRowsTx(ctx context.Context, tx *sql.Tx, secretName string, stageMap map[string][]string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM sm_secret_version_stages WHERE secret_name = $1`, secretName); err != nil {
		return err
	}
	for versionID, stages := range stageMap {
		for _, stage := range stages {
			if _, err := tx.ExecContext(ctx, `INSERT INTO sm_secret_version_stages (secret_name, version_id, stage_label) VALUES ($1, $2, $3)`, secretName, versionID, stage); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) CreateSecret(ctx context.Context, req store.CreateSecretRequest) (store.SecretMetadataRecord, store.SecretValueRecord, error) {
	name := strings.TrimSpace(req.Name)
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
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return store.SecretMetadataRecord{}, store.SecretValueRecord{}, err
	}
	defer tx.Rollback()
	const insertSecret = `
INSERT INTO sm_secrets (name, arn, description, kms_key_id, current_version_id, previous_version_id, deleted_date, created_at, updated_at, account_id)
VALUES ($1, $2, $3, $4, $5, '', NULL, $6, $7, $8)
`
	if _, err := tx.ExecContext(ctx, insertSecret, meta.Name, meta.ARN, meta.Description, meta.KMSKeyID, meta.CurrentVersionID, meta.CreatedAt, meta.LastChangedDate, s.accountForContext(ctx)); err != nil {
		return store.SecretMetadataRecord{}, store.SecretValueRecord{}, mapSecretDBError(err)
	}
	const insertVersion = `
INSERT INTO sm_secret_versions (secret_name, version_id, client_request_token, encrypted_payload_b64, is_binary, version_created_at)
VALUES ($1, $2, $3, $4, $5, $6)
`
	if _, err := tx.ExecContext(ctx, insertVersion, meta.Name, versionID, versionID, encryptedPayloadB64, isBinary, now); err != nil {
		return store.SecretMetadataRecord{}, store.SecretValueRecord{}, mapSecretDBError(err)
	}
	if err := persistSecretStageRowsTx(ctx, tx, meta.Name, meta.VersionStages); err != nil {
		return store.SecretMetadataRecord{}, store.SecretValueRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return store.SecretMetadataRecord{}, store.SecretValueRecord{}, err
	}
	value, err := store.BuildSecretValueRecord(ctx, s.ResolveByID, meta, store.SecretVersionRow{VersionID: versionID, EncryptedPayloadB64: encryptedPayloadB64, IsBinary: isBinary, CreatedAt: now})
	if err != nil {
		return store.SecretMetadataRecord{}, store.SecretValueRecord{}, err
	}
	return meta, value, nil
}

func (s *Store) DescribeSecret(ctx context.Context, secretID string) (store.SecretMetadataRecord, error) {
	return s.loadSecretMetadata(ctx, secretID)
}

func (s *Store) GetSecretValue(ctx context.Context, secretID, versionID, versionStage string) (store.SecretValueRecord, error) {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return store.SecretValueRecord{}, err
	}
	if meta.DeletedDate != nil {
		return store.SecretValueRecord{}, errors.New("secret scheduled for deletion")
	}
	resolvedVersionID, err := store.ResolveSecretVersionID(meta, versionID, versionStage)
	if err != nil {
		return store.SecretValueRecord{}, err
	}
	version, err := s.loadSecretVersion(ctx, meta.Name, resolvedVersionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.SecretValueRecord{}, sql.ErrNoRows
		}
		return store.SecretValueRecord{}, err
	}
	return store.BuildSecretValueRecord(ctx, s.ResolveByID, meta, version)
}

func (s *Store) PutSecretValue(ctx context.Context, req store.PutSecretValueRequest) (store.SecretValueRecord, error) {
	meta, err := s.loadSecretMetadata(ctx, req.SecretID)
	if err != nil {
		return store.SecretValueRecord{}, err
	}
	if meta.DeletedDate != nil {
		return store.SecretValueRecord{}, errors.New("secret scheduled for deletion")
	}
	versionID := req.ClientRequestToken
	if versionID == "" {
		versionID = cryptoutil.RandomHex(16)
	}
	if existing, err := s.loadSecretVersionByToken(ctx, meta.Name, versionID); err == nil {
		return store.BuildSecretValueRecord(ctx, s.ResolveByID, meta, existing)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return store.SecretValueRecord{}, err
	}
	kmsKeyID, encryptedPayloadB64, isBinary, err := store.BuildSecretCiphertext(ctx, s.ResolveByID, s.ResolveDefault, meta.KMSKeyID, req.SecretString, req.SecretBinary)
	if err != nil {
		return store.SecretValueRecord{}, err
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return store.SecretValueRecord{}, err
	}
	defer tx.Rollback()
	const insertVersion = `
INSERT INTO sm_secret_versions (secret_name, version_id, client_request_token, encrypted_payload_b64, is_binary, version_created_at)
VALUES ($1, $2, $3, $4, $5, $6)
`
	if _, err := tx.ExecContext(ctx, insertVersion, meta.Name, versionID, versionID, encryptedPayloadB64, isBinary, now); err != nil {
		return store.SecretValueRecord{}, mapSecretDBError(err)
	}
	store.PromoteSecretVersion(&meta, versionID)
	const updateSecret = `
UPDATE sm_secrets
SET kms_key_id = $2, previous_version_id = current_version_id, current_version_id = $3, updated_at = $4
WHERE name = $1
`
	if _, err := tx.ExecContext(ctx, updateSecret, meta.Name, kmsKeyID, versionID, now); err != nil {
		return store.SecretValueRecord{}, err
	}
	if err := persistSecretStageRowsTx(ctx, tx, meta.Name, meta.VersionStages); err != nil {
		return store.SecretValueRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return store.SecretValueRecord{}, err
	}
	meta.KMSKeyID = kmsKeyID
	meta.LastChangedDate = now
	return store.BuildSecretValueRecord(ctx, s.ResolveByID, meta, store.SecretVersionRow{VersionID: versionID, EncryptedPayloadB64: encryptedPayloadB64, IsBinary: isBinary, CreatedAt: now})
}

func (s *Store) UpdateSecret(ctx context.Context, req store.UpdateSecretRequest) (store.SecretMetadataRecord, *store.SecretValueRecord, error) {
	meta, err := s.loadSecretMetadata(ctx, req.SecretID)
	if err != nil {
		return store.SecretMetadataRecord{}, nil, err
	}
	if meta.DeletedDate != nil {
		return store.SecretMetadataRecord{}, nil, errors.New("secret scheduled for deletion")
	}
	nextDescription := meta.Description
	if strings.TrimSpace(req.Description) != "" {
		nextDescription = strings.TrimSpace(req.Description)
	}
	nextKMSKeyID := meta.KMSKeyID
	if strings.TrimSpace(req.KMSKeyID) != "" {
		resolved, err := s.ResolveByID(ctx, req.KMSKeyID)
		if err != nil {
			return store.SecretMetadataRecord{}, nil, err
		}
		nextKMSKeyID = resolved.ID
	}
	now := time.Now().UTC()
	var value *store.SecretValueRecord
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return store.SecretMetadataRecord{}, nil, err
	}
	defer tx.Rollback()
	store.EnsureSecretStageMap(&meta)
	if req.SecretString != "" || req.SecretBinary != "" {
		versionID := req.ClientRequestToken
		if versionID == "" {
			versionID = cryptoutil.RandomHex(16)
		}
		if existing, err := s.loadSecretVersionByToken(ctx, meta.Name, versionID); err == nil {
			built, buildErr := store.BuildSecretValueRecord(ctx, s.ResolveByID, meta, existing)
			if buildErr != nil {
				return store.SecretMetadataRecord{}, nil, buildErr
			}
			value = &built
		} else if !errors.Is(err, sql.ErrNoRows) {
			return store.SecretMetadataRecord{}, nil, err
		} else {
			kmsKeyID, encryptedPayloadB64, isBinary, encErr := store.BuildSecretCiphertext(ctx, s.ResolveByID, s.ResolveDefault, nextKMSKeyID, req.SecretString, req.SecretBinary)
			if encErr != nil {
				return store.SecretMetadataRecord{}, nil, encErr
			}
			const insertVersion = `
INSERT INTO sm_secret_versions (secret_name, version_id, client_request_token, encrypted_payload_b64, is_binary, version_created_at)
VALUES ($1, $2, $3, $4, $5, $6)
`
			if _, err := tx.ExecContext(ctx, insertVersion, meta.Name, versionID, versionID, encryptedPayloadB64, isBinary, now); err != nil {
				return store.SecretMetadataRecord{}, nil, mapSecretDBError(err)
			}
			store.PromoteSecretVersion(&meta, versionID)
			nextKMSKeyID = kmsKeyID
			// The freshly written version is sealed under nextKMSKeyID, so the
			// returned value record must decrypt with that key. Update meta's
			// key before building the record to avoid decrypting the new
			// ciphertext with the previous master key (AEAD auth failure).
			meta.KMSKeyID = nextKMSKeyID
			built, buildErr := store.BuildSecretValueRecord(ctx, s.ResolveByID, meta, store.SecretVersionRow{VersionID: versionID, EncryptedPayloadB64: encryptedPayloadB64, IsBinary: isBinary, CreatedAt: now})
			if buildErr != nil {
				return store.SecretMetadataRecord{}, nil, buildErr
			}
			value = &built
		}
	}
	const updateSecret = `
UPDATE sm_secrets
SET description = $2, kms_key_id = $3, current_version_id = $4, previous_version_id = $5, updated_at = $6
WHERE name = $1
`
	if _, err := tx.ExecContext(ctx, updateSecret, meta.Name, nextDescription, nextKMSKeyID, meta.CurrentVersionID, meta.PreviousVersionID, now); err != nil {
		return store.SecretMetadataRecord{}, nil, err
	}
	if err := persistSecretStageRowsTx(ctx, tx, meta.Name, meta.VersionStages); err != nil {
		return store.SecretMetadataRecord{}, nil, err
	}
	if err := tx.Commit(); err != nil {
		return store.SecretMetadataRecord{}, nil, err
	}
	meta.Description = nextDescription
	meta.KMSKeyID = nextKMSKeyID
	meta.LastChangedDate = now
	return meta, value, nil
}

func (s *Store) DeleteSecret(ctx context.Context, secretID string, recoveryWindowDays int, forceDelete bool) (store.SecretMetadataRecord, error) {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	// Force delete purges the secret immediately, bypassing the recovery
	// window. This works even when the secret is already scheduled for
	// deletion so operators can fully remove a pending item.
	if forceDelete {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return store.SecretMetadataRecord{}, err
		}
		defer func() { _ = tx.Rollback() }()
		for _, q := range []string{
			`DELETE FROM sm_secret_versions WHERE secret_name = $1`,
			`DELETE FROM sm_secret_tags WHERE secret_name = $1`,
			`DELETE FROM sm_secret_policies WHERE secret_name = $1`,
			`DELETE FROM sm_secrets WHERE name = $1`,
		} {
			if _, err := tx.ExecContext(ctx, q, meta.Name); err != nil {
				return store.SecretMetadataRecord{}, err
			}
		}
		if err := tx.Commit(); err != nil {
			return store.SecretMetadataRecord{}, err
		}
		now := time.Now().UTC()
		meta.DeletedDate = &now
		meta.LastChangedDate = now
		return meta, nil
	}
	if meta.DeletedDate != nil {
		return meta, nil
	}
	deletionDate, err := store.NormalizeSecretDeletion(forceDelete, recoveryWindowDays)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	const q = `UPDATE sm_secrets SET deleted_date = $2, updated_at = NOW() WHERE name = $1`
	if _, err := s.db.ExecContext(ctx, q, meta.Name, deletionDate); err != nil {
		return store.SecretMetadataRecord{}, err
	}
	meta.DeletedDate = &deletionDate
	meta.LastChangedDate = time.Now().UTC()
	return meta, nil
}

func (s *Store) RestoreSecret(ctx context.Context, secretID string) (store.SecretMetadataRecord, error) {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	const q = `UPDATE sm_secrets SET deleted_date = NULL, updated_at = NOW() WHERE name = $1`
	if _, err := s.db.ExecContext(ctx, q, meta.Name); err != nil {
		return store.SecretMetadataRecord{}, err
	}
	meta.DeletedDate = nil
	meta.LastChangedDate = time.Now().UTC()
	return meta, nil
}

func (s *Store) ListSecrets(ctx context.Context) ([]store.SecretMetadataRecord, error) {
	q := `
SELECT name, arn, description, kms_key_id, current_version_id, previous_version_id, rotation_enabled, rotation_lambda_arn, rotation_days, next_rotation_date, deleted_date, created_at, updated_at
FROM sm_secrets`
	cond, args := store.AccountFilter(ctx, "account_id", 1)
	if cond != "" {
		q += "\nWHERE " + cond
	}
	q += "\nORDER BY created_at ASC"
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]store.SecretMetadataRecord, 0)
	for rows.Next() {
		var (
			item        store.SecretMetadataRecord
			nextRotate  sql.NullTime
			deletedDate sql.NullTime
		)
		if err := rows.Scan(&item.Name, &item.ARN, &item.Description, &item.KMSKeyID, &item.CurrentVersionID, &item.PreviousVersionID, &item.RotationEnabled, &item.RotationLambdaARN, &item.RotationDays, &nextRotate, &deletedDate, &item.CreatedAt, &item.LastChangedDate); err != nil {
			return nil, err
		}
		if nextRotate.Valid {
			item.NextRotationDate = &nextRotate.Time
		}
		if deletedDate.Valid {
			item.DeletedDate = &deletedDate.Time
		}
		item.VersionStages = store.BuildFallbackSecretStageMap(item.CurrentVersionID, item.PreviousVersionID)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) loadSecretMetadata(ctx context.Context, secretID string) (store.SecretMetadataRecord, error) {
	q := `
SELECT name, arn, description, kms_key_id, current_version_id, previous_version_id, rotation_enabled, rotation_lambda_arn, rotation_days, next_rotation_date, deleted_date, created_at, updated_at
FROM sm_secrets
WHERE (name = $1 OR arn = $1)`
	args := []any{strings.TrimSpace(secretID)}
	if cond, extra := store.AccountFilter(ctx, "account_id", 2); cond != "" {
		q += " AND " + cond
		args = append(args, extra...)
	}
	q += "\nLIMIT 1"
	var (
		item        store.SecretMetadataRecord
		nextRotate  sql.NullTime
		deletedDate sql.NullTime
	)
	err := s.db.QueryRowContext(ctx, q, args...).Scan(&item.Name, &item.ARN, &item.Description, &item.KMSKeyID, &item.CurrentVersionID, &item.PreviousVersionID, &item.RotationEnabled, &item.RotationLambdaARN, &item.RotationDays, &nextRotate, &deletedDate, &item.CreatedAt, &item.LastChangedDate)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	if nextRotate.Valid {
		item.NextRotationDate = &nextRotate.Time
	}
	if deletedDate.Valid {
		item.DeletedDate = &deletedDate.Time
	}
	item.VersionStages = store.BuildFallbackSecretStageMap(item.CurrentVersionID, item.PreviousVersionID)
	if err := s.loadSecretDecorations(ctx, &item); err != nil {
		return store.SecretMetadataRecord{}, err
	}
	return item, nil
}

func (s *Store) loadSecretVersion(ctx context.Context, secretName, versionID string) (store.SecretVersionRow, error) {
	const q = `
SELECT version_id, encrypted_payload_b64, is_binary, version_created_at
FROM sm_secret_versions
WHERE secret_name = $1 AND version_id = $2
`
	var row store.SecretVersionRow
	err := s.db.QueryRowContext(ctx, q, secretName, versionID).Scan(&row.VersionID, &row.EncryptedPayloadB64, &row.IsBinary, &row.CreatedAt)
	return row, err
}

func (s *Store) loadSecretVersionByToken(ctx context.Context, secretName, token string) (store.SecretVersionRow, error) {
	const q = `
SELECT version_id, encrypted_payload_b64, is_binary, version_created_at
FROM sm_secret_versions
WHERE secret_name = $1 AND client_request_token = $2
`
	var row store.SecretVersionRow
	err := s.db.QueryRowContext(ctx, q, secretName, token).Scan(&row.VersionID, &row.EncryptedPayloadB64, &row.IsBinary, &row.CreatedAt)
	return row, err
}

func (s *Store) ListSecretVersionIDs(ctx context.Context, secretID string) ([]store.SecretVersionListEntry, error) {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return nil, err
	}
	const q = `
SELECT version_id, version_created_at
FROM sm_secret_versions
WHERE secret_name = $1
ORDER BY version_created_at ASC
`
	rows, err := s.db.QueryContext(ctx, q, meta.Name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]store.SecretVersionListEntry, 0)
	for rows.Next() {
		var entry store.SecretVersionListEntry
		var createdAt time.Time
		if err := rows.Scan(&entry.VersionID, &createdAt); err != nil {
			return nil, err
		}
		entry.CreatedDate = store.AWSTimestamp(createdAt)
		entry.VersionStages = store.SecretStagesForVersion(meta, entry.VersionID)
		entry.KMSKeyIDs = []string{meta.KMSKeyID}
		out = append(out, entry)
	}
	return out, rows.Err()
}

func (s *Store) TagSecret(ctx context.Context, secretID string, tags []store.SecretTag) error {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return err
	}
	for _, tag := range tags {
		if strings.TrimSpace(tag.Key) == "" {
			continue
		}
		const q = `
INSERT INTO sm_secret_tags (secret_name, tag_key, tag_value)
VALUES ($1, $2, $3)
ON CONFLICT (secret_name, tag_key) DO UPDATE SET tag_value = EXCLUDED.tag_value
`
		if _, err := s.db.ExecContext(ctx, q, meta.Name, tag.Key, tag.Value); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) UntagSecret(ctx context.Context, secretID string, tagKeys []string) error {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return err
	}
	for _, key := range tagKeys {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM sm_secret_tags WHERE secret_name = $1 AND tag_key = $2`, meta.Name, key); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) GetSecretResourcePolicy(ctx context.Context, secretID string) (string, error) {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return "", err
	}
	const q = `SELECT policy_document FROM sm_secret_policies WHERE secret_name = $1`
	var policy string
	err = s.db.QueryRowContext(ctx, q, meta.Name).Scan(&policy)
	if errors.Is(err, sql.ErrNoRows) {
		return store.DefaultSecretResourcePolicy(meta), nil
	}
	return policy, err
}

func (s *Store) PutSecretResourcePolicy(ctx context.Context, secretID, policyDocument string) error {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return err
	}
	const q = `
INSERT INTO sm_secret_policies (secret_name, policy_document)
VALUES ($1, $2)
ON CONFLICT (secret_name) DO UPDATE SET policy_document = EXCLUDED.policy_document, updated_at = NOW()
`
	_, err = s.db.ExecContext(ctx, q, meta.Name, policyDocument)
	return err
}

func (s *Store) RotateSecret(ctx context.Context, secretID, rotationLambdaARN string, automaticallyAfterDays int, rotateImmediately bool, clientRequestToken string) (store.SecretRotationResult, error) {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return store.SecretRotationResult{}, err
	}
	if automaticallyAfterDays == 0 {
		automaticallyAfterDays = 30
	}
	if automaticallyAfterDays < 1 {
		return store.SecretRotationResult{}, errors.New("AutomaticallyAfterDays must be greater than 0")
	}
	meta.RotationEnabled = true
	meta.RotationLambdaARN = strings.TrimSpace(rotationLambdaARN)
	meta.RotationDays = automaticallyAfterDays
	next := time.Now().UTC().Add(time.Duration(automaticallyAfterDays) * 24 * time.Hour)
	meta.NextRotationDate = &next
	versionID := ""
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return store.SecretRotationResult{}, err
	}
	defer tx.Rollback()
	if rotateImmediately {
		pendingVersionID := clientRequestToken
		if pendingVersionID == "" {
			pendingVersionID = cryptoutil.RandomHex(16)
		}
		currentVersion, err := s.loadSecretVersion(ctx, meta.Name, meta.CurrentVersionID)
		if err != nil {
			return store.SecretRotationResult{}, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO sm_secret_versions (secret_name, version_id, client_request_token, encrypted_payload_b64, is_binary, version_created_at) VALUES ($1,$2,$3,$4,$5,$6)`, meta.Name, pendingVersionID, pendingVersionID, currentVersion.EncryptedPayloadB64, currentVersion.IsBinary, time.Now().UTC()); err != nil {
			return store.SecretRotationResult{}, mapSecretDBError(err)
		}
		store.AssignSecretStage(&meta, store.PendingVersionStage, pendingVersionID)
		versionID = pendingVersionID
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sm_secrets SET rotation_enabled = $2, rotation_lambda_arn = $3, rotation_days = $4, next_rotation_date = $5, updated_at = NOW() WHERE name = $1`, meta.Name, meta.RotationEnabled, meta.RotationLambdaARN, meta.RotationDays, meta.NextRotationDate); err != nil {
		return store.SecretRotationResult{}, err
	}
	if err := persistSecretStageRowsTx(ctx, tx, meta.Name, meta.VersionStages); err != nil {
		return store.SecretRotationResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return store.SecretRotationResult{}, err
	}
	return store.SecretRotationResult{Metadata: meta, VersionID: versionID}, nil
}

func (s *Store) CancelRotateSecret(ctx context.Context, secretID string) (store.SecretMetadataRecord, error) {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	meta.RotationEnabled = false
	meta.RotationLambdaARN = ""
	meta.RotationDays = 0
	meta.NextRotationDate = nil
	store.RemoveSecretStage(&meta, store.PendingVersionStage, "")
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE sm_secrets SET rotation_enabled = FALSE, rotation_lambda_arn = '', rotation_days = 0, next_rotation_date = NULL, updated_at = NOW() WHERE name = $1`, meta.Name); err != nil {
		return store.SecretMetadataRecord{}, err
	}
	if err := persistSecretStageRowsTx(ctx, tx, meta.Name, meta.VersionStages); err != nil {
		return store.SecretMetadataRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return store.SecretMetadataRecord{}, err
	}
	return meta, nil
}

func (s *Store) UpdateSecretVersionStage(ctx context.Context, secretID, versionStage, moveToVersionID, removeFromVersionID string) (store.SecretMetadataRecord, error) {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	if strings.TrimSpace(versionStage) == "" || strings.TrimSpace(moveToVersionID) == "" {
		return store.SecretMetadataRecord{}, errors.New("VersionStage and MoveToVersionId are required")
	}
	if _, err := s.loadSecretVersion(ctx, meta.Name, moveToVersionID); err != nil {
		return store.SecretMetadataRecord{}, err
	}
	store.AssignSecretStage(&meta, versionStage, moveToVersionID)
	if removeFromVersionID != "" {
		store.RemoveSecretStage(&meta, versionStage, removeFromVersionID)
	}
	store.SyncPrimarySecretVersionFields(&meta)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE sm_secrets SET current_version_id = $2, previous_version_id = $3, updated_at = NOW() WHERE name = $1`, meta.Name, meta.CurrentVersionID, meta.PreviousVersionID); err != nil {
		return store.SecretMetadataRecord{}, err
	}
	if err := persistSecretStageRowsTx(ctx, tx, meta.Name, meta.VersionStages); err != nil {
		return store.SecretMetadataRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return store.SecretMetadataRecord{}, err
	}
	return meta, nil
}

func (s *Store) loadSecretDecorations(ctx context.Context, meta *store.SecretMetadataRecord) error {
	stageMap, err := s.loadSecretStageMap(ctx, meta.Name, meta.CurrentVersionID, meta.PreviousVersionID)
	if err != nil {
		return err
	}
	meta.VersionStages = stageMap
	tags, err := s.loadSecretTags(ctx, meta.Name)
	if err != nil {
		return err
	}
	meta.Tags = tags
	var policy string
	err = s.db.QueryRowContext(ctx, `SELECT policy_document FROM sm_secret_policies WHERE secret_name = $1`, meta.Name).Scan(&policy)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if errors.Is(err, sql.ErrNoRows) {
		policy = store.DefaultSecretResourcePolicy(*meta)
	}
	meta.PolicyDocument = policy
	return nil
}

func (s *Store) loadSecretStageMap(ctx context.Context, secretName, currentVersionID, previousVersionID string) (map[string][]string, error) {
	const q = `SELECT version_id, stage_label FROM sm_secret_version_stages WHERE secret_name = $1`
	rows, err := s.db.QueryContext(ctx, q, secretName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	stageMap := map[string][]string{}
	for rows.Next() {
		var versionID, stage string
		if err := rows.Scan(&versionID, &stage); err != nil {
			return nil, err
		}
		stageMap[versionID] = append(stageMap[versionID], stage)
	}
	if len(stageMap) == 0 {
		return store.BuildFallbackSecretStageMap(currentVersionID, previousVersionID), rows.Err()
	}
	store.MergeSecretStageMaps(stageMap, store.BuildFallbackSecretStageMap(currentVersionID, previousVersionID))
	return stageMap, rows.Err()
}

func (s *Store) loadSecretTags(ctx context.Context, secretName string) ([]store.SecretTag, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT tag_key, tag_value FROM sm_secret_tags WHERE secret_name = $1 ORDER BY tag_key ASC`, secretName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]store.SecretTag, 0)
	for rows.Next() {
		var tag store.SecretTag
		if err := rows.Scan(&tag.Key, &tag.Value); err != nil {
			return nil, err
		}
		out = append(out, tag)
	}
	return out, rows.Err()
}
