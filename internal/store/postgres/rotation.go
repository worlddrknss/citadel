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

// Built-in secret rotation (store.SecretRotationStore), in
// sm_secret_rotations and sm_secret_rotation_history (migration 1200).

const rotationColumns = `secret_name, rotator_type, config_secret, config_json, signing_key_sealed, schedule_expression, duration,
	status, last_step, last_error, attempts, last_attempt_at, next_attempt_at, last_rotated_at, lease_owner, lease_until, updated_at, updated_by`

func scanRotation(row interface{ Scan(...any) error }) (store.SecretRotation, error) {
	var (
		r                                     store.SecretRotation
		lastAttempt, nextAttempt, lastRotated sql.NullTime
		leaseUntil                            sql.NullTime
		sealed                                []byte
	)
	err := row.Scan(&r.SecretName, &r.RotatorType, &r.ConfigSecret, &r.Config, &sealed, &r.ScheduleExpression, &r.Duration,
		&r.Status, &r.LastStep, &r.LastError, &r.Attempts, &lastAttempt, &nextAttempt, &lastRotated, &r.LeaseOwner, &leaseUntil, &r.UpdatedAt, &r.UpdatedBy)
	if err != nil {
		return store.SecretRotation{}, err
	}
	if len(sealed) > 0 {
		r.SigningKeySealed = sealed
	}
	r.LastAttemptAt = nullTimePtr(lastAttempt)
	r.NextAttemptAt = nullTimePtr(nextAttempt)
	r.LastRotatedAt = nullTimePtr(lastRotated)
	r.LeaseUntil = nullTimePtr(leaseUntil)
	return r, nil
}

func nullTimePtr(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time
	return &v
}

func (s *Store) GetSecretRotation(ctx context.Context, secretID string) (store.SecretRotation, error) {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return store.SecretRotation{}, err
	}
	r, err := scanRotation(s.db.QueryRowContext(ctx, `SELECT `+rotationColumns+` FROM sm_secret_rotations WHERE account_id = $1 AND secret_name = $2`,
		s.accountForContext(ctx), meta.Name))
	if errors.Is(err, sql.ErrNoRows) {
		return store.SecretRotation{}, store.ErrRotationNotConfigured
	}
	return r, err
}

func (s *Store) ConfigureSecretRotation(ctx context.Context, cfg store.SecretRotationConfig) (store.SecretMetadataRecord, error) {
	acct, actor := s.accountForContext(ctx), store.ActorFromContext(ctx)
	meta, err := s.loadSecretMetadata(ctx, cfg.SecretID)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	defer tx.Rollback()
	lambda := strings.TrimSpace(cfg.LambdaARN)
	if _, err := tx.ExecContext(ctx, `UPDATE sm_secrets SET rotation_enabled = TRUE, rotation_lambda_arn = $3, rotation_days = $4, next_rotation_date = $5, updated_at = NOW() WHERE account_id = $1 AND name = $2`,
		acct, meta.Name, lambda, cfg.AfterDays, cfg.NextRotationDate); err != nil {
		return store.SecretMetadataRecord{}, err
	}
	// signing_key_sealed: $8 replaces it when $9 ('set'), clears it on
	// 'clear', otherwise keeps it.
	keyMode := "keep"
	switch {
	case cfg.SigningKeySealed != nil:
		keyMode = "set"
	case cfg.ClearSigningKey:
		keyMode = "clear"
	}
	const upsert = `
INSERT INTO sm_secret_rotations (account_id, secret_name, rotator_type, config_secret, config_json, schedule_expression, duration, signing_key_sealed, updated_at, updated_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, CASE WHEN $9 = 'set' THEN $8::bytea ELSE NULL END, NOW(), $10)
ON CONFLICT (account_id, secret_name) DO UPDATE SET
	rotator_type = EXCLUDED.rotator_type,
	config_secret = EXCLUDED.config_secret,
	config_json = EXCLUDED.config_json,
	schedule_expression = EXCLUDED.schedule_expression,
	duration = EXCLUDED.duration,
	signing_key_sealed = CASE $9 WHEN 'set' THEN $8::bytea WHEN 'clear' THEN NULL ELSE sm_secret_rotations.signing_key_sealed END,
	attempts = 0,
	next_attempt_at = NULL,
	status = CASE WHEN sm_secret_rotations.status IN ('retrying', 'failed') THEN '' ELSE sm_secret_rotations.status END,
	last_error = CASE WHEN sm_secret_rotations.status IN ('retrying', 'failed') THEN '' ELSE sm_secret_rotations.last_error END,
	updated_at = NOW(),
	updated_by = EXCLUDED.updated_by`
	if _, err := tx.ExecContext(ctx, upsert, acct, meta.Name, cfg.RotatorType, cfg.ConfigSecret, cfg.Config, cfg.ScheduleExpression, cfg.Duration,
		cfg.SigningKeySealed, keyMode, actor); err != nil {
		return store.SecretMetadataRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return store.SecretMetadataRecord{}, err
	}
	meta.RotationEnabled = true
	meta.RotationLambdaARN = lambda
	meta.RotationDays = cfg.AfterDays
	meta.NextRotationDate = cfg.NextRotationDate
	return meta, nil
}

func (s *Store) PutPendingSecretVersion(ctx context.Context, secretID, token, secretString, secretBinary string) (store.SecretValueRecord, error) {
	acct, actor := s.accountForContext(ctx), store.ActorFromContext(ctx)
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return store.SecretValueRecord{}, err
	}
	if meta.DeletedDate != nil {
		return store.SecretValueRecord{}, store.ErrSecretPendingDeletion
	}
	if token == "" {
		token = cryptoutil.RandomHex(16)
	}
	if existing, err := s.loadSecretVersionByToken(ctx, acct, meta.Name, token); err == nil {
		return store.BuildSecretValueRecord(ctx, s.ResolveByID, meta, existing)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return store.SecretValueRecord{}, err
	}
	_, payload, isBinary, err := store.BuildSecretCiphertext(ctx, s.ResolveByID, s.ResolveDefault, meta.KMSKeyID, secretString, secretBinary)
	if err != nil {
		return store.SecretValueRecord{}, err
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return store.SecretValueRecord{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT 1 FROM sm_secrets WHERE account_id = $1 AND name = $2 FOR UPDATE`, acct, meta.Name); err != nil {
		return store.SecretValueRecord{}, err
	}
	stages, err := s.loadSecretStageMapTx(ctx, tx, acct, meta)
	if err != nil {
		return store.SecretValueRecord{}, err
	}
	meta.VersionStages = stages
	if _, err := tx.ExecContext(ctx, `INSERT INTO sm_secret_versions (account_id, secret_name, version_id, client_request_token, encrypted_payload_b64, is_binary, version_created_at, created_by) VALUES ($1,$2,$3,$3,$4,$5,$6,$7)`,
		acct, meta.Name, token, payload, isBinary, now, actor); err != nil {
		return store.SecretValueRecord{}, mapSecretDBError(err)
	}
	store.AssignSecretStage(&meta, store.PendingVersionStage, token)
	if err := persistSecretStageRowsTx(ctx, tx, acct, meta.Name, meta.VersionStages); err != nil {
		return store.SecretValueRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return store.SecretValueRecord{}, err
	}
	return store.BuildSecretValueRecord(ctx, s.ResolveByID, meta, store.SecretVersionRow{VersionID: token, EncryptedPayloadB64: payload, IsBinary: isBinary, CreatedAt: now})
}

// loadSecretStageMapTx reads the stage labels inside tx (after the secret
// row is locked), falling back to the current/previous columns.
func (s *Store) loadSecretStageMapTx(ctx context.Context, tx *sql.Tx, acct string, meta store.SecretMetadataRecord) (map[string][]string, error) {
	var cur, prev string
	if err := tx.QueryRowContext(ctx, `SELECT current_version_id, previous_version_id FROM sm_secrets WHERE account_id = $1 AND name = $2`, acct, meta.Name).Scan(&cur, &prev); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT version_id, stage_label FROM sm_secret_version_stages WHERE account_id = $1 AND secret_name = $2`, acct, meta.Name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var v, st string
		if err := rows.Scan(&v, &st); err != nil {
			return nil, err
		}
		out[v] = append(out[v], st)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	store.MergeSecretStageMaps(out, store.BuildFallbackSecretStageMap(cur, prev))
	return out, nil
}

func (s *Store) FinishSecretRotation(ctx context.Context, secretID, token string) (store.SecretMetadataRecord, error) {
	acct := s.accountForContext(ctx)
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT 1 FROM sm_secrets WHERE account_id = $1 AND name = $2 FOR UPDATE`, acct, meta.Name); err != nil {
		return store.SecretMetadataRecord{}, err
	}
	var createdBy string
	err = tx.QueryRowContext(ctx, `SELECT created_by FROM sm_secret_versions WHERE account_id = $1 AND secret_name = $2 AND version_id = $3`, acct, meta.Name, token).Scan(&createdBy)
	if errors.Is(err, sql.ErrNoRows) {
		return store.SecretMetadataRecord{}, store.ErrInvalidSecretVersion
	}
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	stages, err := s.loadSecretStageMapTx(ctx, tx, acct, meta)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	meta.VersionStages = stages
	store.SyncPrimarySecretVersionFields(&meta)
	if store.FinishRotationStages(&meta, token) {
		now := time.Now().UTC()
		if _, err := tx.ExecContext(ctx, `UPDATE sm_secrets SET current_version_id = $3, previous_version_id = $4, updated_at = $5, updated_by = $6 WHERE account_id = $1 AND name = $2`,
			acct, meta.Name, meta.CurrentVersionID, meta.PreviousVersionID, now, createdBy); err != nil {
			return store.SecretMetadataRecord{}, err
		}
		meta.LastChangedDate = now
		meta.UpdatedBy = createdBy
	}
	if err := persistSecretStageRowsTx(ctx, tx, acct, meta.Name, meta.VersionStages); err != nil {
		return store.SecretMetadataRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return store.SecretMetadataRecord{}, err
	}
	return meta, nil
}

func (s *Store) ClaimSecretRotation(ctx context.Context, secretID, owner string, lease time.Duration) (bool, error) {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return false, err
	}
	// The lease is compared and set on the database clock, so replicas
	// with skewed clocks agree on it. The conditional UPDATE is atomic: of
	// several claimants exactly one sees a row.
	res, err := s.db.ExecContext(ctx, `
UPDATE sm_secret_rotations SET lease_owner = $3, lease_until = NOW() + make_interval(secs => $4)
WHERE account_id = $1 AND secret_name = $2 AND (lease_until IS NULL OR lease_until <= NOW())`,
		s.accountForContext(ctx), meta.Name, owner, lease.Seconds())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 0 {
		var exists bool
		if err := s.db.QueryRowContext(ctx, `SELECT TRUE FROM sm_secret_rotations WHERE account_id = $1 AND secret_name = $2`, s.accountForContext(ctx), meta.Name).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
			return false, store.ErrRotationNotConfigured
		}
	}
	return n == 1, nil
}

func (s *Store) SaveSecretRotationState(ctx context.Context, secretID, owner string, upd store.SecretRotationStateUpdate) error {
	acct := s.accountForContext(ctx)
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `
UPDATE sm_secret_rotations SET status = $4, last_step = $5, last_error = $6, attempts = $7, last_attempt_at = $8, next_attempt_at = $9,
	last_rotated_at = COALESCE($10, last_rotated_at),
	lease_owner = CASE WHEN $11 THEN lease_owner ELSE '' END,
	lease_until = CASE WHEN $11 THEN lease_until ELSE NULL END
WHERE account_id = $1 AND secret_name = $2 AND lease_owner = $3`,
		acct, meta.Name, owner, upd.Status, upd.LastStep, upd.LastError, upd.Attempts, upd.LastAttemptAt, upd.NextAttemptAt, upd.LastRotatedAt, upd.KeepLease)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return store.ErrRotationLeaseLost
	}
	if upd.NextRotationDate != nil {
		if _, err := tx.ExecContext(ctx, `UPDATE sm_secrets SET next_rotation_date = $3 WHERE account_id = $1 AND name = $2`, acct, meta.Name, *upd.NextRotationDate); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ReleaseSecretRotation(ctx context.Context, secretID, owner string) error {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE sm_secret_rotations SET lease_owner = '', lease_until = NULL WHERE account_id = $1 AND secret_name = $2 AND lease_owner = $3`,
		s.accountForContext(ctx), meta.Name, owner)
	return err
}

func (s *Store) ListDueSecretRotations(ctx context.Context, now time.Time, limit int) ([]store.DueSecretRotation, error) {
	if limit <= 0 {
		limit = 100
	}
	// Starts from the (small) rotation table and looks up each secret by
	// its primary key.
	rows, err := s.db.QueryContext(ctx, `
SELECT r.account_id, r.secret_name
FROM sm_secret_rotations r
JOIN sm_secrets s ON s.account_id = r.account_id AND s.name = r.secret_name
WHERE r.rotator_type <> '' AND s.rotation_enabled AND s.deleted_date IS NULL
  AND (r.lease_until IS NULL OR r.lease_until <= NOW())
  AND ((r.next_attempt_at IS NOT NULL AND r.next_attempt_at <= $1)
    OR (r.next_attempt_at IS NULL AND s.next_rotation_date IS NOT NULL AND s.next_rotation_date <= $1))
ORDER BY r.account_id, r.secret_name
LIMIT $2`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.DueSecretRotation
	for rows.Next() {
		var d store.DueSecretRotation
		if err := rows.Scan(&d.AccountID, &d.SecretName); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) AppendSecretRotationHistory(ctx context.Context, secretID string, e store.SecretRotationEvent) error {
	acct := s.accountForContext(ctx)
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO sm_secret_rotation_history (account_id, secret_name, token, rotator_type, trigger, status, step, error, actor, started_at, finished_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		acct, meta.Name, e.Token, e.RotatorType, e.Trigger, e.Status, e.Step, e.Error, e.Actor, e.StartedAt, e.FinishedAt); err != nil {
		return err
	}
	// Keep the newest MaxRotationHistory events.
	if _, err := tx.ExecContext(ctx, `
DELETE FROM sm_secret_rotation_history WHERE account_id = $1 AND secret_name = $2 AND id < (
	SELECT COALESCE(MIN(id), 0) FROM (SELECT id FROM sm_secret_rotation_history WHERE account_id = $1 AND secret_name = $2 ORDER BY id DESC LIMIT $3) newest)`,
		acct, meta.Name, store.MaxRotationHistory); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ListSecretRotationHistory(ctx context.Context, secretID string, limit int) ([]store.SecretRotationEvent, error) {
	meta, err := s.loadSecretMetadata(ctx, secretID)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > store.MaxRotationHistory {
		limit = store.MaxRotationHistory
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, token, rotator_type, trigger, status, step, error, actor, started_at, finished_at
FROM sm_secret_rotation_history WHERE account_id = $1 AND secret_name = $2 ORDER BY id DESC LIMIT $3`,
		s.accountForContext(ctx), meta.Name, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.SecretRotationEvent{}
	for rows.Next() {
		var e store.SecretRotationEvent
		if err := rows.Scan(&e.ID, &e.Token, &e.RotatorType, &e.Trigger, &e.Status, &e.Step, &e.Error, &e.Actor, &e.StartedAt, &e.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) ListSecretRotationSummaries(ctx context.Context) (map[string]store.SecretRotationSummary, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT secret_name, rotator_type, status FROM sm_secret_rotations WHERE account_id = $1`, s.accountForContext(ctx))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]store.SecretRotationSummary{}
	for rows.Next() {
		var name string
		var sum store.SecretRotationSummary
		if err := rows.Scan(&name, &sum.RotatorType, &sum.Status); err != nil {
			return nil, err
		}
		out[name] = sum
	}
	return out, rows.Err()
}
