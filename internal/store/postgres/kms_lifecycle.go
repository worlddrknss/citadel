package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// KMS key lifecycle: rotation, tags, usage counts and scheduled deletion.
// Everything keyed by a key ID is confined to the caller account on ctx.

func (s *Store) SetKeyRotation(ctx context.Context, keyID string, enabled bool, periodDays int) (store.KMSKey, error) {
	key, err := s.ResolveByID(ctx, keyID)
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
	var next *time.Time
	if enabled {
		t := now.Add(time.Duration(periodDays) * 24 * time.Hour)
		// Changing the period of an already-enabled schedule moves the next
		// rotation by the difference rather than restarting the clock.
		if key.RotationEnabled && key.NextRotationAt != nil && key.RotationPeriodDays > 0 {
			t = key.NextRotationAt.Add(time.Duration(periodDays-key.RotationPeriodDays) * 24 * time.Hour)
			if t.Before(now) {
				t = now
			}
		}
		next = &t
	}
	if err := s.execScoped(ctx,
		`UPDATE kms_keys SET rotation_enabled = $2, rotation_period_days = $3, next_rotation_at = $4, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL`,
		"account_id", key.ID, enabled, periodDays, nullTime(next)); err != nil {
		return store.KMSKey{}, err
	}
	return s.ResolveByID(ctx, key.ID)
}

func nullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

func (s *Store) RotateKeyMaterial(ctx context.Context, keyID, kind string, now time.Time) (store.KeyRotation, error) {
	if kind != store.RotationKindAutomatic && kind != store.RotationKindOnDemand {
		return store.KeyRotation{}, errors.New("invalid rotation kind")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return store.KeyRotation{}, err
	}
	defer tx.Rollback()

	q := `SELECT account_id, key_usage, key_spec, enabled, deletion_date, rotation_enabled, rotation_period_days, next_rotation_at
FROM kms_keys WHERE id = $1 AND deleted_at IS NULL`
	args := []any{keyID}
	if cond, extra := store.AccountFilter(ctx, "account_id", 2); cond != "" {
		q += " AND " + cond
		args = append(args, extra...)
	}
	var (
		accountID       string
		usage, spec     string
		enabled         bool
		deletionDate    sql.NullTime
		rotationEnabled bool
		periodDays      int
		next            sql.NullTime
	)
	if err := tx.QueryRowContext(ctx, q+" FOR UPDATE", args...).Scan(&accountID, &usage, &spec, &enabled, &deletionDate, &rotationEnabled, &periodDays, &next); err != nil {
		return store.KeyRotation{}, err
	}
	if !(store.KMSKey{KeyUsage: usage, KeySpec: spec}).IsSymmetric() {
		return store.KeyRotation{}, store.ErrRotationUnsupported
	}
	if !enabled || deletionDate.Valid {
		return store.KeyRotation{}, store.ErrKeyNotUsable
	}
	switch kind {
	case store.RotationKindAutomatic:
		if !rotationEnabled || !next.Valid || next.Time.After(now) {
			return store.KeyRotation{}, store.ErrRotationNotDue
		}
	case store.RotationKindOnDemand:
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM kms_key_materials WHERE key_id = $1 AND kind = $2`, keyID, store.RotationKindOnDemand).Scan(&n); err != nil {
			return store.KeyRotation{}, err
		}
		if n >= store.MaxOnDemandRotations {
			return store.KeyRotation{}, store.ErrRotationLimit
		}
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return store.KeyRotation{}, err
	}
	materialID := cryptoutil.RandomHex(16)
	wrapped, nonce, err := s.wrapKeyMaterial(materialAAD(keyID, materialID), raw)
	if err != nil {
		return store.KeyRotation{}, err
	}
	rotatedAt := now.UTC()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO kms_key_materials (key_id, material_id, account_id, wrapped_b64, nonce_b64, kind, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		keyID, materialID, accountID, wrapped, nonce, kind, rotatedAt); err != nil {
		return store.KeyRotation{}, err
	}
	if kind == store.RotationKindAutomatic {
		if periodDays <= 0 {
			periodDays = store.DefaultRotationPeriodDays
		}
		nextAt := rotatedAt.Add(time.Duration(periodDays) * 24 * time.Hour)
		_, err = tx.ExecContext(ctx, `UPDATE kms_keys SET current_material_id = $2, next_rotation_at = $3, updated_at = NOW() WHERE id = $1`, keyID, materialID, nextAt)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE kms_keys SET current_material_id = $2, updated_at = NOW() WHERE id = $1`, keyID, materialID)
	}
	if err != nil {
		return store.KeyRotation{}, err
	}
	if err := tx.Commit(); err != nil {
		return store.KeyRotation{}, err
	}
	return store.KeyRotation{KeyID: keyID, MaterialID: materialID, Kind: kind, RotatedAt: rotatedAt}, nil
}

func (s *Store) ListKeyRotations(ctx context.Context, keyID string) ([]store.KeyRotation, error) {
	q := `SELECT key_id, material_id, kind, created_at FROM kms_key_materials WHERE key_id = $1`
	args := []any{keyID}
	if cond, extra := store.AccountFilter(ctx, "account_id", 2); cond != "" {
		q += " AND " + cond
		args = append(args, extra...)
	}
	rows, err := s.db.QueryContext(ctx, q+" ORDER BY created_at DESC, material_id DESC", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]store.KeyRotation, 0)
	for rows.Next() {
		var r store.KeyRotation
		if err := rows.Scan(&r.KeyID, &r.MaterialID, &r.Kind, &r.RotatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) listKeyRefs(ctx context.Context, where string, now time.Time) ([]store.KeyRef, error) {
	q := `SELECT id, COALESCE(account_id, '') FROM kms_keys WHERE ` + where
	args := []any{now}
	if cond, extra := store.AccountFilter(ctx, "account_id", 2); cond != "" {
		q += " AND " + cond
		args = append(args, extra...)
	}
	rows, err := s.db.QueryContext(ctx, q+" ORDER BY id", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]store.KeyRef, 0)
	for rows.Next() {
		var r store.KeyRef
		if err := rows.Scan(&r.KeyID, &r.AccountID); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) ListKeysDueForRotation(ctx context.Context, now time.Time) ([]store.KeyRef, error) {
	return s.listKeyRefs(ctx, `rotation_enabled AND next_rotation_at <= $1 AND enabled AND deletion_date IS NULL AND deleted_at IS NULL`, now)
}

func (s *Store) ListKeysPendingDeletion(ctx context.Context, now time.Time) ([]store.KeyRef, error) {
	return s.listKeyRefs(ctx, `deletion_date <= $1 AND deleted_at IS NULL AND managed = FALSE`, now)
}

func (s *Store) DestroyKey(ctx context.Context, keyID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	q := `SELECT managed FROM kms_keys WHERE id = $1 AND deleted_at IS NULL`
	args := []any{keyID}
	if cond, extra := store.AccountFilter(ctx, "account_id", 2); cond != "" {
		q += " AND " + cond
		args = append(args, extra...)
	}
	var managed bool
	if err := tx.QueryRowContext(ctx, q+" FOR UPDATE", args...).Scan(&managed); err != nil {
		return err
	}
	if managed {
		return store.ErrImmutableManagedKey
	}
	for _, stmt := range []string{
		`DELETE FROM kms_aliases WHERE target_key_id = $1`,
		`DELETE FROM kms_key_policies WHERE key_id = $1`,
		`DELETE FROM kms_grants WHERE key_id = $1`,
		`DELETE FROM kms_key_tags WHERE key_id = $1`,
		`DELETE FROM kms_key_materials WHERE key_id = $1`,
	} {
		if _, err := tx.ExecContext(ctx, stmt, keyID); err != nil {
			return err
		}
	}
	// Wipe every copy of the material and leave a tombstone. The row stays so
	// the key ID is never reissued and rows that reference it (secrets,
	// certificate authorities) keep satisfying their foreign keys; they just
	// can no longer be decrypted, as with a deleted AWS KMS key.
	if _, err := tx.ExecContext(ctx, `
UPDATE kms_keys SET master_key_b64 = '', wrapped_key_b64 = '', key_nonce_b64 = '', public_key_b64 = '',
	current_material_id = '', rotation_enabled = FALSE, next_rotation_at = NULL, enabled = FALSE,
	deleted_at = NOW(), updated_at = NOW()
WHERE id = $1`, keyID); err != nil {
		return err
	}
	return tx.Commit()
}

// keyLive checks that keyID is a live key in the caller's account.
func (s *Store) keyLive(ctx context.Context, keyID string) (string, error) {
	q := `SELECT COALESCE(account_id, '') FROM kms_keys WHERE id = $1 AND deleted_at IS NULL`
	args := []any{keyID}
	if cond, extra := store.AccountFilter(ctx, "account_id", 2); cond != "" {
		q += " AND " + cond
		args = append(args, extra...)
	}
	var acct string
	err := s.db.QueryRowContext(ctx, q, args...).Scan(&acct)
	return acct, err
}

func (s *Store) TagKey(ctx context.Context, keyID string, tags []store.KMSTag) error {
	tags, err := store.NormalizeTags(tags)
	if err != nil {
		return err
	}
	acct, err := s.keyLive(ctx, keyID)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, t := range tags {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO kms_key_tags (key_id, account_id, tag_key, tag_value) VALUES ($1, $2, $3, $4)
ON CONFLICT (key_id, tag_key) DO UPDATE SET tag_value = EXCLUDED.tag_value, updated_at = NOW()`,
			keyID, acct, t.Key, t.Value); err != nil {
			return err
		}
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM kms_key_tags WHERE key_id = $1`, keyID).Scan(&n); err != nil {
		return err
	}
	if n > store.MaxKeyTags {
		return fmt.Errorf("%w: at most 50 tags per key", store.ErrInvalidTags)
	}
	return tx.Commit()
}

func (s *Store) UntagKey(ctx context.Context, keyID string, tagKeys []string) error {
	if _, err := s.keyLive(ctx, keyID); err != nil {
		return err
	}
	q := `DELETE FROM kms_key_tags WHERE key_id = $1 AND tag_key = ANY($2)`
	args := []any{keyID, pq.Array(tagKeys)}
	if cond, extra := store.AccountFilter(ctx, "account_id", 3); cond != "" {
		q += " AND " + cond
		args = append(args, extra...)
	}
	_, err := s.db.ExecContext(ctx, q, args...)
	return err
}

func (s *Store) ListKeyTags(ctx context.Context, keyID string) ([]store.KMSTag, error) {
	q := `SELECT tag_key, tag_value FROM kms_key_tags WHERE key_id = $1`
	args := []any{keyID}
	if cond, extra := store.AccountFilter(ctx, "account_id", 2); cond != "" {
		q += " AND " + cond
		args = append(args, extra...)
	}
	rows, err := s.db.QueryContext(ctx, q+" ORDER BY tag_key", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]store.KMSTag, 0)
	for rows.Next() {
		var t store.KMSTag
		if err := rows.Scan(&t.Key, &t.Value); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CountKeyUsage counts live secrets and SecureString parameters that name
// the key by ID, ARN or one of its aliases.
func (s *Store) CountKeyUsage(ctx context.Context, key store.KMSKey) (store.KeyUsageCounts, error) {
	refs := []string{key.ID}
	if key.ARN != "" {
		refs = append(refs, key.ARN)
	}
	if aliases, err := s.ListAliases(ctx); err == nil {
		for _, a := range aliases {
			if a.TargetKeyID == key.ID {
				refs = append(refs, a.AliasName)
			}
		}
	} else {
		return store.KeyUsageCounts{}, err
	}
	var out store.KeyUsageCounts
	q := `SELECT COUNT(*) FROM sm_secrets WHERE kms_key_id = ANY($1) AND deleted_date IS NULL`
	args := []any{pq.Array(refs)}
	if cond, extra := store.AccountFilter(ctx, "account_id", 2); cond != "" {
		q += " AND " + cond
		args = append(args, extra...)
	}
	if err := s.db.QueryRowContext(ctx, q, args...).Scan(&out.Secrets); err != nil {
		return store.KeyUsageCounts{}, err
	}
	q = `SELECT COUNT(*) FROM ps_parameters WHERE kms_key_id = ANY($1) AND param_type = 'SecureString'`
	if cond, extra := store.AccountFilter(ctx, "account_id", 2); cond != "" {
		q += " AND " + cond
		args = []any{pq.Array(refs), extra[0]}
	}
	if err := s.db.QueryRowContext(ctx, q, args...).Scan(&out.Parameters); err != nil {
		return store.KeyUsageCounts{}, err
	}
	return out, nil
}
