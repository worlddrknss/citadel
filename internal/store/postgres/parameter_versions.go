package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// UpdateParameter implements store.ParameterVersionStore. The row is locked
// while its version is compared, so two concurrent edits of the same version
// cannot both succeed.
func (s *Store) UpdateParameter(ctx context.Context, rec store.ParameterRecord, expectedVersion int64) (store.ParameterRecord, error) {
	acct := s.accountForContext(ctx)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return store.ParameterRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var current int64
	err = tx.QueryRowContext(ctx,
		`SELECT version, created_at FROM ps_parameters WHERE account_id=$1 AND name=$2 FOR UPDATE`,
		acct, rec.Name).Scan(&current, &rec.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ParameterRecord{}, store.ErrParameterNotFound
	}
	if err != nil {
		return store.ParameterRecord{}, err
	}
	if current != expectedVersion {
		return store.ParameterRecord{}, store.ErrParameterVersionConflict
	}
	now := time.Now().UTC()
	rec.Version = current + 1
	rec.UpdatedAt = now
	if _, err := tx.ExecContext(ctx,
		`UPDATE ps_parameters SET param_type=$3, param_value=$4, is_encrypted=$5, kms_key_id=$6, tier=$7, version=$8, description=$9, updated_at=$10
		 WHERE account_id=$1 AND name=$2`,
		acct, rec.Name, rec.Type, rec.Value, rec.IsEncrypted, rec.KMSKeyID, rec.Tier, rec.Version, rec.Description, now); err != nil {
		return store.ParameterRecord{}, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO ps_parameter_history (account_id, name, version, param_type, param_value, is_encrypted, kms_key_id, tier, description, labels_json, modified_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'[]',$10)`,
		acct, rec.Name, rec.Version, rec.Type, rec.Value, rec.IsEncrypted, rec.KMSKeyID, rec.Tier, rec.Description, now); err != nil {
		return store.ParameterRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return store.ParameterRecord{}, err
	}
	return rec, nil
}

// UnlabelParameterVersion implements store.ParameterVersionStore.
func (s *Store) UnlabelParameterVersion(ctx context.Context, name string, version int64, labels []string) ([]string, error) {
	acct := s.accountForContext(ctx)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var raw string
	err = tx.QueryRowContext(ctx,
		`SELECT labels_json FROM ps_parameter_history WHERE account_id=$1 AND name=$2 AND version=$3 FOR UPDATE`,
		acct, name, version).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrParameterNotFound
	}
	if err != nil {
		return nil, err
	}
	var current []string
	_ = json.Unmarshal([]byte(raw), &current)
	removed := []string{}
	for _, l := range labels {
		if store.ContainsString(current, l) && !store.ContainsString(removed, l) {
			removed = append(removed, l)
			current = store.RemoveLabel(current, l)
		}
	}
	if current == nil {
		current = []string{}
	}
	out, _ := json.Marshal(current)
	if _, err := tx.ExecContext(ctx,
		`UPDATE ps_parameter_history SET labels_json=$4 WHERE account_id=$1 AND name=$2 AND version=$3`,
		acct, name, version, string(out)); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return removed, nil
}
