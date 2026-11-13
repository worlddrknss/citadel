package postgres

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/worlddrknss/citadel/internal/store"
)

// Cursor pagination for the AWS list APIs. Ordering uses the "C" collation
// so it is byte-wise and matches the memory store and the cursor comparison.

var _ store.AWSPageStore = (*Store)(nil)

func pageLimit(limit int) int {
	if limit <= 0 {
		return 100
	}
	return limit
}

// sqlArgs accumulates positional arguments.
type sqlArgs []any

func (a *sqlArgs) add(v any) string {
	*a = append(*a, v)
	return fmt.Sprintf("$%d", len(*a))
}

// accountCond restricts a query to the caller's account, or the deployment
// account when the request carries none. It never leaves a list unscoped:
// that would return every tenant's rows.
func (s *Store) accountCond(ctx context.Context, column string, args *sqlArgs) string {
	return " AND " + column + " = " + args.add(s.accountForContext(ctx))
}

func (s *Store) ListKeysPage(ctx context.Context, after string, limit int) ([]store.KMSKey, bool, error) {
	limit = pageLimit(limit)
	var args sqlArgs
	q := `SELECT id, arn, public_key_b64, key_usage, key_spec, description, enabled, deletion_date, created_at, managed
FROM kms_keys WHERE id COLLATE "C" > ` + args.add(after)
	q += s.accountCond(ctx, "account_id", &args)
	q += ` ORDER BY id COLLATE "C" LIMIT ` + args.add(limit+1)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := make([]store.KMSKey, 0, limit)
	for rows.Next() {
		var (
			k            store.KMSKey
			publicB64    string
			keyUsage     string
			keySpec      string
			deletionDate sql.NullTime
		)
		if err := rows.Scan(&k.ID, &k.ARN, &publicB64, &keyUsage, &keySpec, &k.Description, &k.Enabled, &deletionDate, &k.CreatedAt, &k.Managed); err != nil {
			return nil, false, err
		}
		if deletionDate.Valid {
			k.DeletionDate = &deletionDate.Time
		}
		k.KeyUsage = store.NormalizeKeyUsage(keyUsage)
		k.KeySpec = strings.ToUpper(strings.TrimSpace(keySpec))
		if k.KeySpec == "" {
			k.KeySpec = store.DefaultKeySpecForUsage(k.KeyUsage)
		}
		if publicB64 != "" {
			if k.PublicKeyRaw, err = base64.StdEncoding.DecodeString(publicB64); err != nil {
				return nil, false, err
			}
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if len(out) > limit {
		return out[:limit], true, nil
	}
	return out, false, nil
}

func (s *Store) ListAliasesPage(ctx context.Context, q store.AliasPageQuery) ([]store.KMSAlias, bool, error) {
	limit := pageLimit(q.Limit)
	var args sqlArgs
	query := `SELECT alias_name, target_key_id FROM kms_aliases WHERE alias_name COLLATE "C" > ` + args.add(q.After)
	if q.TargetKeyID != "" {
		query += ` AND target_key_id = ` + args.add(q.TargetKeyID)
	}
	query += s.accountCond(ctx, "account_id", &args)
	query += ` ORDER BY alias_name COLLATE "C" LIMIT ` + args.add(limit+1)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := make([]store.KMSAlias, 0, limit)
	for rows.Next() {
		var a store.KMSAlias
		if err := rows.Scan(&a.AliasName, &a.TargetKeyID); err != nil {
			return nil, false, err
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if len(out) > limit {
		return out[:limit], true, nil
	}
	return out, false, nil
}

func (s *Store) ListSecretsPage(ctx context.Context, q store.SecretPageQuery) ([]store.SecretMetadataRecord, bool, error) {
	limit := pageLimit(q.Limit)
	var args sqlArgs
	query := `SELECT name, arn, description, kms_key_id, current_version_id, previous_version_id, rotation_enabled, rotation_lambda_arn, rotation_days, next_rotation_date, deleted_date, created_at, updated_at
FROM sm_secrets WHERE `
	order := ` ORDER BY name COLLATE "C"`
	if q.Descending {
		order += ` DESC`
		if q.After != "" {
			query += `name COLLATE "C" < ` + args.add(q.After)
		} else {
			query += `TRUE`
		}
	} else {
		query += `name COLLATE "C" > ` + args.add(q.After)
	}
	if !q.IncludeDeleted {
		query += ` AND deleted_date IS NULL`
	}
	query += s.accountCond(ctx, "account_id", &args)
	query += order + ` LIMIT ` + args.add(limit+1)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, false, err
	}
	out := make([]store.SecretMetadataRecord, 0, limit)
	for rows.Next() {
		var (
			item        store.SecretMetadataRecord
			nextRotate  sql.NullTime
			deletedDate sql.NullTime
		)
		if err := rows.Scan(&item.Name, &item.ARN, &item.Description, &item.KMSKeyID, &item.CurrentVersionID, &item.PreviousVersionID, &item.RotationEnabled, &item.RotationLambdaARN, &item.RotationDays, &nextRotate, &deletedDate, &item.CreatedAt, &item.LastChangedDate); err != nil {
			rows.Close()
			return nil, false, err
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
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, false, err
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	// Tags feed the tag-key / tag-value / all filters; one query per page.
	for i := range out {
		tags, err := s.loadSecretTags(ctx, s.accountForContext(ctx), out[i].Name)
		if err != nil {
			return nil, false, err
		}
		out[i].Tags = tags
	}
	return out, more, nil
}

func (s *Store) ListParametersPage(ctx context.Context, q store.ParameterPageQuery) ([]store.ParameterRecord, bool, error) {
	limit := pageLimit(q.Limit)
	prefix := store.ParameterPathPrefix(q.Path)
	var args sqlArgs
	p := args.add(prefix)
	query := `SELECT name, param_type, param_value, is_encrypted, kms_key_id, tier, version, description, created_at, updated_at
FROM ps_parameters WHERE starts_with(name, ` + p + `) AND length(name) > length(` + p + `) AND name COLLATE "C" > ` + args.add(q.After)
	if !q.Recursive {
		query += ` AND strpos(substr(name, length(` + p + `) + 1), '/') = 0`
	}
	query += s.accountCond(ctx, "account_id", &args)
	query += ` ORDER BY name COLLATE "C" LIMIT ` + args.add(limit+1)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := make([]store.ParameterRecord, 0, limit)
	for rows.Next() {
		var rec store.ParameterRecord
		if err := rows.Scan(&rec.Name, &rec.Type, &rec.Value, &rec.IsEncrypted, &rec.KMSKeyID, &rec.Tier, &rec.Version, &rec.Description, &rec.CreatedAt, &rec.UpdatedAt); err != nil {
			return nil, false, err
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if len(out) > limit {
		return out[:limit], true, nil
	}
	return out, false, nil
}
