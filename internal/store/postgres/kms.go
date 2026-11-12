package postgres

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/arn"
	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

func (s *Store) ResolveByID(ctx context.Context, keyID string) (store.KMSKey, error) {
	if strings.HasPrefix(keyID, "alias/") {
		var target string
		if err := s.db.QueryRowContext(ctx, `SELECT target_key_id FROM kms_aliases WHERE alias_name = $1 AND account_id = $2`, keyID, s.accountForContext(ctx)).Scan(&target); err != nil {
			return store.KMSKey{}, err
		}
		keyID = target
	}
	const q = `
	SELECT id, arn, master_key_b64, wrapped_key_b64, key_nonce_b64, public_key_b64, key_usage, key_spec, description, enabled, deletion_date, created_at, managed
FROM kms_keys
WHERE id = $1
`
	query := q
	args := []any{keyID}
	if cond, extra := store.AccountFilter(ctx, "account_id", 2); cond != "" {
		query += " AND " + cond
		args = append(args, extra...)
	}
	var (
		k            store.KMSKey
		masterB64    string
		wrappedB64   string
		nonceB64     string
		publicB64    string
		keyUsage     string
		keySpec      string
		deletionDate sql.NullTime
	)
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&k.ID, &k.ARN, &masterB64, &wrappedB64, &nonceB64, &publicB64, &keyUsage, &keySpec, &k.Description, &k.Enabled, &deletionDate, &k.CreatedAt, &k.Managed)
	if err != nil {
		return store.KMSKey{}, err
	}
	if deletionDate.Valid {
		k.DeletionDate = &deletionDate.Time
	}
	k.KeyUsage = store.NormalizeKeyUsage(keyUsage)
	if k.KeyUsage == "" {
		k.KeyUsage = store.KeyUsageEncryptDecrypt
	}
	k.KeySpec = strings.ToUpper(strings.TrimSpace(keySpec))
	if k.KeySpec == "" {
		k.KeySpec = store.DefaultKeySpecForUsage(k.KeyUsage)
	}
	if publicB64 != "" {
		k.PublicKeyRaw, err = base64.StdEncoding.DecodeString(publicB64)
		if err != nil {
			return store.KMSKey{}, err
		}
	}
	k.MasterKeyRaw, err = s.resolveKeyMaterial(ctx, k.ID, masterB64, wrappedB64, nonceB64)
	if err != nil {
		return store.KMSKey{}, fmt.Errorf("load key material for %s: %w", k.ID, err)
	}
	return k, nil
}

func (s *Store) ResolveDefault(ctx context.Context) (store.KMSKey, error) {
	// Per-account immutable default: each account's alias/default points at its
	// managed default key. This is the authoritative resolution path.
	var aliasTarget string
	err := s.db.QueryRowContext(ctx,
		`SELECT target_key_id FROM kms_aliases WHERE alias_name = $1 AND account_id = $2`,
		store.ManagedDefaultAlias, s.accountForContext(ctx)).Scan(&aliasTarget)
	if err == nil {
		return s.ResolveByID(ctx, aliasTarget)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return store.KMSKey{}, err
	}

	// Legacy fallback for deployments not yet migrated to per-account defaults.
	const keyBySetting = `
SELECT setting_value
FROM kms_settings
WHERE setting_key = 'default_key_id'
`
	var keyID string
	err = s.db.QueryRowContext(ctx, keyBySetting).Scan(&keyID)
	if err == nil {
		return s.ResolveByID(ctx, keyID)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return store.KMSKey{}, err
	}

	fallback := `
SELECT id
FROM kms_keys
WHERE enabled = TRUE`
	var args []any
	if cond, extra := store.AccountFilter(ctx, "account_id", 1); cond != "" {
		fallback += "\nAND " + cond
		args = append(args, extra...)
	}
	fallback += "\nORDER BY created_at ASC\nLIMIT 1"
	err = s.db.QueryRowContext(ctx, fallback, args...).Scan(&keyID)
	if err != nil {
		return store.KMSKey{}, err
	}
	return s.ResolveByID(ctx, keyID)
}

func (s *Store) EnsureBootstrap(ctx context.Context, k store.KMSKey) error {
	wrappedB64, nonceB64, err := s.wrapKeyMaterial(k.ID, k.MasterKeyRaw)
	if err != nil {
		return fmt.Errorf("wrap bootstrap key material: %w", err)
	}
	const upsertKey = `
INSERT INTO kms_keys (id, arn, master_key_b64, wrapped_key_b64, key_nonce_b64, public_key_b64, key_usage, key_spec, description, enabled, created_at, account_id)
VALUES ($1, $2, '', $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (id) DO NOTHING
`
	if _, err := s.db.ExecContext(ctx, upsertKey, k.ID, k.ARN, wrappedB64, nonceB64, base64.StdEncoding.EncodeToString(k.PublicKeyRaw), k.KeyUsage, k.KeySpec, k.Description, k.Enabled, k.CreatedAt, s.accountForContext(ctx)); err != nil {
		return fmt.Errorf("bootstrap key row: %w", err)
	}

	const upsertDefault = `
INSERT INTO kms_settings (setting_key, setting_value)
VALUES ('default_key_id', $1)
ON CONFLICT (setting_key) DO NOTHING
`
	if _, err := s.db.ExecContext(ctx, upsertDefault, k.ID); err != nil {
		return fmt.Errorf("bootstrap default key setting: %w", err)
	}
	return nil
}

func (s *Store) CreateKey(ctx context.Context, description, keyUsage, keySpec string) (store.KMSKey, error) {
	raw, publicRaw, normalizedUsage, normalizedSpec, err := store.GenerateKeyMaterial(keyUsage, keySpec)
	if err != nil {
		return store.KMSKey{}, err
	}
	id := cryptoutil.RandomHex(12)
	k := store.KMSKey{
		ID:           id,
		ARN:          s.keyARNForCtx(ctx, id),
		MasterKeyRaw: raw,
		PublicKeyRaw: publicRaw,
		Description:  description,
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
		KeyUsage:     normalizedUsage,
		KeySpec:      normalizedSpec,
	}
	wrappedB64, nonceB64, err := s.wrapKeyMaterial(k.ID, k.MasterKeyRaw)
	if err != nil {
		return store.KMSKey{}, err
	}
	const q = `
INSERT INTO kms_keys (id, arn, master_key_b64, wrapped_key_b64, key_nonce_b64, public_key_b64, key_usage, key_spec, description, enabled, deletion_date, created_at, account_id)
VALUES ($1, $2, '', $3, $4, $5, $6, $7, $8, $9, NULL, $10, $11)
`
	if _, err := s.db.ExecContext(ctx, q, k.ID, k.ARN, wrappedB64, nonceB64, base64.StdEncoding.EncodeToString(publicRaw), k.KeyUsage, k.KeySpec, k.Description, k.Enabled, k.CreatedAt, s.accountForContext(ctx)); err != nil {
		return store.KMSKey{}, err
	}
	return k, nil
}

// ImportSigningKey persists externally supplied asymmetric key material as a
// SIGN_VERIFY key. The private key must be PKCS#8 DER and the public key PKIX
// DER; both are stored using the same wrapping path as generated keys.
func (s *Store) ImportSigningKey(ctx context.Context, description string, privPKCS8DER, pubPKIXDER []byte, keySpec string) (store.KMSKey, error) {
	normalizedSpec, err := store.NormalizeKeySpec(store.KeyUsageSignVerify, keySpec)
	if err != nil {
		return store.KMSKey{}, err
	}
	id := cryptoutil.RandomHex(12)
	k := store.KMSKey{
		ID:           id,
		ARN:          s.keyARNForCtx(ctx, id),
		MasterKeyRaw: privPKCS8DER,
		PublicKeyRaw: pubPKIXDER,
		Description:  description,
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
		KeyUsage:     store.KeyUsageSignVerify,
		KeySpec:      normalizedSpec,
	}
	wrappedB64, nonceB64, err := s.wrapKeyMaterial(k.ID, k.MasterKeyRaw)
	if err != nil {
		return store.KMSKey{}, err
	}
	const q = `
INSERT INTO kms_keys (id, arn, master_key_b64, wrapped_key_b64, key_nonce_b64, public_key_b64, key_usage, key_spec, description, enabled, deletion_date, created_at, account_id)
VALUES ($1, $2, '', $3, $4, $5, $6, $7, $8, $9, NULL, $10, $11)
`
	if _, err := s.db.ExecContext(ctx, q, k.ID, k.ARN, wrappedB64, nonceB64, base64.StdEncoding.EncodeToString(pubPKIXDER), k.KeyUsage, k.KeySpec, k.Description, k.Enabled, k.CreatedAt, s.accountForContext(ctx)); err != nil {
		return store.KMSKey{}, err
	}
	return k, nil
}

func (s *Store) ListKeys(ctx context.Context) ([]store.KMSKey, error) {
	q := `
	SELECT id, arn, master_key_b64, wrapped_key_b64, key_nonce_b64, public_key_b64, key_usage, key_spec, description, enabled, deletion_date, created_at, managed
FROM kms_keys`
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

	out := make([]store.KMSKey, 0)
	for rows.Next() {
		var (
			k            store.KMSKey
			masterB64    string
			wrappedB64   string
			nonceB64     string
			publicB64    string
			keyUsage     string
			keySpec      string
			deletionDate sql.NullTime
		)
		if err := rows.Scan(&k.ID, &k.ARN, &masterB64, &wrappedB64, &nonceB64, &publicB64, &keyUsage, &keySpec, &k.Description, &k.Enabled, &deletionDate, &k.CreatedAt, &k.Managed); err != nil {
			return nil, err
		}
		if deletionDate.Valid {
			k.DeletionDate = &deletionDate.Time
		}
		k.KeyUsage = store.NormalizeKeyUsage(keyUsage)
		if k.KeyUsage == "" {
			k.KeyUsage = store.KeyUsageEncryptDecrypt
		}
		k.KeySpec = strings.ToUpper(strings.TrimSpace(keySpec))
		if k.KeySpec == "" {
			k.KeySpec = store.DefaultKeySpecForUsage(k.KeyUsage)
		}
		if publicB64 != "" {
			k.PublicKeyRaw, err = base64.StdEncoding.DecodeString(publicB64)
			if err != nil {
				return nil, err
			}
		}
		k.MasterKeyRaw, err = s.resolveKeyMaterial(ctx, k.ID, masterB64, wrappedB64, nonceB64)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) GetKeyPolicy(ctx context.Context, keyID, policyName string) (string, error) {
	if policyName == "" {
		policyName = "default"
	}
	key, err := s.ResolveByID(ctx, keyID)
	if err != nil {
		return "", err
	}
	const q = `
SELECT policy_document
FROM kms_key_policies
WHERE key_id = $1 AND policy_name = $2
`
	var doc string
	err = s.db.QueryRowContext(ctx, q, key.ID, policyName).Scan(&doc)
	if errors.Is(err, sql.ErrNoRows) {
		return store.DefaultKeyPolicy(key), nil
	}
	if err != nil {
		return "", err
	}
	return doc, nil
}

func (s *Store) PutKeyPolicy(ctx context.Context, keyID, policyName, policyDocument string) error {
	if policyName == "" {
		policyName = "default"
	}
	key, err := s.ResolveByID(ctx, keyID)
	if err != nil {
		return err
	}
	const q = `
INSERT INTO kms_key_policies (key_id, policy_name, policy_document)
VALUES ($1, $2, $3)
ON CONFLICT (key_id, policy_name)
DO UPDATE SET policy_document = EXCLUDED.policy_document, updated_at = NOW()
`
	_, err = s.db.ExecContext(ctx, q, key.ID, policyName, policyDocument)
	return err
}

func (s *Store) CreateAlias(ctx context.Context, aliasName, keyID string) error {
	const q = `
INSERT INTO kms_aliases (alias_name, target_key_id, account_id)
VALUES ($1, $2, $3)
`
	_, err := s.db.ExecContext(ctx, q, aliasName, keyID, s.accountForContext(ctx))
	return err
}

func (s *Store) UpdateAlias(ctx context.Context, aliasName, keyID string) error {
	if aliasName == store.ManagedDefaultAlias {
		return store.ErrImmutableManagedKey
	}
	const q = `
UPDATE kms_aliases
SET target_key_id = $2, updated_at = NOW()
WHERE alias_name = $1
`
	res, err := s.db.ExecContext(ctx, q, aliasName, keyID)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) DeleteAlias(ctx context.Context, aliasName string) error {
	if aliasName == store.ManagedDefaultAlias {
		return store.ErrImmutableManagedKey
	}
	cond, args := store.AccountFilter(ctx, "account_id", 2)
	q := `DELETE FROM kms_aliases WHERE alias_name = $1`
	if cond != "" {
		q += " AND " + cond
	}
	res, err := s.db.ExecContext(ctx, q, append([]any{aliasName}, args...)...)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) ListAliases(ctx context.Context) ([]store.KMSAlias, error) {
	q := `
SELECT alias_name, target_key_id
FROM kms_aliases`
	cond, args := store.AccountFilter(ctx, "account_id", 1)
	if cond != "" {
		q += "\nWHERE " + cond
	}
	q += "\nORDER BY alias_name ASC"
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]store.KMSAlias, 0)
	for rows.Next() {
		var a store.KMSAlias
		if err := rows.Scan(&a.AliasName, &a.TargetKeyID); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) SetKeyEnabled(ctx context.Context, keyID string, enabled bool) error {
	if !enabled {
		if managed, err := s.keyManaged(ctx, keyID); err != nil {
			return err
		} else if managed {
			return store.ErrImmutableManagedKey
		}
	}
	const q = `UPDATE kms_keys SET enabled = $2, updated_at = NOW() WHERE id = $1`
	res, err := s.db.ExecContext(ctx, q, keyID, enabled)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) ScheduleKeyDeletion(ctx context.Context, keyID string, windowDays int) (time.Time, error) {
	if managed, err := s.keyManaged(ctx, keyID); err != nil {
		return time.Time{}, err
	} else if managed {
		return time.Time{}, store.ErrImmutableManagedKey
	}
	deletionDate := time.Now().UTC().Add(time.Duration(windowDays) * 24 * time.Hour)
	const q = `UPDATE kms_keys SET deletion_date = $2, updated_at = NOW() WHERE id = $1`
	res, err := s.db.ExecContext(ctx, q, keyID, deletionDate)
	if err != nil {
		return time.Time{}, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return time.Time{}, err
	}
	if rows == 0 {
		return time.Time{}, sql.ErrNoRows
	}
	return deletionDate, nil
}

func (s *Store) CancelKeyDeletion(ctx context.Context, keyID string) error {
	const q = `UPDATE kms_keys SET deletion_date = NULL, updated_at = NOW() WHERE id = $1`
	res, err := s.db.ExecContext(ctx, q, keyID)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) ForceDeleteKey(ctx context.Context, keyID string) error {
	if managed, err := s.keyManaged(ctx, keyID); err != nil {
		return err
	} else if managed {
		return store.ErrImmutableManagedKey
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM kms_aliases WHERE target_key_id = $1`, keyID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM kms_key_policies WHERE key_id = $1`, keyID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM kms_grants WHERE key_id = $1`, keyID); err != nil {
		return err
	}

	res, err := tx.ExecContext(ctx, `DELETE FROM kms_keys WHERE id = $1`, keyID)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "foreign key") {
			return fmt.Errorf("key is in use and cannot be force deleted")
		}
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}

	return tx.Commit()
}

func (s *Store) CreateGrant(ctx context.Context, req store.CreateGrantRequest) (store.KMSGrant, error) {
	grant := store.KMSGrant{
		GrantID:           "grant-" + cryptoutil.RandomHex(12),
		GrantToken:        cryptoutil.RandomHex(16),
		KeyID:             req.KeyID,
		GranteePrincipal:  strings.TrimSpace(req.GranteePrincipal),
		RetiringPrincipal: strings.TrimSpace(req.RetiringPrincipal),
		Operations:        append([]string(nil), req.Operations...),
		Name:              strings.TrimSpace(req.Name),
		CreatedAt:         time.Now().UTC(),
	}
	operationsJSON, err := json.Marshal(grant.Operations)
	if err != nil {
		return store.KMSGrant{}, err
	}
	const q = `
INSERT INTO kms_grants (grant_id, grant_token, key_id, grantee_principal, retiring_principal, operations_json, grant_name, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
`
	if _, err := s.db.ExecContext(ctx, q, grant.GrantID, grant.GrantToken, grant.KeyID, grant.GranteePrincipal, grant.RetiringPrincipal, string(operationsJSON), grant.Name, grant.CreatedAt); err != nil {
		return store.KMSGrant{}, err
	}
	return grant, nil
}

func (s *Store) ListGrants(ctx context.Context, keyID string) ([]store.KMSGrant, error) {
	const q = `
SELECT grant_id, grant_token, key_id, grantee_principal, retiring_principal, operations_json, grant_name, created_at
FROM kms_grants
WHERE key_id = $1
ORDER BY created_at ASC
`
	rows, err := s.db.QueryContext(ctx, q, keyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]store.KMSGrant, 0)
	for rows.Next() {
		var grant store.KMSGrant
		var operationsJSON string
		if err := rows.Scan(&grant.GrantID, &grant.GrantToken, &grant.KeyID, &grant.GranteePrincipal, &grant.RetiringPrincipal, &operationsJSON, &grant.Name, &grant.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(operationsJSON), &grant.Operations); err != nil {
			return nil, err
		}
		out = append(out, grant)
	}
	return out, rows.Err()
}

func (s *Store) RevokeGrant(ctx context.Context, keyID, grantID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM kms_grants WHERE key_id = $1 AND grant_id = $2`, keyID, grantID)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) RetireGrant(ctx context.Context, grantID, grantToken string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM kms_grants WHERE grant_id = $1 OR grant_token = $2`, grantID, grantToken)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) resolveKeyMaterial(ctx context.Context, keyID, masterB64, wrappedB64, nonceB64 string) ([]byte, error) {
	if strings.TrimSpace(wrappedB64) != "" && strings.TrimSpace(nonceB64) != "" {
		return s.unwrapKeyMaterial(keyID, wrappedB64, nonceB64)
	}
	if strings.TrimSpace(masterB64) == "" {
		return nil, errors.New("missing key material")
	}
	raw, err := base64.StdEncoding.DecodeString(masterB64)
	if err != nil {
		return nil, err
	}
	wrapped, nonce, err := s.wrapKeyMaterial(keyID, raw)
	if err != nil {
		return nil, err
	}
	if err := s.persistWrappedKeyMaterial(ctx, keyID, wrapped, nonce); err != nil {
		log.Printf("key migration warning key=%s: %v", keyID, err)
	}
	return raw, nil
}

func (s *Store) wrapKeyMaterial(keyID string, raw []byte) (string, string, error) {
	if len(s.wrappingKey) != 32 {
		return "", "", errors.New("wrapping key is not configured")
	}
	// Bind the key ID as additional authenticated data so a wrapped blob cannot
	// be transplanted onto a different key row.
	sealed, err := cryptoutil.GCMSeal(s.wrappingKey, raw, []byte(keyID))
	if err != nil {
		return "", "", err
	}
	// Stored as separate ciphertext and nonce columns, as before.
	nonce, wrapped := sealed[:cryptoutil.GCMNonceSize], sealed[cryptoutil.GCMNonceSize:]
	return base64.StdEncoding.EncodeToString(wrapped), base64.StdEncoding.EncodeToString(nonce), nil
}

func (s *Store) unwrapKeyMaterial(keyID, wrappedB64, nonceB64 string) ([]byte, error) {
	if len(s.wrappingKey) != 32 {
		return nil, errors.New("wrapping key is not configured")
	}
	wrapped, err := base64.StdEncoding.DecodeString(wrappedB64)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, err
	}
	// Try the current key with AAD, then legacy combinations so material wrapped
	// before AAD binding / the HKDF derivation upgrade still decrypts.
	candidates := []struct {
		key []byte
		aad []byte
	}{
		{s.wrappingKey, []byte(keyID)},
		{s.wrappingKey, nil},
	}
	if len(s.legacyWrappingKey) == 32 {
		candidates = append(candidates,
			struct {
				key []byte
				aad []byte
			}{s.legacyWrappingKey, []byte(keyID)},
			struct {
				key []byte
				aad []byte
			}{s.legacyWrappingKey, nil},
		)
	}
	blob := append(append(make([]byte, 0, len(nonce)+len(wrapped)), nonce...), wrapped...)
	var lastErr error
	for _, c := range candidates {
		if out, err := cryptoutil.GCMOpen(c.key, blob, c.aad); err == nil {
			return out, nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("unwrap failed")
	}
	return nil, lastErr
}

func (s *Store) persistWrappedKeyMaterial(ctx context.Context, keyID, wrappedB64, nonceB64 string) error {
	const q = `
UPDATE kms_keys
SET wrapped_key_b64 = $2, key_nonce_b64 = $3, master_key_b64 = '', updated_at = NOW()
WHERE id = $1
`
	_, err := s.db.ExecContext(ctx, q, keyID, wrappedB64, nonceB64)
	return err
}

func (s *Store) migrateLegacyKeyMaterial(ctx context.Context) error {
	const q = `
SELECT id, master_key_b64
FROM kms_keys
WHERE master_key_b64 <> '' AND wrapped_key_b64 = '' AND key_nonce_b64 = ''
`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return err
	}
	defer rows.Close()

	type row struct {
		id        string
		masterB64 string
	}
	legacy := make([]row, 0)
	for rows.Next() {
		var item row
		if err := rows.Scan(&item.id, &item.masterB64); err != nil {
			return err
		}
		legacy = append(legacy, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, item := range legacy {
		raw, err := base64.StdEncoding.DecodeString(item.masterB64)
		if err != nil {
			return fmt.Errorf("decode legacy key %s: %w", item.id, err)
		}
		wrapped, nonce, err := s.wrapKeyMaterial(item.id, raw)
		if err != nil {
			return fmt.Errorf("wrap legacy key %s: %w", item.id, err)
		}
		if err := s.persistWrappedKeyMaterial(ctx, item.id, wrapped, nonce); err != nil {
			return fmt.Errorf("persist wrapped key %s: %w", item.id, err)
		}
	}

	if len(legacy) > 0 {
		log.Printf("migrated %d legacy key rows to wrapped storage", len(legacy))
	}
	return nil
}

// keyManaged reports whether the key identified by keyID is a managed (immutable)
// key. A missing key reports false so callers surface their own not-found error.
func (s *Store) keyManaged(ctx context.Context, keyID string) (bool, error) {
	var managed bool
	err := s.db.QueryRowContext(ctx, `SELECT managed FROM kms_keys WHERE id = $1`, keyID).Scan(&managed)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return managed, nil
}

// EnsureAccountDefaultKey guarantees that accountID owns an immutable managed
// default key reachable via the per-account alias/default. It is idempotent: if
// the alias already exists the existing key is returned unchanged.
//
// When the deployment's legacy global default_key_id setting points at a key
// already owned by accountID, that key is adopted as the managed default
// (preserving existing ciphertext) instead of minting a new one. This makes the
// pre-existing deployment default the root account's managed default on upgrade.
func (s *Store) EnsureAccountDefaultKey(ctx context.Context, accountID string) (store.KMSKey, error) {
	accountID = strings.TrimSpace(accountID)
	if !arn.IsValidAccountID(accountID) {
		return store.KMSKey{}, fmt.Errorf("invalid account id %q", accountID)
	}

	// Fast path: alias/default already exists for this account.
	var existingKeyID string
	err := s.db.QueryRowContext(ctx,
		`SELECT target_key_id FROM kms_aliases WHERE alias_name = $1 AND account_id = $2`,
		store.ManagedDefaultAlias, accountID).Scan(&existingKeyID)
	if err == nil {
		return s.resolveByIDForAccount(ctx, existingKeyID, accountID)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return store.KMSKey{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return store.KMSKey{}, err
	}
	defer tx.Rollback()

	// Re-check inside the transaction to avoid a race that would create a
	// duplicate alias/default for the same account.
	if e := tx.QueryRowContext(ctx,
		`SELECT target_key_id FROM kms_aliases WHERE alias_name = $1 AND account_id = $2 FOR UPDATE`,
		store.ManagedDefaultAlias, accountID).Scan(&existingKeyID); e == nil {
		if ce := tx.Commit(); ce != nil {
			return store.KMSKey{}, ce
		}
		return s.resolveByIDForAccount(ctx, existingKeyID, accountID)
	} else if !errors.Is(e, sql.ErrNoRows) {
		return store.KMSKey{}, e
	}

	// Adopt the legacy global default key when it belongs to this account and is
	// a symmetric encryption key.
	keyID := ""
	var adoptID string
	if e := tx.QueryRowContext(ctx,
		`SELECT setting_value FROM kms_settings WHERE setting_key = 'default_key_id'`).Scan(&adoptID); e == nil {
		adoptID = strings.TrimSpace(adoptID)
		if adoptID != "" {
			var owned bool
			if e2 := tx.QueryRowContext(ctx,
				`SELECT TRUE FROM kms_keys WHERE id = $1 AND account_id = $2 AND key_usage = $3`,
				adoptID, accountID, store.KeyUsageEncryptDecrypt).Scan(&owned); e2 == nil && owned {
				keyID = adoptID
			} else if e2 != nil && !errors.Is(e2, sql.ErrNoRows) {
				return store.KMSKey{}, e2
			}
		}
	} else if !errors.Is(e, sql.ErrNoRows) {
		return store.KMSKey{}, e
	}

	region, _ := s.DeploymentIdentity()

	if keyID == "" {
		// Mint a fresh symmetric encryption key owned by this account.
		raw, _, usage, spec, gerr := store.GenerateKeyMaterial(store.KeyUsageEncryptDecrypt, store.KeySpecSymmetricDefault)
		if gerr != nil {
			return store.KMSKey{}, gerr
		}
		keyID = cryptoutil.RandomHex(12)
		wrappedB64, nonceB64, werr := s.wrapKeyMaterial(keyID, raw)
		if werr != nil {
			return store.KMSKey{}, werr
		}
		arn := arn.Build("kms", region, accountID, "key/"+keyID)
		if _, e := tx.ExecContext(ctx,
			`INSERT INTO kms_keys (id, arn, master_key_b64, wrapped_key_b64, key_nonce_b64, public_key_b64, key_usage, key_spec, description, enabled, managed, deletion_date, created_at, account_id)
			 VALUES ($1, $2, '', $3, $4, '', $5, $6, $7, TRUE, TRUE, NULL, $8, $9)`,
			keyID, arn, wrappedB64, nonceB64, usage, spec,
			"default", time.Now().UTC(), accountID); e != nil {
			return store.KMSKey{}, e
		}
	} else {
		// Promote the adopted key to a managed, enabled, non-deleting state.
		if _, e := tx.ExecContext(ctx,
			`UPDATE kms_keys SET managed = TRUE, enabled = TRUE, deletion_date = NULL, description = 'default', updated_at = NOW() WHERE id = $1 AND account_id = $2`,
			keyID, accountID); e != nil {
			return store.KMSKey{}, e
		}
	}

	if _, e := tx.ExecContext(ctx,
		`INSERT INTO kms_aliases (alias_name, target_key_id, account_id) VALUES ($1, $2, $3)`,
		store.ManagedDefaultAlias, keyID, accountID); e != nil {
		return store.KMSKey{}, e
	}

	if e := tx.Commit(); e != nil {
		return store.KMSKey{}, e
	}
	return s.resolveByIDForAccount(ctx, keyID, accountID)
}

// resolveByIDForAccount loads a key scoped to an explicit account, independent of
// any caller account already present in ctx. Used when provisioning keys for an
// account other than the authenticated caller (e.g. account creation, backfill).
func (s *Store) resolveByIDForAccount(ctx context.Context, keyID, accountID string) (store.KMSKey, error) {
	return s.ResolveByID(store.WithCallerAccount(ctx, accountID), keyID)
}

// EnsureManagedDefaultKeys provisions the immutable per-account default key
// for every account in ui_accounts plus the deployment account. It is
// idempotent.
func (s *Store) EnsureManagedDefaultKeys(ctx context.Context) error {
	ids := map[string]struct{}{}
	rows, err := s.db.QueryContext(ctx, `SELECT account_id FROM ui_accounts`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id string
		if scanErr := rows.Scan(&id); scanErr != nil {
			rows.Close()
			return scanErr
		}
		if id = strings.TrimSpace(id); arn.IsValidAccountID(id) {
			ids[id] = struct{}{}
		}
	}
	if cerr := rows.Err(); cerr != nil {
		rows.Close()
		return cerr
	}
	rows.Close()

	// Always include the deployment/root account so single-tenant deployments
	// get a managed default even before any ui_accounts rows exist.
	if _, dep := s.DeploymentIdentity(); arn.IsValidAccountID(dep) && dep != arn.PlaceholderAccountID {
		ids[dep] = struct{}{}
	}

	var firstErr error
	for id := range ids {
		if _, e := s.EnsureAccountDefaultKey(ctx, id); e != nil {
			log.Printf("warning: ensure default key for account %s: %v", id, e)
			if firstErr == nil {
				firstErr = e
			}
		}
	}
	return firstErr
}
