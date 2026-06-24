package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

// managedDefaultAlias is the per-account alias that always resolves to that
// account's immutable, system-provisioned default encryption key. Every account
// owns exactly one such alias; it cannot be deleted, re-pointed, or created by
// callers.
const managedDefaultAlias = "alias/default"

// errImmutableManagedKey is returned when an operation would disable, delete, or
// re-alias an account's managed default key (or its alias/default alias).
var errImmutableManagedKey = errors.New("the account default key is immutable: it cannot be disabled, deleted, or re-aliased")

// keyManaged reports whether the key identified by keyID is a managed (immutable)
// key. A missing key reports false so callers surface their own not-found error.
func (s *dbStore) keyManaged(ctx context.Context, keyID string) (bool, error) {
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
func (s *dbStore) EnsureAccountDefaultKey(ctx context.Context, accountID string) (kmsKey, error) {
	accountID = strings.TrimSpace(accountID)
	if !isValidAccountID(accountID) {
		return kmsKey{}, fmt.Errorf("invalid account id %q", accountID)
	}

	// Fast path: alias/default already exists for this account.
	var existingKeyID string
	err := s.db.QueryRowContext(ctx,
		`SELECT target_key_id FROM kms_aliases WHERE alias_name = $1 AND account_id = $2`,
		managedDefaultAlias, accountID).Scan(&existingKeyID)
	if err == nil {
		return s.resolveByIDForAccount(ctx, existingKeyID, accountID)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return kmsKey{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return kmsKey{}, err
	}
	defer tx.Rollback()

	// Re-check inside the transaction to avoid a race that would create a
	// duplicate alias/default for the same account.
	if e := tx.QueryRowContext(ctx,
		`SELECT target_key_id FROM kms_aliases WHERE alias_name = $1 AND account_id = $2 FOR UPDATE`,
		managedDefaultAlias, accountID).Scan(&existingKeyID); e == nil {
		if ce := tx.Commit(); ce != nil {
			return kmsKey{}, ce
		}
		return s.resolveByIDForAccount(ctx, existingKeyID, accountID)
	} else if !errors.Is(e, sql.ErrNoRows) {
		return kmsKey{}, e
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
				adoptID, accountID, keyUsageEncryptDecrypt).Scan(&owned); e2 == nil && owned {
				keyID = adoptID
			} else if e2 != nil && !errors.Is(e2, sql.ErrNoRows) {
				return kmsKey{}, e2
			}
		}
	} else if !errors.Is(e, sql.ErrNoRows) {
		return kmsKey{}, e
	}

	region, _ := s.DeploymentIdentity()

	if keyID == "" {
		// Mint a fresh symmetric encryption key owned by this account.
		raw, _, usage, spec, gerr := generateKeyMaterial(keyUsageEncryptDecrypt, keySpecSymmetricDefault)
		if gerr != nil {
			return kmsKey{}, gerr
		}
		keyID = randomHex(12)
		wrappedB64, nonceB64, werr := s.wrapKeyMaterial(keyID, raw)
		if werr != nil {
			return kmsKey{}, werr
		}
		arn := arnFor("kms", region, accountID, "key/"+keyID)
		if _, e := tx.ExecContext(ctx,
			`INSERT INTO kms_keys (id, arn, master_key_b64, wrapped_key_b64, key_nonce_b64, public_key_b64, key_usage, key_spec, description, enabled, managed, deletion_date, created_at, account_id)
			 VALUES ($1, $2, '', $3, $4, '', $5, $6, $7, TRUE, TRUE, NULL, $8, $9)`,
			keyID, arn, wrappedB64, nonceB64, usage, spec,
			fmt.Sprintf("Default key for account %s", accountID), time.Now().UTC(), accountID); e != nil {
			return kmsKey{}, e
		}
	} else {
		// Promote the adopted key to a managed, enabled, non-deleting state.
		if _, e := tx.ExecContext(ctx,
			`UPDATE kms_keys SET managed = TRUE, enabled = TRUE, deletion_date = NULL, updated_at = NOW() WHERE id = $1 AND account_id = $2`,
			keyID, accountID); e != nil {
			return kmsKey{}, e
		}
	}

	if _, e := tx.ExecContext(ctx,
		`INSERT INTO kms_aliases (alias_name, target_key_id, account_id) VALUES ($1, $2, $3)`,
		managedDefaultAlias, keyID, accountID); e != nil {
		return kmsKey{}, e
	}

	if e := tx.Commit(); e != nil {
		return kmsKey{}, e
	}
	return s.resolveByIDForAccount(ctx, keyID, accountID)
}

// resolveByIDForAccount loads a key scoped to an explicit account, independent of
// any caller account already present in ctx. Used when provisioning keys for an
// account other than the authenticated caller (e.g. account creation, backfill).
func (s *dbStore) resolveByIDForAccount(ctx context.Context, keyID, accountID string) (kmsKey, error) {
	return s.ResolveByID(withCallerAccount(ctx, accountID), keyID)
}

// ensureManagedDefaultKeys provisions the immutable per-account default key for
// every known account at startup. It is idempotent and only operates on
// DB-backed deployments.
func ensureManagedDefaultKeys(ctx context.Context, store keyStore) error {
	db, ok := store.(*dbStore)
	if !ok {
		return nil
	}

	ids := map[string]struct{}{}
	rows, err := db.db.QueryContext(ctx, `SELECT account_id FROM ui_accounts`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id string
		if scanErr := rows.Scan(&id); scanErr != nil {
			rows.Close()
			return scanErr
		}
		if id = strings.TrimSpace(id); isValidAccountID(id) {
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
	if _, dep := db.DeploymentIdentity(); isValidAccountID(dep) && dep != placeholderAccountID {
		ids[dep] = struct{}{}
	}

	var firstErr error
	for id := range ids {
		if _, e := db.EnsureAccountDefaultKey(ctx, id); e != nil {
			log.Printf("warning: ensure default key for account %s: %v", id, e)
			if firstErr == nil {
				firstErr = e
			}
		}
	}
	return firstErr
}
