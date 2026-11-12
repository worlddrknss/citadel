// Package postgres is the PostgreSQL store.Store backend. Open applies the
// embedded schema migrations, resolves the deployment identity and runs the
// Go-side data migrations before returning a ready store.
package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"

	"github.com/worlddrknss/citadel/internal/arn"
	"github.com/worlddrknss/citadel/internal/store"

	// Registers the "postgres" database/sql driver this backend uses.
	_ "github.com/lib/pq"
)

// Store is the PostgreSQL store backend.
type Store struct {
	db                *sql.DB
	wrappingKey       []byte
	legacyWrappingKey []byte
	auditHMACKey      []byte
	region            string
	accountID         string
}

// Options configures a dbStore.
type Options struct {
	// WrappingKey wraps per-key material at rest (32 bytes).
	WrappingKey []byte
	// LegacyWrappingKey unwraps material wrapped before the HKDF upgrade.
	LegacyWrappingKey []byte
	// AuditHMACKey, when set, makes the audit chain an HMAC chain.
	AuditHMACKey []byte
	// Region and AccountID are the configured deployment identity, used only
	// when the database has not recorded one yet.
	Region    string
	AccountID string
}

// New wraps an already-migrated database. It runs no migrations and
// does not resolve the deployment identity; use openDBStore for that.
func New(db *sql.DB, opts Options) *Store {
	return &Store{db: db, wrappingKey: opts.WrappingKey, legacyWrappingKey: opts.LegacyWrappingKey, auditHMACKey: opts.AuditHMACKey}
}

// Open brings the schema up to date, resolves the persisted deployment
// identity (region and account ID) and runs the data migrations, returning a
// ready store.
func Open(ctx context.Context, db *sql.DB, opts Options) (*Store, error) {
	if err := Migrate(ctx, db); err != nil {
		return nil, err
	}
	store := New(db, opts)
	region, accountID, err := resolveDeploymentIdentity(ctx, db, opts.Region, opts.AccountID)
	if err != nil {
		return nil, fmt.Errorf("resolve deployment identity: %w", err)
	}
	store.region = region
	store.accountID = accountID
	if err := store.migrateLegacyKeyMaterial(ctx); err != nil {
		return nil, fmt.Errorf("migrate legacy key material: %w", err)
	}
	if err := store.migrateResourceARNs(ctx); err != nil {
		return nil, fmt.Errorf("migrate resource ARNs: %w", err)
	}
	return store, nil
}

var _ store.Store = (*Store)(nil)

// DB returns the underlying database handle.
func (s *Store) DB() *sql.DB { return s.db }

// resolveDeploymentIdentity determines the region and account ID embedded in
// resource ARNs. Stored settings take precedence, falling back to configuration
// (env/default) and finally to a freshly generated account ID. Any values that
// are not yet persisted are written back so the identity is stable across
// restarts.
func resolveDeploymentIdentity(ctx context.Context, db *sql.DB, cfgRegion, cfgAccountID string) (string, string, error) {
	region, err := GetSetting(ctx, db, settingAWSRegion)
	if err != nil {
		return "", "", err
	}
	if !arn.IsValidRegion(region) {
		region = arn.EffectiveRegion(cfgRegion)
		if err := PutSetting(ctx, db, settingAWSRegion, region); err != nil {
			return "", "", err
		}
	}

	accountID, err := GetSetting(ctx, db, settingAWSAccountID)
	if err != nil {
		return "", "", err
	}
	if !arn.IsValidAccountID(accountID) {
		if arn.IsValidAccountID(cfgAccountID) {
			accountID = cfgAccountID
		} else {
			accountID = arn.GenerateAccountID()
		}
		if err := PutSetting(ctx, db, settingAWSAccountID, accountID); err != nil {
			return "", "", err
		}
	}

	return region, accountID, nil
}

// DeploymentIdentity returns the region and account ID embedded in resource ARNs.
func (s *Store) DeploymentIdentity() (string, string) {
	return arn.EffectiveRegion(s.region), arn.EffectiveAccountID(s.accountID)
}

func (s *Store) keyARN(id string) string {
	r, a := s.DeploymentIdentity()
	return arn.Build("kms", r, a, "key/"+id)
}

func (s *Store) secretARNFor(name string) string {
	r, a := s.DeploymentIdentity()
	return arn.Build("secretsmanager", r, a, "secret:"+name)
}

// accountForContext returns the caller's account ID when present (strict SigV4),
// otherwise the deployment's global account ID. It is used to stamp newly
// created resources and to build their ARNs so that records remain consistent
// whether or not per-account auth is active.
func (s *Store) accountForContext(ctx context.Context) string {
	if acct, ok := store.CallerAccountFromContext(ctx); ok {
		return acct
	}
	_, a := s.DeploymentIdentity()
	return a
}

// keyARNForCtx builds a KMS key ARN using the caller's account when available,
// falling back to the deployment account.
func (s *Store) keyARNForCtx(ctx context.Context, id string) string {
	r, _ := s.DeploymentIdentity()
	return arn.Build("kms", r, s.accountForContext(ctx), "key/"+id)
}

// secretARNForCtx builds a Secrets Manager ARN using the caller's account when
// available, falling back to the deployment account.
func (s *Store) SecretARNForCtx(ctx context.Context, name string) string {
	r, _ := s.DeploymentIdentity()
	return arn.Build("secretsmanager", r, s.accountForContext(ctx), "secret:"+name)
}

// migrateResourceARNs rewrites stored resource ARNs so their region and account
// segments match the current deployment identity. It is idempotent: the applied
// identity is recorded in kms_settings and the rewrite is skipped when unchanged.
func (s *Store) migrateResourceARNs(ctx context.Context) error {
	current := s.region + "|" + s.accountID
	applied, err := GetSetting(ctx, s.db, settingARNIdentityDone)
	if err != nil {
		return err
	}
	if applied == current {
		return nil
	}

	oldRegion, oldAccount := arn.DefaultRegion, arn.PlaceholderAccountID
	if parts := strings.SplitN(applied, "|", 2); len(parts) == 2 && parts[1] != "" {
		oldRegion, oldAccount = parts[0], parts[1]
	} else {
		// Records created before deployment identity tracking used the historical
		// placeholder region/account.
		oldRegion, oldAccount = "local", arn.PlaceholderAccountID
	}

	oldSeg := ":" + oldRegion + ":" + oldAccount + ":"
	newSeg := ":" + s.region + ":" + s.accountID + ":"
	if oldSeg == newSeg {
		return PutSetting(ctx, s.db, settingARNIdentityDone, current)
	}

	type arnColumn struct {
		table  string
		column string
	}
	columns := []arnColumn{
		{"kms_keys", "arn"},
		{"sm_secrets", "arn"},
		{"pca_certificate_authorities", "urn"},
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, c := range columns {
		stmt := fmt.Sprintf(
			"UPDATE %s SET %s = REPLACE(%s, $1, $2) WHERE %s LIKE $3",
			c.table, c.column, c.column, c.column,
		)
		if _, err := tx.ExecContext(ctx, stmt, oldSeg, newSeg, "%"+oldSeg+"%"); err != nil {
			return fmt.Errorf("rewrite %s.%s ARNs: %w", c.table, c.column, err)
		}
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO kms_settings (setting_key, setting_value)
VALUES ($1, $2)
ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value`,
		settingARNIdentityDone, current,
	); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	log.Printf("migrated resource ARNs to identity region=%s account=%s", s.region, s.accountID)
	return nil
}
