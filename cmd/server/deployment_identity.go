package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
)

const (
	settingAWSRegion       = "aws_region"
	settingAWSAccountID    = "aws_account_id"
	settingARNIdentityDone = "arn_identity_applied"
)

// resolveDeploymentIdentity determines the region and account ID embedded in
// resource ARNs. Stored settings take precedence, falling back to configuration
// (env/default) and finally to a freshly generated account ID. Any values that
// are not yet persisted are written back so the identity is stable across
// restarts.
func resolveDeploymentIdentity(ctx context.Context, db *sql.DB, cfg config) (string, string, error) {
	region, err := getSetting(ctx, db, settingAWSRegion)
	if err != nil {
		return "", "", err
	}
	if !isValidRegion(region) {
		region = effectiveRegion(cfg.awsRegion)
		if err := putSetting(ctx, db, settingAWSRegion, region); err != nil {
			return "", "", err
		}
	}

	accountID, err := getSetting(ctx, db, settingAWSAccountID)
	if err != nil {
		return "", "", err
	}
	if !isValidAccountID(accountID) {
		if isValidAccountID(cfg.awsAccountID) {
			accountID = cfg.awsAccountID
		} else {
			accountID = generateAccountID()
		}
		if err := putSetting(ctx, db, settingAWSAccountID, accountID); err != nil {
			return "", "", err
		}
	}

	return region, accountID, nil
}

// migrateResourceARNs rewrites stored resource ARNs so their region and account
// segments match the current deployment identity. It is idempotent: the applied
// identity is recorded in kms_settings and the rewrite is skipped when unchanged.
func (s *dbStore) migrateResourceARNs(ctx context.Context) error {
	current := s.region + "|" + s.accountID
	applied, err := getSetting(ctx, s.db, settingARNIdentityDone)
	if err != nil {
		return err
	}
	if applied == current {
		return nil
	}

	oldRegion, oldAccount := defaultAWSRegion, placeholderAccountID
	if parts := strings.SplitN(applied, "|", 2); len(parts) == 2 && parts[1] != "" {
		oldRegion, oldAccount = parts[0], parts[1]
	} else {
		// Records created before deployment identity tracking used the historical
		// placeholder region/account.
		oldRegion, oldAccount = "local", placeholderAccountID
	}

	oldSeg := ":" + oldRegion + ":" + oldAccount + ":"
	newSeg := ":" + s.region + ":" + s.accountID + ":"
	if oldSeg == newSeg {
		return putSetting(ctx, s.db, settingARNIdentityDone, current)
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

func getSetting(ctx context.Context, db *sql.DB, key string) (string, error) {
	var value string
	err := db.QueryRowContext(ctx,
		`SELECT setting_value FROM kms_settings WHERE setting_key = $1`, key,
	).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(value), nil
}

func putSetting(ctx context.Context, db *sql.DB, key, value string) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO kms_settings (setting_key, setting_value)
VALUES ($1, $2)
ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value`,
		key, value,
	)
	return err
}
