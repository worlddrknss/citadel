package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

const (
	settingAWSRegion       = "aws_region"
	settingAWSAccountID    = "aws_account_id"
	settingARNIdentityDone = "arn_identity_applied"
)

func GetSetting(ctx context.Context, db *sql.DB, key string) (string, error) {
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

func PutSetting(ctx context.Context, db *sql.DB, key, value string) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO kms_settings (setting_key, setting_value)
VALUES ($1, $2)
ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value`,
		key, value,
	)
	return err
}
