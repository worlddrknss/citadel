package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// Console MFA (migration 1000_console_mfa): TOTP enrolments, recovery codes
// and spent pending-login tokens.

func (s *Store) GetMFA(ctx context.Context, username string) (store.MFAEnrollment, error) {
	var (
		out       store.MFAEnrollment
		enabledAt sql.NullTime
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT m.username, m.secret_enc, m.enabled, m.last_step, m.created_at, m.enabled_at,
	(SELECT COUNT(*) FROM console_mfa_recovery_codes c WHERE c.username = m.username AND c.used_at IS NULL)
FROM console_mfa m WHERE m.username = $1`, strings.TrimSpace(username),
	).Scan(&out.Username, &out.SecretEnc, &out.Enabled, &out.LastStep, &out.CreatedAt, &enabledAt, &out.RecoveryCodesLeft)
	if errors.Is(err, sql.ErrNoRows) {
		return store.MFAEnrollment{}, store.ErrMFANotFound
	}
	if err != nil {
		return store.MFAEnrollment{}, err
	}
	out.CreatedAt = out.CreatedAt.UTC()
	if enabledAt.Valid {
		out.EnabledAt = enabledAt.Time.UTC()
	}
	return out, nil
}

func (s *Store) PutPendingMFA(ctx context.Context, username string, secretEnc []byte, now time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO console_mfa (username, secret_enc, enabled, last_step, created_at)
VALUES ($1, $2, FALSE, 0, $3)
ON CONFLICT (username) DO UPDATE SET secret_enc = EXCLUDED.secret_enc, created_at = EXCLUDED.created_at, last_step = 0
WHERE NOT console_mfa.enabled`, strings.TrimSpace(username), secretEnc, now)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return store.ErrMFAAlreadyEnabled
	}
	return nil
}

func (s *Store) EnableMFA(ctx context.Context, username string, secretEnc []byte, step int64, recoveryHashes []string, now time.Time) (err error) {
	username = strings.TrimSpace(username)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	res, err := tx.ExecContext(ctx,
		`UPDATE console_mfa SET enabled = TRUE, enabled_at = $3, last_step = $4
WHERE username = $1 AND secret_enc = $2 AND NOT enabled`, username, secretEnc, now, step)
	if err != nil {
		return err
	}
	if n, rerr := res.RowsAffected(); rerr != nil {
		return rerr
	} else if n == 0 {
		return store.ErrMFANotFound
	}
	if err = replaceRecoveryCodes(ctx, tx, username, recoveryHashes); err != nil {
		return err
	}
	return tx.Commit()
}

func replaceRecoveryCodes(ctx context.Context, tx *sql.Tx, username string, hashes []string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM console_mfa_recovery_codes WHERE username = $1`, username); err != nil {
		return err
	}
	for _, h := range hashes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO console_mfa_recovery_codes (username, code_hash) VALUES ($1, $2)`, username, h); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) AdvanceMFAStep(ctx context.Context, username string, step int64) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE console_mfa SET last_step = $2 WHERE username = $1 AND enabled AND last_step < $2`,
		strings.TrimSpace(username), step)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (s *Store) DeleteMFA(ctx context.Context, username string) (bool, error) {
	// Recovery codes go with the enrolment (ON DELETE CASCADE).
	res, err := s.db.ExecContext(ctx, `DELETE FROM console_mfa WHERE username = $1`, strings.TrimSpace(username))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (s *Store) ListMFARecoveryCodeHashes(ctx context.Context, username string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT code_hash FROM console_mfa_recovery_codes WHERE username = $1 AND used_at IS NULL ORDER BY code_hash`,
		strings.TrimSpace(username))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) ConsumeMFARecoveryCode(ctx context.Context, username, codeHash string) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE console_mfa_recovery_codes SET used_at = NOW() WHERE username = $1 AND code_hash = $2 AND used_at IS NULL`,
		strings.TrimSpace(username), codeHash)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (s *Store) ReplaceMFARecoveryCodes(ctx context.Context, username string, hashes []string) (err error) {
	username = strings.TrimSpace(username)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	var enabled bool
	err = tx.QueryRowContext(ctx, `SELECT enabled FROM console_mfa WHERE username = $1 FOR UPDATE`, username).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !enabled) {
		err = store.ErrMFANotFound
	}
	if err != nil {
		return err
	}
	if err = replaceRecoveryCodes(ctx, tx, username, hashes); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ListMFAEnabledUsers(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT username FROM console_mfa WHERE enabled ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) UseMFALoginToken(ctx context.Context, id string, expiresAt, now time.Time) (bool, error) {
	// Spent tokens are only needed until they expire; drop old ones as we go.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM console_mfa_login_tokens WHERE expires_at < $1`, now); err != nil {
		return false, err
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO console_mfa_login_tokens (id, expires_at) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING`, id, expiresAt)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}
