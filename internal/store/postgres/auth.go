package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/arn"
	"github.com/worlddrknss/citadel/internal/store"
)

// bootstrapLockKey is the pg_advisory_xact_lock key serializing Bootstrap
// across replicas ("citb" in ASCII).
const bootstrapLockKey int64 = 0x63697462

// GetUIUser returns one console user.
func (s *Store) GetUIUser(ctx context.Context, username string) (store.UIUser, error) {
	var (
		user         store.UIUser
		accountsJSON string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT username, password_hash, role, display_name, accounts_json, platform_admin FROM ui_users WHERE username = $1`,
		strings.TrimSpace(username),
	).Scan(&user.Username, &user.PasswordHash, &user.Role, &user.DisplayName, &accountsJSON, &user.PlatformAdmin)
	if errors.Is(err, sql.ErrNoRows) {
		return store.UIUser{}, store.ErrUIUserNotFound
	}
	if err != nil {
		return store.UIUser{}, err
	}
	user.Accounts = store.DecodeAccountsJSON(accountsJSON)
	return user, nil
}

// CountUIUsers returns how many console users exist.
func (s *Store) CountUIUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ui_users`).Scan(&n)
	return n, err
}

// Bootstrap performs first-run setup in one transaction holding a
// transaction-scoped advisory lock, so concurrent calls (from any replica)
// are serialized and only the first, finding no users, succeeds.
func (s *Store) Bootstrap(ctx context.Context, req store.BootstrapRequest) (accountID string, err error) {
	username := strings.TrimSpace(req.Username)
	accountName := store.NormalizeAccountName(req.AccountName)
	if username == "" || strings.TrimSpace(req.PasswordHash) == "" || accountName == "" {
		return "", errors.New("bootstrap requires an account name, username and password hash")
	}
	display := strings.TrimSpace(req.DisplayName)
	if display == "" {
		display = username
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, bootstrapLockKey); err != nil {
		return "", fmt.Errorf("acquire bootstrap lock: %w", err)
	}
	var users int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM ui_users`).Scan(&users); err != nil {
		return "", err
	}
	if users > 0 {
		err = store.ErrAlreadyBootstrapped
		return "", err
	}
	var exists bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM ui_accounts WHERE account = $1)`, accountName).Scan(&exists); err != nil {
		return "", err
	}
	if exists {
		err = errors.New("account name already exists")
		return "", err
	}
	for {
		accountID = arn.GenerateAccountID()
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM ui_accounts WHERE account_id = $1)`, accountID).Scan(&exists); err != nil {
			return "", err
		}
		if !exists {
			break
		}
	}
	if _, err = tx.ExecContext(ctx,
		`INSERT INTO ui_accounts (account_id, account, created_at, updated_at) VALUES ($1, $2, NOW(), NOW())`,
		accountID, accountName); err != nil {
		return "", err
	}
	if _, err = tx.ExecContext(ctx,
		`INSERT INTO ui_users (username, password_hash, role, display_name, accounts_json, platform_admin, updated_at)
VALUES ($1, $2, 'admin', $3, '[]', TRUE, NOW())`,
		username, req.PasswordHash, display); err != nil {
		return "", err
	}
	if _, err = tx.ExecContext(ctx,
		`INSERT INTO user_accounts (username, account_id, role, created_at, updated_at) VALUES ($1, $2, 'admin', NOW(), NOW())`,
		username, accountID); err != nil {
		return "", err
	}
	if _, err = tx.ExecContext(ctx,
		`INSERT INTO org_settings (id, organization_name) VALUES (1, $1)
ON CONFLICT (id) DO UPDATE SET organization_name = EXCLUDED.organization_name`,
		strings.TrimSpace(req.OrganizationName)); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return accountID, nil
}

const consoleSessionColumns = `id, token_hash, username, account_id, method, ip, user_agent, created_at, last_seen_at, expires_at`

func scanConsoleSession(row interface{ Scan(...any) error }) (store.ConsoleSession, error) {
	var sess store.ConsoleSession
	err := row.Scan(&sess.ID, &sess.TokenHash, &sess.Username, &sess.AccountID, &sess.Method, &sess.IP, &sess.UserAgent,
		&sess.CreatedAt, &sess.LastSeenAt, &sess.ExpiresAt)
	sess.CreatedAt = sess.CreatedAt.UTC()
	sess.LastSeenAt = sess.LastSeenAt.UTC()
	sess.ExpiresAt = sess.ExpiresAt.UTC()
	return sess, err
}

func (s *Store) CreateConsoleSession(ctx context.Context, sess store.ConsoleSession) error {
	if sess.ID == "" || sess.TokenHash == "" || sess.Username == "" {
		return errors.New("console session requires an id, token hash and username")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO console_sessions (`+consoleSessionColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		sess.ID, sess.TokenHash, sess.Username, sess.AccountID, sess.Method, sess.IP, sess.UserAgent,
		sess.CreatedAt, sess.LastSeenAt, sess.ExpiresAt)
	return err
}

func (s *Store) GetConsoleSessionByTokenHash(ctx context.Context, tokenHash string) (store.ConsoleSession, error) {
	sess, err := scanConsoleSession(s.db.QueryRowContext(ctx,
		`SELECT `+consoleSessionColumns+` FROM console_sessions WHERE token_hash = $1`, tokenHash))
	if errors.Is(err, sql.ErrNoRows) {
		return store.ConsoleSession{}, store.ErrConsoleSessionNotFound
	}
	return sess, err
}

func (s *Store) TouchConsoleSession(ctx context.Context, id string, lastSeen time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE console_sessions SET last_seen_at = GREATEST(last_seen_at, $2) WHERE id = $1`, id, lastSeen)
	return requireRow(res, err)
}

func (s *Store) SetConsoleSessionAccount(ctx context.Context, id, accountID string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE console_sessions SET account_id = $2 WHERE id = $1`, id, accountID)
	return requireRow(res, err)
}

func requireRow(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return store.ErrConsoleSessionNotFound
	}
	return nil
}

func (s *Store) ListConsoleSessions(ctx context.Context, username string) ([]store.ConsoleSession, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+consoleSessionColumns+` FROM console_sessions WHERE username = $1 ORDER BY created_at DESC`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.ConsoleSession
	for rows.Next() {
		sess, err := scanConsoleSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

func (s *Store) DeleteConsoleSession(ctx context.Context, username, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM console_sessions WHERE id = $1 AND username = $2`, id, username)
	return requireRow(res, err)
}

func (s *Store) DeleteUserConsoleSessions(ctx context.Context, username, keepID string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM console_sessions WHERE username = $1 AND id <> $2`, username, keepID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) DeleteExpiredConsoleSessions(ctx context.Context, now, idleCutoff time.Time) (int64, error) {
	var (
		res sql.Result
		err error
	)
	if idleCutoff.IsZero() {
		res, err = s.db.ExecContext(ctx, `DELETE FROM console_sessions WHERE expires_at <= $1`, now)
	} else {
		res, err = s.db.ExecContext(ctx, `DELETE FROM console_sessions WHERE expires_at <= $1 OR last_seen_at < $2`, now, idleCutoff)
	}
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) GetOrgSettings(ctx context.Context) (store.OrgSettings, error) {
	var (
		out       store.OrgSettings
		envsJSON  string
		updatedAt sql.NullTime
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT organization_name, approval_environments, approval_min_approvers, allow_self_approval,
	session_idle_minutes, session_max_hours, updated_at, updated_by
FROM org_settings WHERE id = 1`,
	).Scan(&out.OrganizationName, &envsJSON, &out.ApprovalMinApprovers, &out.AllowSelfApproval,
		&out.SessionIdleMinutes, &out.SessionMaxHours, &updatedAt, &out.UpdatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return store.OrgSettings{ApprovalMinApprovers: 1}, nil
	}
	if err != nil {
		return store.OrgSettings{}, err
	}
	if err := json.Unmarshal([]byte(envsJSON), &out.ApprovalEnvironments); err != nil {
		out.ApprovalEnvironments = nil
	}
	if updatedAt.Valid {
		out.UpdatedAt = updatedAt.Time.UTC()
	}
	return out, nil
}

func (s *Store) PutOrgSettings(ctx context.Context, in store.OrgSettings) error {
	envs := in.ApprovalEnvironments
	if envs == nil {
		envs = []string{}
	}
	envsJSON, err := json.Marshal(envs)
	if err != nil {
		return err
	}
	var updatedAt any
	if !in.UpdatedAt.IsZero() {
		updatedAt = in.UpdatedAt
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO org_settings (id, organization_name, approval_environments, approval_min_approvers, allow_self_approval,
	session_idle_minutes, session_max_hours, updated_at, updated_by)
VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (id) DO UPDATE SET
	organization_name = EXCLUDED.organization_name,
	approval_environments = EXCLUDED.approval_environments,
	approval_min_approvers = EXCLUDED.approval_min_approvers,
	allow_self_approval = EXCLUDED.allow_self_approval,
	session_idle_minutes = EXCLUDED.session_idle_minutes,
	session_max_hours = EXCLUDED.session_max_hours,
	updated_at = EXCLUDED.updated_at,
	updated_by = EXCLUDED.updated_by`,
		in.OrganizationName, string(envsJSON), in.ApprovalMinApprovers, in.AllowSelfApproval,
		in.SessionIdleMinutes, in.SessionMaxHours, updatedAt, in.UpdatedBy)
	return err
}

func (s *Store) ListSSOProviders(ctx context.Context, enabledOnly bool) ([]store.SSOProvider, error) {
	q := ssoProviderSelect
	if enabledOnly {
		q += ` WHERE enabled`
	}
	q += ` ORDER BY name, id`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.SSOProvider{}
	for rows.Next() {
		p, err := scanSSOProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
