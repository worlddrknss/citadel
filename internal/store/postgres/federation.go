package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// rowScanner unifies *sql.Row and *sql.Rows for the shared role scan helper.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanIAMRole(sc rowScanner) (store.IAMRole, error) {
	var role store.IAMRole
	var policy string
	if err := sc.Scan(&role.RoleARN, &role.AccountID, &role.RoleName, &role.Description, &policy, &role.MaxSessionSecs, &role.CreatedAt, &role.UpdatedAt); err != nil {
		return store.IAMRole{}, err
	}
	_ = json.Unmarshal([]byte(policy), &role.Trust)
	return role, nil
}

func (s *Store) CreateOIDCProvider(ctx context.Context, p store.OIDCProvider) error {
	clientIDs, _ := json.Marshal(p.ClientIDs)
	thumbs, _ := json.Marshal(p.Thumbprints)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO iam_oidc_providers (provider_arn, account_id, url, client_ids_json, thumbprints_json, created_at)
VALUES ($1, $2, $3, $4, $5, NOW())
ON CONFLICT (provider_arn) DO UPDATE SET url = EXCLUDED.url, client_ids_json = EXCLUDED.client_ids_json, thumbprints_json = EXCLUDED.thumbprints_json`,
		p.ProviderARN, p.AccountID, p.URL, string(clientIDs), string(thumbs),
	)
	return err
}

func (s *Store) ListOIDCProviders(ctx context.Context, accountID string) ([]store.OIDCProvider, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT provider_arn, account_id, url, client_ids_json, thumbprints_json, created_at
FROM iam_oidc_providers WHERE account_id = $1 ORDER BY url`,
		strings.TrimSpace(accountID),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.OIDCProvider
	for rows.Next() {
		var p store.OIDCProvider
		var clientIDs, thumbs string
		if err := rows.Scan(&p.ProviderARN, &p.AccountID, &p.URL, &clientIDs, &thumbs, &p.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(clientIDs), &p.ClientIDs)
		_ = json.Unmarshal([]byte(thumbs), &p.Thumbprints)
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetOIDCProviderByURL(ctx context.Context, accountID, url string) (store.OIDCProvider, error) {
	var p store.OIDCProvider
	var clientIDs, thumbs string
	err := s.db.QueryRowContext(ctx,
		`SELECT provider_arn, account_id, url, client_ids_json, thumbprints_json, created_at
FROM iam_oidc_providers WHERE account_id = $1 AND url = $2`,
		strings.TrimSpace(accountID), store.NormalizeIssuerURL(url),
	).Scan(&p.ProviderARN, &p.AccountID, &p.URL, &clientIDs, &thumbs, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return store.OIDCProvider{}, store.ErrOIDCProviderNotFound
	}
	if err != nil {
		return store.OIDCProvider{}, err
	}
	_ = json.Unmarshal([]byte(clientIDs), &p.ClientIDs)
	_ = json.Unmarshal([]byte(thumbs), &p.Thumbprints)
	return p, nil
}

func (s *Store) DeleteOIDCProvider(ctx context.Context, accountID, providerARN string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM iam_oidc_providers WHERE account_id = $1 AND provider_arn = $2`,
		strings.TrimSpace(accountID), strings.TrimSpace(providerARN),
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrOIDCProviderNotFound
	}
	return nil
}

func (s *Store) CreateIAMRole(ctx context.Context, role store.IAMRole) error {
	policy, err := json.Marshal(role.Trust)
	if err != nil {
		return err
	}
	if role.MaxSessionSecs <= 0 {
		role.MaxSessionSecs = 3600
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO iam_roles (role_arn, account_id, role_name, description, trust_policy, max_session_seconds, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
ON CONFLICT (role_arn) DO UPDATE SET description = EXCLUDED.description, trust_policy = EXCLUDED.trust_policy, max_session_seconds = EXCLUDED.max_session_seconds, updated_at = NOW()`,
		role.RoleARN, role.AccountID, role.RoleName, role.Description, string(policy), role.MaxSessionSecs,
	)
	return err
}

func (s *Store) ListIAMRoles(ctx context.Context, accountID string) ([]store.IAMRole, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT role_arn, account_id, role_name, description, trust_policy, max_session_seconds, created_at, updated_at
FROM iam_roles WHERE account_id = $1 ORDER BY role_name`,
		strings.TrimSpace(accountID),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.IAMRole
	for rows.Next() {
		role, err := scanIAMRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, role)
	}
	return out, rows.Err()
}

func (s *Store) GetIAMRole(ctx context.Context, accountID, roleName string) (store.IAMRole, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT role_arn, account_id, role_name, description, trust_policy, max_session_seconds, created_at, updated_at
FROM iam_roles WHERE account_id = $1 AND role_name = $2`,
		strings.TrimSpace(accountID), strings.TrimSpace(roleName),
	)
	role, err := scanIAMRole(row)
	if err == sql.ErrNoRows {
		return store.IAMRole{}, store.ErrIAMRoleNotFound
	}
	return role, err
}

// GetIAMRoleByARN resolves a role by its full ARN regardless of account scope.
func (s *Store) GetIAMRoleByARN(ctx context.Context, roleARN string) (store.IAMRole, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT role_arn, account_id, role_name, description, trust_policy, max_session_seconds, created_at, updated_at
FROM iam_roles WHERE role_arn = $1`,
		strings.TrimSpace(roleARN),
	)
	role, err := scanIAMRole(row)
	if err == sql.ErrNoRows {
		return store.IAMRole{}, store.ErrIAMRoleNotFound
	}
	return role, err
}

func (s *Store) DeleteIAMRole(ctx context.Context, accountID, roleName string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM iam_roles WHERE account_id = $1 AND role_name = $2`,
		strings.TrimSpace(accountID), strings.TrimSpace(roleName),
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrIAMRoleNotFound
	}
	return nil
}

// CreateSTSSession persists a freshly minted temporary credential. The secret is
// wrapped with the store's wrapping key (key ID bound as AAD) just like a
// long-lived access key, so the existing SigV4 path can verify it unchanged.
func (s *Store) CreateSTSSession(ctx context.Context, sess store.STSSession, secret, sessionToken string) error {
	wrappedB64, nonceB64, err := s.wrapKeyMaterial(sess.AccessKeyID, []byte(secret))
	if err != nil {
		return fmt.Errorf("wrap temp secret: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO sts_sessions (access_key_id, account_id, role_arn, role_session_name, subject, secret_wrapped_b64, secret_nonce_b64, session_token, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())`,
		sess.AccessKeyID, sess.AccountID, sess.RoleARN, sess.RoleSessionName, sess.Subject,
		wrappedB64, nonceB64, sessionToken, sess.ExpiresAt.UTC(),
	)
	return err
}

// getSTSSessionSecret resolves a temporary credential's secret for SigV4
// verification. It returns errSTSSessionExpired once past expires_at.
func (s *Store) GetSTSSessionSecret(ctx context.Context, keyID string) (accountID, secret, sessionToken string, expiresAt time.Time, err error) {
	var wrappedB64, nonceB64 string
	err = s.db.QueryRowContext(ctx,
		`SELECT account_id, secret_wrapped_b64, secret_nonce_b64, session_token, expires_at
FROM sts_sessions WHERE access_key_id = $1`,
		strings.TrimSpace(keyID),
	).Scan(&accountID, &wrappedB64, &nonceB64, &sessionToken, &expiresAt)
	if err == sql.ErrNoRows {
		return "", "", "", time.Time{}, store.ErrSTSSessionNotFound
	}
	if err != nil {
		return "", "", "", time.Time{}, err
	}
	if time.Now().UTC().After(expiresAt.UTC()) {
		return "", "", "", expiresAt, store.ErrSTSSessionExpired
	}
	secretBytes, err := s.unwrapKeyMaterial(keyID, wrappedB64, nonceB64)
	if err != nil {
		return "", "", "", expiresAt, fmt.Errorf("unwrap temp secret: %w", err)
	}
	return accountID, string(secretBytes), sessionToken, expiresAt, nil
}

// DeleteExpiredSTSSessions garbage-collects sessions past their expiry.
func (s *Store) DeleteExpiredSTSSessions(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sts_sessions WHERE expires_at < NOW()`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}
