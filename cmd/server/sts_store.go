package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// STS / IAM identity federation store.
//
// This layer backs Citadel's AWS-compatible Security Token Service (STS) and
// the IAM primitives it depends on:
//
//   - OIDC identity providers  (iam_oidc_providers): external token issuers
//     (e.g. a Kubernetes cluster) whose JWTs may be exchanged for temporary
//     Citadel credentials, IRSA-style.
//   - IAM roles                (iam_roles):          named identities with a
//     trust policy describing who may assume them.
//   - STS sessions             (sts_sessions):       short-lived ASIA-prefixed
//     credentials minted by AssumeRole / AssumeRoleWithWebIdentity.
//
// The design intentionally mirrors the existing iam_access_keys plumbing: the
// temporary secret is wrapped with the store's wrapping key (AES-GCM, key ID
// bound as AAD) exactly like a long-lived access key, so the same SigV4
// verification path validates both once GetAccessKeyByID learns to resolve
// ASIA-prefixed keys from sts_sessions.

var (
	errOIDCProviderNotFound = errors.New("oidc provider not found")
	errIAMRoleNotFound      = errors.New("iam role not found")
	errSTSSessionNotFound   = errors.New("sts session not found")
	errSTSSessionExpired    = errors.New("sts session expired")
)

// trustPolicyType discriminates the two supported trust relationships.
const (
	trustTypeOIDC    = "oidc"
	trustTypeAccount = "account"
)

// trustPolicy is Citadel's deliberately small subset of an IAM role trust
// policy. It is persisted as JSON in iam_roles.trust_policy and is expressive
// enough for the two flows Citadel supports: web-identity federation (OIDC) and
// cross/same-account AssumeRole by principals.
type trustPolicy struct {
	// Type is "oidc" or "account".
	Type string `json:"type"`
	// ProviderURL is the OIDC issuer URL (https://...) for type "oidc". It must
	// match a registered iam_oidc_providers row.
	ProviderURL string `json:"providerUrl,omitempty"`
	// Audiences lists acceptable JWT "aud" values for type "oidc".
	Audiences []string `json:"audiences,omitempty"`
	// Subjects lists acceptable JWT "sub" values for type "oidc". A trailing
	// "*" performs a prefix match (e.g. "system:serviceaccount:app:*").
	Subjects []string `json:"subjects,omitempty"`
	// Principals lists account IDs allowed to AssumeRole for type "account".
	Principals []string `json:"principals,omitempty"`
}

// subjectAllowed reports whether sub satisfies the policy's Subjects list.
func (p trustPolicy) subjectAllowed(sub string) bool {
	sub = strings.TrimSpace(sub)
	if sub == "" {
		return false
	}
	for _, want := range p.Subjects {
		want = strings.TrimSpace(want)
		if want == "*" {
			return true
		}
		if strings.HasSuffix(want, "*") {
			if strings.HasPrefix(sub, strings.TrimSuffix(want, "*")) {
				return true
			}
			continue
		}
		if want == sub {
			return true
		}
	}
	return false
}

// audienceAllowed reports whether any of the token audiences is accepted.
func (p trustPolicy) audienceAllowed(auds []string) bool {
	if len(p.Audiences) == 0 {
		return false
	}
	for _, got := range auds {
		got = strings.TrimSpace(got)
		for _, want := range p.Audiences {
			if strings.TrimSpace(want) == got {
				return true
			}
		}
	}
	return false
}

// principalAllowed reports whether accountID may AssumeRole under this policy.
func (p trustPolicy) principalAllowed(accountID string) bool {
	accountID = strings.TrimSpace(accountID)
	for _, want := range p.Principals {
		want = strings.TrimSpace(want)
		if want == "*" || want == accountID {
			return true
		}
	}
	return false
}

// oidcProvider is a registered external token issuer.
type oidcProvider struct {
	ProviderARN string
	AccountID   string
	URL         string
	ClientIDs   []string
	Thumbprints []string
	CreatedAt   time.Time
}

// iamRole is a named identity with an attached trust policy.
type iamRole struct {
	RoleARN        string
	AccountID      string
	RoleName       string
	Description    string
	Trust          trustPolicy
	MaxSessionSecs int
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// stsSession is a minted set of temporary credentials.
type stsSession struct {
	AccessKeyID     string
	AccountID       string
	RoleARN         string
	RoleSessionName string
	Subject         string
	ExpiresAt       time.Time
	CreatedAt       time.Time
}

// generateTempAccessKeyID returns an AWS-style temporary access key ID. STS keys
// use the "ASIA" prefix (vs "AKIA" for long-lived keys); the base32 suffix keeps
// the ID free of characters that would corrupt a SigV4 Credential scope.
func generateTempAccessKeyID() string {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "ASIA" + base32.StdEncoding.EncodeToString(b)
}

// generateSessionToken returns an opaque session token carried in the
// X-Amz-Security-Token header by SDK clients using temporary credentials.
func generateSessionToken() string {
	b := make([]byte, 48)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// isTempAccessKeyID reports whether keyID is an STS temporary credential.
func isTempAccessKeyID(keyID string) bool {
	return strings.HasPrefix(strings.TrimSpace(keyID), "ASIA")
}

// ---- OIDC providers --------------------------------------------------------

func (s *dbStore) CreateOIDCProvider(ctx context.Context, p oidcProvider) error {
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

func (s *dbStore) ListOIDCProviders(ctx context.Context, accountID string) ([]oidcProvider, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT provider_arn, account_id, url, client_ids_json, thumbprints_json, created_at
FROM iam_oidc_providers WHERE account_id = $1 ORDER BY url`,
		strings.TrimSpace(accountID),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []oidcProvider
	for rows.Next() {
		var p oidcProvider
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

func (s *dbStore) GetOIDCProviderByURL(ctx context.Context, accountID, url string) (oidcProvider, error) {
	var p oidcProvider
	var clientIDs, thumbs string
	err := s.db.QueryRowContext(ctx,
		`SELECT provider_arn, account_id, url, client_ids_json, thumbprints_json, created_at
FROM iam_oidc_providers WHERE account_id = $1 AND url = $2`,
		strings.TrimSpace(accountID), normalizeIssuerURL(url),
	).Scan(&p.ProviderARN, &p.AccountID, &p.URL, &clientIDs, &thumbs, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return oidcProvider{}, errOIDCProviderNotFound
	}
	if err != nil {
		return oidcProvider{}, err
	}
	_ = json.Unmarshal([]byte(clientIDs), &p.ClientIDs)
	_ = json.Unmarshal([]byte(thumbs), &p.Thumbprints)
	return p, nil
}

func (s *dbStore) DeleteOIDCProvider(ctx context.Context, accountID, providerARN string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM iam_oidc_providers WHERE account_id = $1 AND provider_arn = $2`,
		strings.TrimSpace(accountID), strings.TrimSpace(providerARN),
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errOIDCProviderNotFound
	}
	return nil
}

// ---- IAM roles -------------------------------------------------------------

func (s *dbStore) CreateIAMRole(ctx context.Context, role iamRole) error {
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

func (s *dbStore) ListIAMRoles(ctx context.Context, accountID string) ([]iamRole, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT role_arn, account_id, role_name, description, trust_policy, max_session_seconds, created_at, updated_at
FROM iam_roles WHERE account_id = $1 ORDER BY role_name`,
		strings.TrimSpace(accountID),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []iamRole
	for rows.Next() {
		role, err := scanIAMRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, role)
	}
	return out, rows.Err()
}

func (s *dbStore) GetIAMRole(ctx context.Context, accountID, roleName string) (iamRole, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT role_arn, account_id, role_name, description, trust_policy, max_session_seconds, created_at, updated_at
FROM iam_roles WHERE account_id = $1 AND role_name = $2`,
		strings.TrimSpace(accountID), strings.TrimSpace(roleName),
	)
	role, err := scanIAMRole(row)
	if err == sql.ErrNoRows {
		return iamRole{}, errIAMRoleNotFound
	}
	return role, err
}

// GetIAMRoleByARN resolves a role by its full ARN regardless of account scope.
func (s *dbStore) GetIAMRoleByARN(ctx context.Context, roleARN string) (iamRole, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT role_arn, account_id, role_name, description, trust_policy, max_session_seconds, created_at, updated_at
FROM iam_roles WHERE role_arn = $1`,
		strings.TrimSpace(roleARN),
	)
	role, err := scanIAMRole(row)
	if err == sql.ErrNoRows {
		return iamRole{}, errIAMRoleNotFound
	}
	return role, err
}

func (s *dbStore) DeleteIAMRole(ctx context.Context, accountID, roleName string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM iam_roles WHERE account_id = $1 AND role_name = $2`,
		strings.TrimSpace(accountID), strings.TrimSpace(roleName),
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errIAMRoleNotFound
	}
	return nil
}

// rowScanner unifies *sql.Row and *sql.Rows for the shared role scan helper.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanIAMRole(sc rowScanner) (iamRole, error) {
	var role iamRole
	var policy string
	if err := sc.Scan(&role.RoleARN, &role.AccountID, &role.RoleName, &role.Description, &policy, &role.MaxSessionSecs, &role.CreatedAt, &role.UpdatedAt); err != nil {
		return iamRole{}, err
	}
	_ = json.Unmarshal([]byte(policy), &role.Trust)
	return role, nil
}

// ---- STS sessions ----------------------------------------------------------

// CreateSTSSession persists a freshly minted temporary credential. The secret is
// wrapped with the store's wrapping key (key ID bound as AAD) just like a
// long-lived access key, so the existing SigV4 path can verify it unchanged.
func (s *dbStore) CreateSTSSession(ctx context.Context, sess stsSession, secret, sessionToken string) error {
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
func (s *dbStore) getSTSSessionSecret(ctx context.Context, keyID string) (accountID, secret, sessionToken string, expiresAt time.Time, err error) {
	var wrappedB64, nonceB64 string
	err = s.db.QueryRowContext(ctx,
		`SELECT account_id, secret_wrapped_b64, secret_nonce_b64, session_token, expires_at
FROM sts_sessions WHERE access_key_id = $1`,
		strings.TrimSpace(keyID),
	).Scan(&accountID, &wrappedB64, &nonceB64, &sessionToken, &expiresAt)
	if err == sql.ErrNoRows {
		return "", "", "", time.Time{}, errSTSSessionNotFound
	}
	if err != nil {
		return "", "", "", time.Time{}, err
	}
	if time.Now().UTC().After(expiresAt.UTC()) {
		return "", "", "", expiresAt, errSTSSessionExpired
	}
	secretBytes, err := s.unwrapKeyMaterial(keyID, wrappedB64, nonceB64)
	if err != nil {
		return "", "", "", expiresAt, fmt.Errorf("unwrap temp secret: %w", err)
	}
	return accountID, string(secretBytes), sessionToken, expiresAt, nil
}

// DeleteExpiredSTSSessions garbage-collects sessions past their expiry.
func (s *dbStore) DeleteExpiredSTSSessions(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sts_sessions WHERE expires_at < NOW()`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// normalizeIssuerURL strips a trailing slash so issuer comparisons are stable.
func normalizeIssuerURL(u string) string {
	return strings.TrimRight(strings.TrimSpace(u), "/")
}

// ---- in-memory store: unsupported -----------------------------------------

func (s *inMemoryStore) CreateOIDCProvider(context.Context, oidcProvider) error {
	return errUnsupported
}
func (s *inMemoryStore) ListOIDCProviders(context.Context, string) ([]oidcProvider, error) {
	return nil, errUnsupported
}
func (s *inMemoryStore) GetOIDCProviderByURL(context.Context, string, string) (oidcProvider, error) {
	return oidcProvider{}, errUnsupported
}
func (s *inMemoryStore) DeleteOIDCProvider(context.Context, string, string) error {
	return errUnsupported
}
func (s *inMemoryStore) CreateIAMRole(context.Context, iamRole) error { return errUnsupported }
func (s *inMemoryStore) ListIAMRoles(context.Context, string) ([]iamRole, error) {
	return nil, errUnsupported
}
func (s *inMemoryStore) GetIAMRole(context.Context, string, string) (iamRole, error) {
	return iamRole{}, errUnsupported
}
func (s *inMemoryStore) GetIAMRoleByARN(context.Context, string) (iamRole, error) {
	return iamRole{}, errUnsupported
}
func (s *inMemoryStore) DeleteIAMRole(context.Context, string, string) error { return errUnsupported }
func (s *inMemoryStore) CreateSTSSession(context.Context, stsSession, string, string) error {
	return errUnsupported
}
func (s *inMemoryStore) DeleteExpiredSTSSessions(context.Context) (int64, error) {
	return 0, errUnsupported
}
