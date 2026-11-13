package postgres

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/lib/pq"

	"github.com/worlddrknss/citadel/internal/store"
)

const ssoProviderSelect = `SELECT id, name, issuer, client_id, scopes_json, group_claim, role_mappings_json, default_role, enabled,
created_at, updated_at, account_id, allowed_email_domains_json, client_secret_wrapped_b64 <> ''
FROM console_sso_providers`

func scanSSOProvider(row rowScanner) (store.SSOProvider, error) {
	var (
		p                                    store.SSOProvider
		scopesJSON, mappingJSON, domainsJSON string
	)
	if err := row.Scan(&p.ID, &p.Name, &p.Issuer, &p.ClientID, &scopesJSON, &p.GroupClaim, &mappingJSON,
		&p.DefaultRole, &p.Enabled, &p.CreatedAt, &p.UpdatedAt, &p.AccountID, &domainsJSON, &p.ClientSecretSet); err != nil {
		return store.SSOProvider{}, err
	}
	_ = json.Unmarshal([]byte(scopesJSON), &p.Scopes)
	_ = json.Unmarshal([]byte(mappingJSON), &p.RoleMappings)
	_ = json.Unmarshal([]byte(domainsJSON), &p.AllowedEmailDomains)
	p.CreatedAt = p.CreatedAt.UTC()
	p.UpdatedAt = p.UpdatedAt.UTC()
	return p, nil
}

func idnJSONList[T any](v []T) string {
	if v == nil {
		v = []T{}
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func idnUniqueViolation(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "23505"
}

func idnFKViolation(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "23503"
}

func (s *Store) GetSSOProvider(ctx context.Context, id string) (store.SSOProvider, error) {
	p, err := scanSSOProvider(s.db.QueryRowContext(ctx, ssoProviderSelect+` WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return store.SSOProvider{}, store.ErrSSOProviderNotFound
	}
	return p, err
}

func (s *Store) GetSSOProviderSecret(ctx context.Context, id string) ([]byte, error) {
	var b64 string
	err := s.db.QueryRowContext(ctx, `SELECT client_secret_wrapped_b64 FROM console_sso_providers WHERE id = $1`, id).Scan(&b64)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrSSOProviderNotFound
	}
	if err != nil || b64 == "" {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(b64)
}

func (s *Store) CreateSSOProvider(ctx context.Context, p store.SSOProvider, sealedSecret []byte) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO console_sso_providers
(id, name, issuer, client_id, client_secret_wrapped_b64, scopes_json, group_claim, role_mappings_json, default_role, enabled,
 created_at, updated_at, account_id, allowed_email_domains_json)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		p.ID, p.Name, p.Issuer, p.ClientID, base64.StdEncoding.EncodeToString(sealedSecret), idnJSONList(p.Scopes), p.GroupClaim,
		idnJSONList(p.RoleMappings), p.DefaultRole, p.Enabled, p.CreatedAt, p.UpdatedAt, p.AccountID, idnJSONList(p.AllowedEmailDomains))
	if idnUniqueViolation(err) {
		return store.ErrSSOProviderExists
	}
	return err
}

func (s *Store) UpdateSSOProvider(ctx context.Context, p store.SSOProvider, sealedSecret []byte) error {
	q := `UPDATE console_sso_providers SET name=$2, issuer=$3, client_id=$4, scopes_json=$5, group_claim=$6, role_mappings_json=$7,
default_role=$8, enabled=$9, updated_at=$10, account_id=$11, allowed_email_domains_json=$12`
	args := []any{p.ID, p.Name, p.Issuer, p.ClientID, idnJSONList(p.Scopes), p.GroupClaim, idnJSONList(p.RoleMappings),
		p.DefaultRole, p.Enabled, p.UpdatedAt, p.AccountID, idnJSONList(p.AllowedEmailDomains)}
	if sealedSecret != nil {
		q += `, client_secret_wrapped_b64=$13`
		args = append(args, base64.StdEncoding.EncodeToString(sealedSecret))
	}
	res, err := s.db.ExecContext(ctx, q+` WHERE id=$1`, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrSSOProviderNotFound
	}
	return nil
}

func (s *Store) DeleteSSOProvider(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM console_sso_providers WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrSSOProviderNotFound
	}
	return nil
}

func (s *Store) GetExternalIdentity(ctx context.Context, providerID, subject string) (store.ExternalIdentity, error) {
	var id store.ExternalIdentity
	err := s.db.QueryRowContext(ctx, `SELECT provider_id, subject, username, email, created_at, last_login_at
FROM console_sso_identities WHERE provider_id = $1 AND subject = $2`, providerID, subject).
		Scan(&id.ProviderID, &id.Subject, &id.Username, &id.Email, &id.CreatedAt, &id.LastLoginAt)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ExternalIdentity{}, store.ErrExternalIdentityNotFound
	}
	id.CreatedAt, id.LastLoginAt = id.CreatedAt.UTC(), id.LastLoginAt.UTC()
	return id, err
}

func (s *Store) CreateExternalIdentity(ctx context.Context, id store.ExternalIdentity) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO console_sso_identities (provider_id, subject, username, email, created_at, last_login_at)
VALUES ($1,$2,$3,$4,$5,$6)`, id.ProviderID, id.Subject, id.Username, id.Email, id.CreatedAt, id.LastLoginAt)
	switch {
	case idnUniqueViolation(err):
		return store.ErrExternalIdentityExists
	case idnFKViolation(err):
		return store.ErrSSOProviderNotFound
	}
	return err
}

func (s *Store) TouchExternalIdentity(ctx context.Context, providerID, subject, email string, at time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE console_sso_identities SET email = $3, last_login_at = $4 WHERE provider_id = $1 AND subject = $2`,
		providerID, subject, email, at)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrExternalIdentityNotFound
	}
	return nil
}

// ConsumeOnce inserts id, or takes over an expired row; a live row means a
// replay. The single statement is atomic across replicas.
func (s *Store) ConsumeOnce(ctx context.Context, id string, expires time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO consumed_once (id, expires_at) VALUES ($1, $2)
ON CONFLICT (id) DO UPDATE SET expires_at = EXCLUDED.expires_at WHERE consumed_once.expires_at <= NOW()`, id, expires)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (s *Store) PurgeConsumed(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM consumed_once WHERE expires_at < $1`, now)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func scanSigningKey(row rowScanner) (store.WorkloadSigningKey, error) {
	var (
		k                  store.WorkloadSigningKey
		retired, unpublish sql.NullTime
	)
	if err := row.Scan(&k.KID, &k.KMSKeyID, &k.Algorithm, &k.ActivatedAt, &retired, &unpublish); err != nil {
		return k, err
	}
	k.ActivatedAt = k.ActivatedAt.UTC()
	if retired.Valid {
		k.RetiredAt = retired.Time.UTC()
	}
	if unpublish.Valid {
		k.UnpublishAt = unpublish.Time.UTC()
	}
	return k, nil
}

func (s *Store) ListWorkloadSigningKeys(ctx context.Context) ([]store.WorkloadSigningKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT kid, kms_key_id, algorithm, activated_at, retired_at, unpublish_at
FROM workload_signing_keys ORDER BY activated_at DESC, kid DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.WorkloadSigningKey
	for rows.Next() {
		k, err := scanSigningKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) RotateWorkloadSigningKey(ctx context.Context, next store.WorkloadSigningKey, expectCurrentKID string, retiredAt, unpublishAt time.Time) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	var current string
	err = tx.QueryRowContext(ctx, `SELECT kid FROM workload_signing_keys WHERE retired_at IS NULL FOR UPDATE`).Scan(&current)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	err = nil
	if current != expectCurrentKID {
		err = store.ErrWorkloadRotationConflict
		return err
	}
	if current != "" {
		if _, err = tx.ExecContext(ctx, `UPDATE workload_signing_keys SET retired_at = $2, unpublish_at = $3 WHERE kid = $1`, current, retiredAt, unpublishAt); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO workload_signing_keys (kid, kms_key_id, algorithm, activated_at) VALUES ($1,$2,$3,$4)`,
		next.KID, next.KMSKeyID, next.Algorithm, next.ActivatedAt)
	if idnUniqueViolation(err) {
		// Another replica inserted a current key concurrently.
		err = store.ErrWorkloadRotationConflict
		return err
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteUnpublishedWorkloadSigningKeys(ctx context.Context, now time.Time) ([]store.WorkloadSigningKey, error) {
	rows, err := s.db.QueryContext(ctx, `DELETE FROM workload_signing_keys WHERE retired_at IS NOT NULL AND unpublish_at < $1
RETURNING kid, kms_key_id, algorithm, activated_at, retired_at, unpublish_at`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.WorkloadSigningKey
	for rows.Next() {
		k, err := scanSigningKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) GetWorkloadIssuerSettings(ctx context.Context) (store.WorkloadIssuerSettings, error) {
	var (
		st      store.WorkloadIssuerSettings
		updated sql.NullTime
	)
	err := s.db.QueryRowContext(ctx, `SELECT algorithm, rotation_days, updated_at, updated_by FROM workload_issuer_settings WHERE id = 1`).
		Scan(&st.Algorithm, &st.RotationDays, &updated, &st.UpdatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return store.WorkloadIssuerSettings{}, nil
	}
	if updated.Valid {
		st.UpdatedAt = updated.Time.UTC()
	}
	return st, err
}

func (s *Store) PutWorkloadIssuerSettings(ctx context.Context, st store.WorkloadIssuerSettings) error {
	var updated any
	if !st.UpdatedAt.IsZero() {
		updated = st.UpdatedAt
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO workload_issuer_settings (id, algorithm, rotation_days, updated_at, updated_by)
VALUES (1, $1, $2, $3, $4)
ON CONFLICT (id) DO UPDATE SET algorithm = EXCLUDED.algorithm, rotation_days = EXCLUDED.rotation_days,
	updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by`, st.Algorithm, st.RotationDays, updated, st.UpdatedBy)
	return err
}

const workloadClientSelect = `SELECT client_id, account_id, name, audiences_json, token_ttl_seconds, subject_format, auth_method,
allowed_users_json, api_server, ca_pem, service_accounts_json, review_audience, created_at, updated_at, last_issued_at
FROM workload_clients`

func scanWorkloadClient(row rowScanner) (store.WorkloadClient, error) {
	var (
		c                store.WorkloadClient
		auds, users, sas string
		lastIssued       sql.NullTime
	)
	if err := row.Scan(&c.ClientID, &c.AccountID, &c.Name, &auds, &c.TokenTTLSeconds, &c.SubjectFormat, &c.AuthMethod,
		&users, &c.APIServer, &c.CAPEM, &sas, &c.ReviewAudience, &c.CreatedAt, &c.UpdatedAt, &lastIssued); err != nil {
		return c, err
	}
	_ = json.Unmarshal([]byte(auds), &c.Audiences)
	_ = json.Unmarshal([]byte(users), &c.AllowedUsers)
	_ = json.Unmarshal([]byte(sas), &c.ServiceAccounts)
	c.CreatedAt, c.UpdatedAt = c.CreatedAt.UTC(), c.UpdatedAt.UTC()
	if lastIssued.Valid {
		c.LastIssuedAt = lastIssued.Time.UTC()
	}
	return c, nil
}

func (s *Store) CreateWorkloadClient(ctx context.Context, c store.WorkloadClient) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO workload_clients (client_id, account_id, name, audiences_json, token_ttl_seconds,
subject_format, auth_method, allowed_users_json, api_server, ca_pem, service_accounts_json, review_audience, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		c.ClientID, c.AccountID, c.Name, idnJSONList(c.Audiences), c.TokenTTLSeconds, c.SubjectFormat, c.AuthMethod,
		idnJSONList(c.AllowedUsers), c.APIServer, c.CAPEM, idnJSONList(c.ServiceAccounts), c.ReviewAudience, c.CreatedAt, c.UpdatedAt)
	if workloadNameViolation(err) {
		return store.ErrWorkloadClientNameTaken
	}
	if idnUniqueViolation(err) {
		return store.ErrWorkloadClientExists
	}
	return err
}

// workloadNameViolation reports whether err is a violation of the
// per-account client name index (migration 0900).
func workloadNameViolation(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "23505" && pqErr.Constraint == "workload_clients_account_name_uniq"
}

func (s *Store) GetWorkloadClient(ctx context.Context, clientID string) (store.WorkloadClient, error) {
	c, err := scanWorkloadClient(s.db.QueryRowContext(ctx, workloadClientSelect+` WHERE client_id = $1`, clientID))
	if errors.Is(err, sql.ErrNoRows) {
		return store.WorkloadClient{}, store.ErrWorkloadClientNotFound
	}
	return c, err
}

func (s *Store) ListWorkloadClients(ctx context.Context, accountID string) ([]store.WorkloadClient, error) {
	rows, err := s.db.QueryContext(ctx, workloadClientSelect+` WHERE account_id = $1 ORDER BY lower(name), client_id`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.WorkloadClient{}
	for rows.Next() {
		c, err := scanWorkloadClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) UpdateWorkloadClient(ctx context.Context, c store.WorkloadClient) error {
	res, err := s.db.ExecContext(ctx, `UPDATE workload_clients SET name=$3, audiences_json=$4, token_ttl_seconds=$5, subject_format=$6,
auth_method=$7, allowed_users_json=$8, api_server=$9, ca_pem=$10, service_accounts_json=$11, review_audience=$12, updated_at=$13
WHERE client_id=$1 AND account_id=$2`,
		c.ClientID, c.AccountID, c.Name, idnJSONList(c.Audiences), c.TokenTTLSeconds, c.SubjectFormat, c.AuthMethod,
		idnJSONList(c.AllowedUsers), c.APIServer, c.CAPEM, idnJSONList(c.ServiceAccounts), c.ReviewAudience, c.UpdatedAt)
	if workloadNameViolation(err) {
		return store.ErrWorkloadClientNameTaken
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrWorkloadClientNotFound
	}
	return nil
}

func (s *Store) DeleteWorkloadClient(ctx context.Context, accountID, clientID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM workload_clients WHERE client_id = $1 AND account_id = $2`, clientID, accountID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrWorkloadClientNotFound
	}
	return nil
}

func (s *Store) TouchWorkloadClientIssued(ctx context.Context, clientID string, at time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE workload_clients SET last_issued_at = $2 WHERE client_id = $1`, clientID, at)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrWorkloadClientNotFound
	}
	return nil
}
