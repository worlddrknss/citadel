package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/worlddrknss/citadel/internal/store"
)

// MarkExpiredCertificates moves certificates and CAs past their notAfter to
// EXPIRED.
func (s *Store) MarkExpiredCertificates(ctx context.Context, now time.Time) (int64, error) {
	var total int64
	stmts := []string{
		`UPDATE pca_certificates SET status = 'EXPIRED', updated_at = NOW() WHERE status = 'ISSUED' AND not_after < $1`,
		`UPDATE acm_certificates SET status = 'EXPIRED', updated_at = NOW() WHERE status = 'ISSUED' AND not_after < $1`,
		`UPDATE acme_le_certificates SET status = 'EXPIRED', updated_at = NOW() WHERE status = 'ISSUED' AND not_after < $1`,
		`UPDATE pca_certificate_authorities SET state = 'EXPIRED', updated_at = NOW() WHERE state = 'ACTIVE' AND not_after < $1`,
	}
	for _, q := range stmts {
		cond, args := andAccount(ctx, "account_id", 2)
		res, err := s.db.ExecContext(ctx, q+cond, append([]any{now}, args...)...)
		if err != nil {
			return total, fmt.Errorf("mark expired: %w", err)
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}

func jsonList(v []string) string {
	if v == nil {
		v = []string{}
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func parseJSONList(raw string) []string {
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil || out == nil {
		return []string{}
	}
	return out
}

// GetACMEServerSettings loads the caller account's ACME server settings.
func (s *Store) GetACMEServerSettings(ctx context.Context) (store.ACMEServerSettings, error) {
	var (
		out                 store.ACMEServerSettings
		domains, ips, cidrs string
	)
	err := s.db.QueryRowContext(ctx, `
SELECT account_id, issuing_ca_id, allowed_domains, allowed_ip_ranges, validation_allowed_cidrs, updated_at, updated_by
FROM pki_acme_settings WHERE account_id = $1`, s.accountForContext(ctx)).Scan(
		&out.AccountID, &out.IssuingCAID, &domains, &ips, &cidrs, &out.UpdatedAt, &out.UpdatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ACMEServerSettings{}, store.ErrACMEServerSettingsNotFound
	}
	if err != nil {
		return store.ACMEServerSettings{}, fmt.Errorf("query acme settings: %w", err)
	}
	out.AllowedDomains, out.AllowedIPRanges, out.ValidationAllowedCIDRs = parseJSONList(domains), parseJSONList(ips), parseJSONList(cidrs)
	return out, nil
}

// PutACMEServerSettings upserts the caller account's ACME server settings.
func (s *Store) PutACMEServerSettings(ctx context.Context, in store.ACMEServerSettings) error {
	if in.UpdatedAt.IsZero() {
		in.UpdatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO pki_acme_settings (account_id, issuing_ca_id, allowed_domains, allowed_ip_ranges, validation_allowed_cidrs, updated_at, updated_by)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (account_id) DO UPDATE SET
	issuing_ca_id = EXCLUDED.issuing_ca_id,
	allowed_domains = EXCLUDED.allowed_domains,
	allowed_ip_ranges = EXCLUDED.allowed_ip_ranges,
	validation_allowed_cidrs = EXCLUDED.validation_allowed_cidrs,
	updated_at = EXCLUDED.updated_at,
	updated_by = EXCLUDED.updated_by`,
		s.accountForContext(ctx), in.IssuingCAID, jsonList(in.AllowedDomains), jsonList(in.AllowedIPRanges),
		jsonList(in.ValidationAllowedCIDRs), in.UpdatedAt, in.UpdatedBy)
	if err != nil {
		return fmt.Errorf("upsert acme settings: %w", err)
	}
	return nil
}

// eabAAD binds a wrapped HMAC key to its kid and table.
func eabAAD(kid string) string { return "pki_acme_eab_keys:" + kid }

// CreateEABKey stores an EAB key with its HMAC key wrapped.
func (s *Store) CreateEABKey(ctx context.Context, k store.EABKey) error {
	wrapped, nonce, err := s.wrapKeyMaterial(eabAAD(k.KID), k.HMACKey)
	if err != nil {
		return fmt.Errorf("wrap eab key: %w", err)
	}
	if k.Status == "" {
		k.Status = store.EABStatusUnused
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO pki_acme_eab_keys (kid, account_id, label, hmac_wrapped_b64, hmac_nonce_b64, status, created_at, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		k.KID, s.accountForContext(ctx), k.Label, wrapped, nonce, k.Status, k.CreatedAt, k.CreatedBy)
	if err != nil {
		return fmt.Errorf("insert eab key: %w", err)
	}
	return nil
}

const eabColumns = `kid, account_id, label, status, created_at, created_by, bound_at, acme_account_id`

func scanEAB(row interface{ Scan(...any) error }, extra ...any) (store.EABKey, error) {
	var k store.EABKey
	var bound sql.NullTime
	dest := append([]any{&k.KID, &k.AccountID, &k.Label, &k.Status, &k.CreatedAt, &k.CreatedBy, &bound, &k.ACMEAccountID}, extra...)
	if err := row.Scan(dest...); err != nil {
		return k, err
	}
	if bound.Valid {
		t := bound.Time
		k.BoundAt = &t
	}
	return k, nil
}

// ListEABKeys lists the caller account's EAB keys, newest first.
func (s *Store) ListEABKeys(ctx context.Context) ([]store.EABKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+eabColumns+` FROM pki_acme_eab_keys WHERE account_id = $1 ORDER BY created_at DESC, kid`,
		s.accountForContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("query eab keys: %w", err)
	}
	defer rows.Close()
	var out []store.EABKey
	for rows.Next() {
		k, err := scanEAB(rows)
		if err != nil {
			return nil, fmt.Errorf("scan eab key: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// GetEABKey loads one key including its unwrapped HMAC key. Without a caller
// account on the context (the ACME server's resolver) it searches all
// accounts.
func (s *Store) GetEABKey(ctx context.Context, kid string) (store.EABKey, error) {
	cond, args := andAccount(ctx, "account_id", 2)
	var wrapped, nonce string
	k, err := scanEAB(s.db.QueryRowContext(ctx, `SELECT `+eabColumns+`, hmac_wrapped_b64, hmac_nonce_b64 FROM pki_acme_eab_keys WHERE kid = $1`+cond,
		append([]any{kid}, args...)...), &wrapped, &nonce)
	if errors.Is(err, sql.ErrNoRows) {
		return store.EABKey{}, store.ErrEABKeyNotFound
	}
	if err != nil {
		return store.EABKey{}, fmt.Errorf("query eab key: %w", err)
	}
	if k.HMACKey, err = s.unwrapKeyMaterial(eabAAD(k.KID), wrapped, nonce); err != nil {
		return store.EABKey{}, fmt.Errorf("unwrap eab key: %w", err)
	}
	return k, nil
}

// RevokeEABKey marks a key revoked and returns it (without its HMAC key).
func (s *Store) RevokeEABKey(ctx context.Context, kid string) (store.EABKey, error) {
	k, err := scanEAB(s.db.QueryRowContext(ctx, `
UPDATE pki_acme_eab_keys SET status = 'revoked' WHERE kid = $1 AND account_id = $2
RETURNING `+eabColumns, kid, s.accountForContext(ctx)))
	if errors.Is(err, sql.ErrNoRows) {
		return store.EABKey{}, store.ErrEABKeyNotFound
	}
	if err != nil {
		return store.EABKey{}, fmt.Errorf("revoke eab key: %w", err)
	}
	return k, nil
}

// BindEABKey atomically binds an unused key to an ACME account.
func (s *Store) BindEABKey(ctx context.Context, kid, acmeAccountID string, at time.Time) error {
	cond, args := andAccount(ctx, "account_id", 4)
	res, err := s.db.ExecContext(ctx, `
UPDATE pki_acme_eab_keys SET status = 'bound', bound_at = $2, acme_account_id = $3
WHERE kid = $1 AND status = 'unused'`+cond, append([]any{kid, at, acmeAccountID}, args...)...)
	if err != nil {
		return fmt.Errorf("bind eab key: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrEABKeyUnavailable
	}
	return nil
}

func acmAAD(arn string) string { return "acm_certificates:" + arn }

// CreateACMCertificate stores an ACM certificate, wrapping its private key.
func (s *Store) CreateACMCertificate(ctx context.Context, c store.ACMCertificate) error {
	var wrapped, nonce string
	if len(c.KeyDER) > 0 {
		var err error
		if wrapped, nonce, err = s.wrapKeyMaterial(acmAAD(c.ARN), c.KeyDER); err != nil {
			return fmt.Errorf("wrap acm key: %w", err)
		}
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO acm_certificates (cert_arn, account_id, cert_type, ca_id, pca_cert_id, domain_name, sans, serial,
	cert_b64, chain_pem, key_wrapped_b64, key_nonce_b64, status, not_before, not_after, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
		c.ARN, s.accountForContext(ctx), c.Type, c.CAID, c.PCACertID, c.DomainName, jsonList(c.SANs), c.Serial,
		c.CertB64, c.ChainPEM, wrapped, nonce, c.Status, c.NotBefore, c.NotAfter, c.CreatedAt, c.UpdatedAt)
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23505" {
		return store.ErrACMCertificateExists
	}
	if err != nil {
		return fmt.Errorf("insert acm certificate: %w", err)
	}
	return nil
}

const acmColumns = `cert_arn, account_id, cert_type, ca_id, pca_cert_id, domain_name, sans, serial,
	cert_b64, chain_pem, status, not_before, not_after, created_at, updated_at`

func scanACM(row interface{ Scan(...any) error }, extra ...any) (store.ACMCertificate, error) {
	var c store.ACMCertificate
	var sans string
	dest := append([]any{&c.ARN, &c.AccountID, &c.Type, &c.CAID, &c.PCACertID, &c.DomainName, &sans, &c.Serial,
		&c.CertB64, &c.ChainPEM, &c.Status, &c.NotBefore, &c.NotAfter, &c.CreatedAt, &c.UpdatedAt}, extra...)
	if err := row.Scan(dest...); err != nil {
		return c, err
	}
	c.SANs = parseJSONList(sans)
	return c, nil
}

// GetACMCertificate loads an ACM certificate including its private key.
func (s *Store) GetACMCertificate(ctx context.Context, arn string) (store.ACMCertificate, error) {
	cond, args := andAccount(ctx, "account_id", 2)
	var wrapped, nonce string
	c, err := scanACM(s.db.QueryRowContext(ctx, `SELECT `+acmColumns+`, key_wrapped_b64, key_nonce_b64 FROM acm_certificates WHERE cert_arn = $1`+cond,
		append([]any{arn}, args...)...), &wrapped, &nonce)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ACMCertificate{}, store.ErrACMCertificateNotFound
	}
	if err != nil {
		return store.ACMCertificate{}, fmt.Errorf("query acm certificate: %w", err)
	}
	if wrapped != "" {
		if c.KeyDER, err = s.unwrapKeyMaterial(acmAAD(c.ARN), wrapped, nonce); err != nil {
			return store.ACMCertificate{}, fmt.Errorf("unwrap acm key: %w", err)
		}
	}
	return c, nil
}

// ListACMCertificates lists the caller account's ACM certificates, oldest
// first, without key material.
func (s *Store) ListACMCertificates(ctx context.Context) ([]store.ACMCertificate, error) {
	where, args := store.AccountFilter(ctx, "account_id", 1)
	if where != "" {
		where = " WHERE " + where
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+acmColumns+` FROM acm_certificates`+where+` ORDER BY created_at, cert_arn`, args...)
	if err != nil {
		return nil, fmt.Errorf("query acm certificates: %w", err)
	}
	defer rows.Close()
	var out []store.ACMCertificate
	for rows.Next() {
		c, err := scanACM(rows)
		if err != nil {
			return nil, fmt.Errorf("scan acm certificate: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpdateACMCertificate replaces an ACM certificate's material and status.
func (s *Store) UpdateACMCertificate(ctx context.Context, c store.ACMCertificate) error {
	var wrapped, nonce string
	if len(c.KeyDER) > 0 {
		var err error
		if wrapped, nonce, err = s.wrapKeyMaterial(acmAAD(c.ARN), c.KeyDER); err != nil {
			return fmt.Errorf("wrap acm key: %w", err)
		}
	}
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = time.Now().UTC()
	}
	cond, args := andAccount(ctx, "account_id", 15)
	res, err := s.db.ExecContext(ctx, `
UPDATE acm_certificates SET cert_type = $2, ca_id = $3, pca_cert_id = $4, domain_name = $5, sans = $6, serial = $7,
	cert_b64 = $8, chain_pem = $9, key_wrapped_b64 = $10, key_nonce_b64 = $11, status = $12, not_before = $13,
	not_after = $14, updated_at = NOW()
WHERE cert_arn = $1`+cond,
		append([]any{c.ARN, c.Type, c.CAID, c.PCACertID, c.DomainName, jsonList(c.SANs), c.Serial,
			c.CertB64, c.ChainPEM, wrapped, nonce, c.Status, c.NotBefore, c.NotAfter}, args...)...)
	if err != nil {
		return fmt.Errorf("update acm certificate: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrACMCertificateNotFound
	}
	return nil
}

// DeleteACMCertificate removes an ACM certificate.
func (s *Store) DeleteACMCertificate(ctx context.Context, arn string) error {
	cond, args := andAccount(ctx, "account_id", 2)
	res, err := s.db.ExecContext(ctx, `DELETE FROM acm_certificates WHERE cert_arn = $1`+cond, append([]any{arn}, args...)...)
	if err != nil {
		return fmt.Errorf("delete acm certificate: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrACMCertificateNotFound
	}
	return nil
}
