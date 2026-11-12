package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// CreateACMELEOrder persists a pending manual DNS-01 order scoped to the caller.
func (s *Store) CreateACMELEOrder(ctx context.Context, order store.ACMELEOrder) error {
	if order.OrderID == "" {
		order.OrderID = cryptoutil.RandomHex(12)
	}
	if order.Status == "" {
		order.Status = "pending"
	}
	const q = `
INSERT INTO acme_le_orders (
	order_id, order_url, directory_url, domains, status, account_id, created_at, expires_at
) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW() + INTERVAL '7 days')
`
	if _, err := s.db.ExecContext(ctx, q,
		order.OrderID, order.OrderURL, order.DirectoryURL, order.Domains, order.Status,
		s.accountForContext(ctx),
	); err != nil {
		return fmt.Errorf("insert acme order: %w", err)
	}
	return nil
}

// GetACMELEOrder loads a pending order owned by the caller's account.
func (s *Store) GetACMELEOrder(ctx context.Context, orderID string) (store.ACMELEOrder, error) {
	const q = `
SELECT order_id, order_url, directory_url, domains, status, created_at, expires_at
FROM acme_le_orders
WHERE order_id = $1 AND account_id = $2
`
	var o store.ACMELEOrder
	err := s.db.QueryRowContext(ctx, q, orderID, s.accountForContext(ctx)).Scan(
		&o.OrderID, &o.OrderURL, &o.DirectoryURL, &o.Domains, &o.Status, &o.CreatedAt, &o.ExpiresAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return store.ACMELEOrder{}, fmt.Errorf("acme order not found")
		}
		return store.ACMELEOrder{}, fmt.Errorf("query acme order: %w", err)
	}
	return o, nil
}

// DeleteACMELEOrder removes a pending order owned by the caller's account.
func (s *Store) DeleteACMELEOrder(ctx context.Context, orderID string) error {
	const q = `DELETE FROM acme_le_orders WHERE order_id = $1 AND account_id = $2`
	if _, err := s.db.ExecContext(ctx, q, orderID, s.accountForContext(ctx)); err != nil {
		return fmt.Errorf("delete acme order: %w", err)
	}
	return nil
}

// GetACMELEAccount loads the ACME account for a directory URL. It returns
// sql.ErrNoRows-wrapped error semantics via a not-found message when absent.
func (s *Store) GetACMELEAccount(ctx context.Context, directoryURL string) (store.ACMELEAccount, error) {
	const q = `
SELECT id, directory_url, account_uri, contact_email,
       account_key_wrapped_b64, account_key_nonce_b64, created_at, updated_at
FROM acme_le_accounts
WHERE directory_url = $1
`
	var (
		a          store.ACMELEAccount
		wrappedB64 string
		nonceB64   string
	)
	err := s.db.QueryRowContext(ctx, q, directoryURL).Scan(
		&a.ID, &a.DirectoryURL, &a.AccountURI, &a.ContactEmail,
		&wrappedB64, &nonceB64, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return store.ACMELEAccount{}, fmt.Errorf("acme account not found")
		}
		return store.ACMELEAccount{}, fmt.Errorf("query acme account: %w", err)
	}
	if wrappedB64 != "" && nonceB64 != "" {
		a.AccountKeyDER, err = s.unwrapKeyMaterial(a.ID, wrappedB64, nonceB64)
		if err != nil {
			return store.ACMELEAccount{}, fmt.Errorf("unwrap acme account key: %w", err)
		}
	}
	return a, nil
}

// UpsertACMELEAccount inserts or updates the ACME account for its directory URL.
func (s *Store) UpsertACMELEAccount(ctx context.Context, account store.ACMELEAccount) error {
	if account.ID == "" {
		account.ID = cryptoutil.RandomHex(12)
	}
	wrappedB64, nonceB64, err := s.wrapKeyMaterial(account.ID, account.AccountKeyDER)
	if err != nil {
		return fmt.Errorf("wrap acme account key: %w", err)
	}
	const q = `
INSERT INTO acme_le_accounts (
	id, directory_url, account_uri, contact_email,
	account_key_wrapped_b64, account_key_nonce_b64, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
ON CONFLICT (directory_url) DO UPDATE SET
	id = EXCLUDED.id,
	account_uri = EXCLUDED.account_uri,
	contact_email = EXCLUDED.contact_email,
	account_key_wrapped_b64 = EXCLUDED.account_key_wrapped_b64,
	account_key_nonce_b64 = EXCLUDED.account_key_nonce_b64,
	updated_at = NOW()
`
	if _, err := s.db.ExecContext(ctx, q,
		account.ID, account.DirectoryURL, account.AccountURI, account.ContactEmail,
		wrappedB64, nonceB64,
	); err != nil {
		return fmt.Errorf("upsert acme account: %w", err)
	}
	return nil
}

// CreateACMELECertificate persists a Let's Encrypt certificate and its wrapped
// private key.
func (s *Store) CreateACMELECertificate(ctx context.Context, cert store.ACMELECertificate) error {
	if cert.CertID == "" {
		cert.CertID = cryptoutil.RandomHex(12)
	}
	wrappedB64, nonceB64, err := s.wrapKeyMaterial(cert.CertID, cert.KeyDER)
	if err != nil {
		return fmt.Errorf("wrap acme cert key: %w", err)
	}
	const q = `
INSERT INTO acme_le_certificates (
	cert_id, directory_url, domains, serial, cert_b64, chain_b64,
	key_wrapped_b64, key_nonce_b64, status, not_before, not_after, created_at, updated_at, account_id
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW(), $12)
`
	if _, err := s.db.ExecContext(ctx, q,
		cert.CertID, cert.DirectoryURL, cert.Domains, cert.Serial, cert.CertB64, cert.ChainB64,
		wrappedB64, nonceB64, cert.Status, cert.NotBefore, cert.NotAfter, s.accountForContext(ctx),
	); err != nil {
		return fmt.Errorf("insert acme certificate: %w", err)
	}
	return nil
}

// GetACMELECertificate loads a Let's Encrypt certificate, unwrapping its key.
func (s *Store) GetACMELECertificate(ctx context.Context, certID string) (store.ACMELECertificate, error) {
	q := `
SELECT cert_id, directory_url, domains, serial, cert_b64, chain_b64,
       key_wrapped_b64, key_nonce_b64, status, not_before, not_after, created_at, updated_at
FROM acme_le_certificates
WHERE cert_id = $1`
	cond, args := andAccount(ctx, "account_id", 2)
	q += cond
	var (
		c          store.ACMELECertificate
		wrappedB64 string
		nonceB64   string
	)
	err := s.db.QueryRowContext(ctx, q, append([]any{certID}, args...)...).Scan(
		&c.CertID, &c.DirectoryURL, &c.Domains, &c.Serial, &c.CertB64, &c.ChainB64,
		&wrappedB64, &nonceB64, &c.Status, &c.NotBefore, &c.NotAfter, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return store.ACMELECertificate{}, fmt.Errorf("acme certificate not found")
		}
		return store.ACMELECertificate{}, fmt.Errorf("query acme certificate: %w", err)
	}
	if wrappedB64 != "" && nonceB64 != "" {
		c.KeyDER, err = s.unwrapKeyMaterial(c.CertID, wrappedB64, nonceB64)
		if err != nil {
			return store.ACMELECertificate{}, fmt.Errorf("unwrap acme cert key: %w", err)
		}
	}
	return c, nil
}

// ListACMELECertificates returns all Let's Encrypt certificates (without key
// material) newest first.
func (s *Store) ListACMELECertificates(ctx context.Context) ([]store.ACMELECertificate, error) {
	where, args := store.AccountFilter(ctx, "account_id", 1)
	if where != "" {
		where = "WHERE " + where
	}
	q := `
SELECT cert_id, directory_url, domains, serial, cert_b64, chain_b64,
       status, not_before, not_after, created_at, updated_at
FROM acme_le_certificates
` + where + `
ORDER BY created_at DESC
`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query acme certificates: %w", err)
	}
	defer rows.Close()

	var out []store.ACMELECertificate
	for rows.Next() {
		var c store.ACMELECertificate
		if err := rows.Scan(
			&c.CertID, &c.DirectoryURL, &c.Domains, &c.Serial, &c.CertB64, &c.ChainB64,
			&c.Status, &c.NotBefore, &c.NotAfter, &c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan acme certificate: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
