package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/worlddrknss/citadel/internal/store"
)

// ---- certificate authorities ----

// TransitionCertificateAuthority moves a CA between lifecycle states.
func (s *Store) TransitionCertificateAuthority(ctx context.Context, caID string, from []string, state string, restorableUntil *time.Time) (store.PCACertificateAuthority, error) {
	cond, args := andAccount(ctx, "account_id", 5)
	var until any
	if restorableUntil != nil {
		until = restorableUntil.UTC()
	}
	row := s.db.QueryRowContext(ctx, `
		UPDATE pca_certificate_authorities
		SET state = $1, restorable_until = $2, updated_at = NOW()
		WHERE ca_id = $3 AND state = ANY($4)`+cond+`
		RETURNING `+caColumns,
		append([]any{state, until, caID, pq.Array(from)}, args...)...)
	ca, err := scanCA(row)
	if errors.Is(err, sql.ErrNoRows) {
		cur, gerr := s.GetCertificateAuthorityByID(ctx, caID)
		if gerr != nil {
			return store.PCACertificateAuthority{}, gerr
		}
		return cur, store.ErrCAStateConflict
	}
	if err != nil {
		return store.PCACertificateAuthority{}, fmt.Errorf("update CA state: %w", err)
	}
	return ca, nil
}

// CountOutstandingCertificates counts a CA's still-trusted issued
// certificates and subordinate CAs.
func (s *Store) CountOutstandingCertificates(ctx context.Context, caID string, now time.Time) (int, error) {
	if _, err := s.GetCertificateAuthorityByID(ctx, caID); err != nil {
		return 0, err
	}
	var n int
	err := s.db.QueryRowContext(ctx, `
		SELECT
			(SELECT COUNT(*) FROM pca_certificates
			 WHERE ca_id = $1 AND status <> 'REVOKED' AND revoked_at IS NULL AND not_after > $2)
			+
			(SELECT COUNT(*) FROM pca_certificate_authorities
			 WHERE parent_ca_id = $1 AND state <> 'DELETED' AND not_after > $2)`,
		caID, now).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count outstanding certificates: %w", err)
	}
	return n, nil
}

// ListCertificateAuthoritiesDueForPurge returns DELETED CAs past their window.
func (s *Store) ListCertificateAuthoritiesDueForPurge(ctx context.Context, now time.Time) ([]store.PCACertificateAuthority, error) {
	cond, args := andAccount(ctx, "account_id", 2)
	rows, err := s.db.QueryContext(ctx, `SELECT `+caColumns+` FROM pca_certificate_authorities
		WHERE state = 'DELETED' AND restorable_until IS NOT NULL AND restorable_until <= $1`+cond+` ORDER BY restorable_until, ca_id`,
		append([]any{now}, args...)...)
	if err != nil {
		return nil, fmt.Errorf("query CAs due for purge: %w", err)
	}
	defer rows.Close()
	var out []store.PCACertificateAuthority
	for rows.Next() {
		ca, err := scanCA(rows)
		if err != nil {
			return nil, fmt.Errorf("scan CA: %w", err)
		}
		out = append(out, ca)
	}
	return out, rows.Err()
}

// PurgeCertificateAuthority deletes a due CA; its certificates, policies and
// CRL state go with it (ON DELETE CASCADE).
func (s *Store) PurgeCertificateAuthority(ctx context.Context, caID string, now time.Time) (bool, error) {
	cond, args := andAccount(ctx, "account_id", 3)
	res, err := s.db.ExecContext(ctx, `DELETE FROM pca_certificate_authorities
		WHERE ca_id = $1 AND state = 'DELETED' AND restorable_until IS NOT NULL AND restorable_until <= $2`+cond,
		append([]any{caID, now}, args...)...)
	if err != nil {
		return false, fmt.Errorf("purge CA: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rows affected: %w", err)
	}
	return n > 0, nil
}

// HideCertificate marks a private CA certificate deleted from the inventory.
func (s *Store) HideCertificate(ctx context.Context, certID string, at time.Time) error {
	cond, args := andAccount(ctx, "account_id", 3)
	res, err := s.db.ExecContext(ctx, `UPDATE pca_certificates SET deleted_at = $1, updated_at = $1
		WHERE cert_id = $2 AND deleted_at IS NULL`+cond,
		append([]any{at.UTC(), certID}, args...)...)
	if err != nil {
		return fmt.Errorf("hide certificate: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("rows affected: %w", err)
	} else if n == 0 {
		return store.ErrCertificateNotFound
	}
	return nil
}

// ---- Let's Encrypt ----

const leRenewalColumns = `COALESCE(account_id, ''), challenge_kind, auto_renew, renew_attempts,
       renew_next_attempt_at, renew_last_attempt_at, renew_last_error, renewed_by`

const leListColumns = `cert_id, directory_url, domains, serial, cert_b64, chain_b64,
       status, not_before, not_after, created_at, updated_at, ` + leRenewalColumns

// leRenewalDest returns scan destinations for leRenewalColumns and a func
// to call after the scan, which fills in the nullable timestamps.
func leRenewalDest(c *store.ACMELECertificate) ([]any, func()) {
	var next, last sql.NullTime
	finish := func() {
		if next.Valid {
			t := next.Time
			c.RenewNextAttemptAt = &t
		}
		if last.Valid {
			t := last.Time
			c.RenewLastAttemptAt = &t
		}
	}
	return []any{&c.AccountID, &c.ChallengeKind, &c.AutoRenew, &c.RenewAttempts, &next, &last, &c.RenewLastError, &c.RenewedBy}, finish
}

func (s *Store) queryLECerts(ctx context.Context, q string, args ...any) ([]store.ACMELECertificate, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query acme certificates: %w", err)
	}
	defer rows.Close()
	var out []store.ACMELECertificate
	for rows.Next() {
		var c store.ACMELECertificate
		dest, finish := leRenewalDest(&c)
		if err := rows.Scan(append([]any{
			&c.CertID, &c.DirectoryURL, &c.Domains, &c.Serial, &c.CertB64, &c.ChainB64,
			&c.Status, &c.NotBefore, &c.NotAfter, &c.CreatedAt, &c.UpdatedAt,
		}, dest...)...); err != nil {
			return nil, fmt.Errorf("scan acme certificate: %w", err)
		}
		finish()
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteACMELECertificate removes a Let's Encrypt certificate and its key.
func (s *Store) DeleteACMELECertificate(ctx context.Context, certID string) error {
	cond, args := andAccount(ctx, "account_id", 2)
	res, err := s.db.ExecContext(ctx, `DELETE FROM acme_le_certificates WHERE cert_id = $1`+cond, append([]any{certID}, args...)...)
	if err != nil {
		return fmt.Errorf("delete acme certificate: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("rows affected: %w", err)
	} else if n == 0 {
		return store.ErrCertificateNotFound
	}
	return nil
}

// SetACMELEAutoRenew turns automatic renewal on or off. Turning it on
// clears the failure backoff so the next run may try at once.
func (s *Store) SetACMELEAutoRenew(ctx context.Context, certID string, on bool) error {
	cond, args := andAccount(ctx, "account_id", 3)
	res, err := s.db.ExecContext(ctx, `UPDATE acme_le_certificates
		SET auto_renew = $1,
		    renew_attempts = CASE WHEN $1 THEN 0 ELSE renew_attempts END,
		    renew_next_attempt_at = CASE WHEN $1 THEN NULL ELSE renew_next_attempt_at END,
		    updated_at = NOW()
		WHERE cert_id = $2`+cond, append([]any{on, certID}, args...)...)
	if err != nil {
		return fmt.Errorf("set auto-renew: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("rows affected: %w", err)
	} else if n == 0 {
		return store.ErrCertificateNotFound
	}
	return nil
}

// ListACMELERenewalsDue returns certificates due for automatic renewal.
func (s *Store) ListACMELERenewalsDue(ctx context.Context, renewBefore, now time.Time, limit int) ([]store.ACMELECertificate, error) {
	if limit <= 0 {
		limit = 50
	}
	cond, args := andAccount(ctx, "account_id", 4)
	return s.queryLECerts(ctx, `SELECT `+leListColumns+` FROM acme_le_certificates
		WHERE auto_renew AND renewed_by = '' AND status = 'ISSUED' AND not_after < $1
		  AND (renew_next_attempt_at IS NULL OR renew_next_attempt_at <= $2)`+cond+`
		ORDER BY not_after, cert_id LIMIT $3`,
		append([]any{renewBefore, now, limit}, args...)...)
}

// ClaimACMELERenewal leases a due renewal to the caller.
func (s *Store) ClaimACMELERenewal(ctx context.Context, certID string, now, leaseUntil time.Time) (bool, error) {
	cond, args := andAccount(ctx, "account_id", 4)
	res, err := s.db.ExecContext(ctx, `UPDATE acme_le_certificates
		SET renew_next_attempt_at = $1, renew_last_attempt_at = $2
		WHERE cert_id = $3 AND auto_renew AND renewed_by = ''
		  AND (renew_next_attempt_at IS NULL OR renew_next_attempt_at <= $2)`+cond,
		append([]any{leaseUntil, now, certID}, args...)...)
	if err != nil {
		return false, fmt.Errorf("claim renewal: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rows affected: %w", err)
	}
	return n > 0, nil
}

// RecordACMELERenewal stores a renewal attempt's outcome.
func (s *Store) RecordACMELERenewal(ctx context.Context, certID string, r store.ACMELERenewalResult) error {
	var (
		q    string
		args []any
	)
	if r.NewCertID != "" {
		q = `UPDATE acme_le_certificates
			SET renewed_by = $1, renew_attempts = 0, renew_last_error = '', renew_next_attempt_at = NULL,
			    renew_last_attempt_at = $2, updated_at = NOW()
			WHERE cert_id = $3`
		args = []any{r.NewCertID, r.At, certID}
	} else {
		q = `UPDATE acme_le_certificates
			SET renew_attempts = renew_attempts + 1, renew_last_error = $1, renew_next_attempt_at = $2,
			    renew_last_attempt_at = $3, updated_at = NOW()
			WHERE cert_id = $4`
		args = []any{r.Error, r.NextAttemptAt, r.At, certID}
	}
	cond, acct := andAccount(ctx, "account_id", len(args)+1)
	res, err := s.db.ExecContext(ctx, q+cond, append(args, acct...)...)
	if err != nil {
		return fmt.Errorf("record renewal: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("rows affected: %w", err)
	} else if n == 0 {
		return store.ErrCertificateNotFound
	}
	return nil
}
