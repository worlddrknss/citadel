package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// ClaimACMIdempotencyToken implements store.PKIParityStore. The upsert only
// replaces a record older than notBefore, so of two concurrent claims exactly
// one wins and the other reads the winner.
func (s *Store) ClaimACMIdempotencyToken(ctx context.Context, rec store.ACMIdempotencyRecord, notBefore time.Time) (store.ACMIdempotencyRecord, bool, error) {
	rec.AccountID = s.accountForContext(ctx)
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now().UTC()
	}
	// Expired claims are swept opportunistically (indexed on created_at).
	if _, err := s.db.ExecContext(ctx, `DELETE FROM acm_idempotency_tokens WHERE account_id = $1 AND created_at < $2`, rec.AccountID, notBefore); err != nil {
		return store.ACMIdempotencyRecord{}, false, fmt.Errorf("sweep idempotency tokens: %w", err)
	}
	var arn string
	err := s.db.QueryRowContext(ctx, `
INSERT INTO acm_idempotency_tokens (account_id, operation, token, params_hash, arn, created_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (account_id, operation, token) DO UPDATE
	SET params_hash = EXCLUDED.params_hash, arn = EXCLUDED.arn, created_at = EXCLUDED.created_at
	WHERE acm_idempotency_tokens.created_at < $7
RETURNING arn`, rec.AccountID, rec.Operation, rec.Token, rec.ParamsHash, rec.ARN, rec.CreatedAt, notBefore).Scan(&arn)
	if err == nil {
		return rec, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return store.ACMIdempotencyRecord{}, false, fmt.Errorf("claim idempotency token: %w", err)
	}
	prev := store.ACMIdempotencyRecord{AccountID: rec.AccountID, Operation: rec.Operation, Token: rec.Token}
	err = s.db.QueryRowContext(ctx,
		`SELECT params_hash, arn, created_at FROM acm_idempotency_tokens WHERE account_id = $1 AND operation = $2 AND token = $3`,
		rec.AccountID, rec.Operation, rec.Token).Scan(&prev.ParamsHash, &prev.ARN, &prev.CreatedAt)
	if err != nil {
		return store.ACMIdempotencyRecord{}, false, fmt.Errorf("read idempotency token: %w", err)
	}
	return prev, false, nil
}

// ReleaseACMIdempotencyToken implements store.PKIParityStore.
func (s *Store) ReleaseACMIdempotencyToken(ctx context.Context, operation, token, arn string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM acm_idempotency_tokens WHERE account_id = $1 AND operation = $2 AND token = $3 AND arn = $4`,
		s.accountForContext(ctx), operation, token, arn)
	return err
}

// PutCertificateAuthorityCSR implements store.PKIParityStore.
func (s *Store) PutCertificateAuthorityCSR(ctx context.Context, caID, csrB64 string) error {
	if _, err := s.GetCertificateAuthorityByID(ctx, caID); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO pca_ca_csrs (ca_id, account_id, csr_b64) VALUES ($1, $2, $3)
ON CONFLICT (ca_id) DO UPDATE SET csr_b64 = EXCLUDED.csr_b64`, caID, s.accountForContext(ctx), csrB64)
	return err
}

// GetCertificateAuthorityCSR implements store.PKIParityStore.
func (s *Store) GetCertificateAuthorityCSR(ctx context.Context, caID string) (string, error) {
	cond, args := andAccount(ctx, "account_id", 2)
	var csr string
	err := s.db.QueryRowContext(ctx, `SELECT csr_b64 FROM pca_ca_csrs WHERE ca_id = $1`+cond, append([]any{caID}, args...)...).Scan(&csr)
	if errors.Is(err, sql.ErrNoRows) {
		return "", store.ErrCANotFound
	}
	return csr, err
}

// ActivateCertificateAuthority implements store.PKIParityStore.
func (s *Store) ActivateCertificateAuthority(ctx context.Context, ca store.PCACertificateAuthority) error {
	cond, args := andAccount(ctx, "account_id", 9)
	res, err := s.db.ExecContext(ctx, `
UPDATE pca_certificate_authorities
SET ca_cert_b64 = $2, subject_dn = $3, path_length = $4, not_before = $5, not_after = $6, parent_ca_id = $7,
	state = 'ACTIVE', updated_at = NOW()
WHERE ca_id = $1 AND state = $8`+cond,
		append([]any{ca.CAID, ca.CACertB64, ca.SubjectDN, ca.PathLength, ca.NotBefore, ca.NotAfter, ca.ParentCAID, store.CAStatePendingCertificate}, args...)...)
	if err != nil {
		return fmt.Errorf("activate CA: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return nil
	}
	if _, err := s.GetCertificateAuthorityByID(ctx, ca.CAID); err != nil {
		return err
	}
	return store.ErrCANotPending
}
