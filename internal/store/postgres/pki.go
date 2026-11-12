package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/worlddrknss/citadel/internal/store"
)

// andAccount returns " AND <column> = $argPos" and its argument when the
// context carries a caller account, so reads and writes stay inside the
// caller's tenant. Without one (internal jobs, public CRL fetches) the query
// is unchanged.
func andAccount(ctx context.Context, column string, argPos int) (string, []any) {
	cond, args := store.AccountFilter(ctx, column, argPos)
	if cond == "" {
		return "", nil
	}
	return " AND " + cond, args
}

const caColumns = `ca_id, urn, type, kms_key_id, subject_dn, state, ca_cert_b64,
	path_length, not_before, not_after, description, account, created_at, updated_at,
	parent_ca_id, COALESCE(account_id, '')`

func scanCA(row interface{ Scan(...any) error }) (store.PCACertificateAuthority, error) {
	var ca store.PCACertificateAuthority
	var pathLength sql.NullInt32
	err := row.Scan(
		&ca.CAID, &ca.ARN, &ca.Type, &ca.KMSKeyID, &ca.SubjectDN, &ca.State, &ca.CACertB64,
		&pathLength, &ca.NotBefore, &ca.NotAfter, &ca.Description, &ca.Account, &ca.CreatedAt, &ca.UpdatedAt,
		&ca.ParentCAID, &ca.AccountID,
	)
	if err != nil {
		return ca, err
	}
	if pathLength.Valid {
		pl := int(pathLength.Int32)
		ca.PathLength = &pl
	}
	return ca, nil
}

// CreateCertificateAuthority inserts a new CA record into the database
func (s *Store) CreateCertificateAuthority(ctx context.Context, ca store.PCACertificateAuthority) error {
	query := `
		INSERT INTO pca_certificate_authorities (
			ca_id, urn, type, kms_key_id, subject_dn, state, ca_cert_b64,
			path_length, not_before, not_after, description, account, created_at, updated_at, account_id,
			parent_ca_id
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11, $12, $13, $14, $15, $16
		)
	`
	_, err := s.db.ExecContext(ctx, query,
		ca.CAID, ca.ARN, ca.Type, ca.KMSKeyID, ca.SubjectDN, ca.State, ca.CACertB64,
		ca.PathLength, ca.NotBefore, ca.NotAfter, ca.Description, ca.Account, ca.CreatedAt, ca.UpdatedAt, s.accountForContext(ctx),
		ca.ParentCAID,
	)
	if err != nil {
		return fmt.Errorf("insert CA: %w", err)
	}
	return nil
}

// DescribeCertificateAuthority retrieves a CA by its ARN
func (s *Store) DescribeCertificateAuthority(ctx context.Context, arn string) (store.PCACertificateAuthority, error) {
	cond, args := andAccount(ctx, "account_id", 2)
	row := s.db.QueryRowContext(ctx, `SELECT `+caColumns+` FROM pca_certificate_authorities WHERE urn = $1`+cond,
		append([]any{arn}, args...)...)
	ca, err := scanCA(row)
	if errors.Is(err, sql.ErrNoRows) {
		return store.PCACertificateAuthority{}, store.ErrCANotFound
	}
	if err != nil {
		return store.PCACertificateAuthority{}, fmt.Errorf("query CA: %w", err)
	}
	return ca, nil
}

// GetCertificateAuthorityByID retrieves a CA by its ID.
func (s *Store) GetCertificateAuthorityByID(ctx context.Context, caID string) (store.PCACertificateAuthority, error) {
	cond, args := andAccount(ctx, "account_id", 2)
	row := s.db.QueryRowContext(ctx, `SELECT `+caColumns+` FROM pca_certificate_authorities WHERE ca_id = $1`+cond,
		append([]any{caID}, args...)...)
	ca, err := scanCA(row)
	if errors.Is(err, sql.ErrNoRows) {
		return store.PCACertificateAuthority{}, store.ErrCANotFound
	}
	if err != nil {
		return store.PCACertificateAuthority{}, fmt.Errorf("query CA: %w", err)
	}
	return ca, nil
}

// ListCertificateAuthorities returns the caller account's CAs, newest first.
func (s *Store) ListCertificateAuthorities(ctx context.Context) ([]store.PCACertificateAuthority, error) {
	where, args := store.AccountFilter(ctx, "account_id", 1)
	if where != "" {
		where = " WHERE " + where
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+caColumns+` FROM pca_certificate_authorities`+where+` ORDER BY created_at DESC, ca_id`, args...)
	if err != nil {
		return nil, fmt.Errorf("query CAs: %w", err)
	}
	defer rows.Close()

	var cas []store.PCACertificateAuthority
	for rows.Next() {
		ca, err := scanCA(rows)
		if err != nil {
			return nil, fmt.Errorf("scan CA: %w", err)
		}
		cas = append(cas, ca)
	}
	return cas, rows.Err()
}

const certColumns = `cert_id, ca_id, serial, csr_b64, cert_b64, status,
	not_before, not_after, revoked_at, revocation_reason, template, created_at, updated_at,
	COALESCE(account_id, '')`

func scanCert(row interface{ Scan(...any) error }) (store.PCACertificate, error) {
	var cert store.PCACertificate
	var revokedAt sql.NullTime
	var revocationReason sql.NullString
	err := row.Scan(
		&cert.CertID, &cert.CAID, &cert.Serial, &cert.CSRB64, &cert.CertB64, &cert.Status,
		&cert.NotBefore, &cert.NotAfter, &revokedAt, &revocationReason, &cert.Template, &cert.CreatedAt, &cert.UpdatedAt,
		&cert.AccountID,
	)
	if err != nil {
		return cert, err
	}
	if revokedAt.Valid {
		t := revokedAt.Time
		cert.RevokedAt = &t
	}
	if revocationReason.Valid {
		cert.RevocationReason = revocationReason.String
	}
	return cert, nil
}

// CreateCertificate inserts a new certificate record into the database
func (s *Store) CreateCertificate(ctx context.Context, cert store.PCACertificate) error {
	query := `
		INSERT INTO pca_certificates (
			cert_id, ca_id, serial, csr_b64, cert_b64, status,
			not_before, not_after, revoked_at, revocation_reason, template, created_at, updated_at, account_id
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11, $12, $13, $14
		)
	`
	_, err := s.db.ExecContext(ctx, query,
		cert.CertID, cert.CAID, cert.Serial, cert.CSRB64, cert.CertB64, cert.Status,
		cert.NotBefore, cert.NotAfter, cert.RevokedAt, cert.RevocationReason, cert.Template, cert.CreatedAt, cert.UpdatedAt, s.accountForContext(ctx),
	)
	if err != nil {
		return fmt.Errorf("insert certificate: %w", err)
	}
	return nil
}

// GetCertificate retrieves a certificate by its ID
func (s *Store) GetCertificate(ctx context.Context, certID string) (store.PCACertificate, error) {
	cond, args := andAccount(ctx, "account_id", 2)
	row := s.db.QueryRowContext(ctx, `SELECT `+certColumns+` FROM pca_certificates WHERE cert_id = $1`+cond,
		append([]any{certID}, args...)...)
	cert, err := scanCert(row)
	if errors.Is(err, sql.ErrNoRows) {
		return store.PCACertificate{}, store.ErrCertificateNotFound
	}
	if err != nil {
		return store.PCACertificate{}, fmt.Errorf("query certificate: %w", err)
	}
	return cert, nil
}

// ListCertificates returns all certificates issued by a CA
func (s *Store) ListCertificates(ctx context.Context, caID string) ([]store.PCACertificate, error) {
	cond, args := andAccount(ctx, "account_id", 2)
	return s.queryCerts(ctx, `SELECT `+certColumns+` FROM pca_certificates WHERE ca_id = $1`+cond+` ORDER BY created_at DESC, cert_id`,
		append([]any{caID}, args...)...)
}

// FindCertificatesBySerial returns the certificates with a serial number.
func (s *Store) FindCertificatesBySerial(ctx context.Context, serial string) ([]store.PCACertificate, error) {
	cond, args := andAccount(ctx, "account_id", 2)
	return s.queryCerts(ctx, `SELECT `+certColumns+` FROM pca_certificates WHERE serial = $1`+cond+` ORDER BY created_at, cert_id`,
		append([]any{serial}, args...)...)
}

func (s *Store) queryCerts(ctx context.Context, q string, args ...any) ([]store.PCACertificate, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query certificates: %w", err)
	}
	defer rows.Close()
	var certs []store.PCACertificate
	for rows.Next() {
		cert, err := scanCert(rows)
		if err != nil {
			return nil, fmt.Errorf("scan certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, rows.Err()
}

// RevokeCertificate marks a certificate as revoked. It returns
// ErrCertificateAlreadyRevoked when it already was.
func (s *Store) RevokeCertificate(ctx context.Context, certID, reason string) error {
	cond, args := andAccount(ctx, "account_id", 3)
	result, err := s.db.ExecContext(ctx, `
		UPDATE pca_certificates
		SET status = 'REVOKED', revoked_at = NOW(), revocation_reason = $1, updated_at = NOW()
		WHERE cert_id = $2 AND status <> 'REVOKED'`+cond,
		append([]any{reason, certID}, args...)...)
	if err != nil {
		return fmt.Errorf("revoke certificate: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		if _, err := s.GetCertificate(ctx, certID); err != nil {
			return err
		}
		return store.ErrCertificateAlreadyRevoked
	}
	return nil
}
