package main

import (
	"context"
	"database/sql"
	"fmt"
)

// CreateCertificateAuthority inserts a new CA record into the database
func (s *dbStore) CreateCertificateAuthority(ctx context.Context, ca pcaCertificateAuthority) error {
	query := `
		INSERT INTO pca_certificate_authorities (
			ca_id, urn, type, kms_key_id, subject_dn, state, ca_cert_b64,
			path_length, not_before, not_after, description, account, created_at, updated_at, account_id
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11, $12, $13, $14, $15
		)
	`
	_, err := s.db.ExecContext(ctx, query,
		ca.CAID, ca.ARN, ca.Type, ca.KMSKeyID, ca.SubjectDN, ca.State, ca.CACertB64,
		ca.PathLength, ca.NotBefore, ca.NotAfter, ca.Description, ca.Account, ca.CreatedAt, ca.UpdatedAt, s.accountForContext(ctx),
	)
	if err != nil {
		return fmt.Errorf("insert CA: %w", err)
	}
	return nil
}

// DescribeCertificateAuthority retrieves a CA by its ARN
func (s *dbStore) DescribeCertificateAuthority(ctx context.Context, arn string) (pcaCertificateAuthority, error) {
	query := `
		SELECT ca_id, urn, type, kms_key_id, subject_dn, state, ca_cert_b64,
		       path_length, not_before, not_after, description, account, created_at, updated_at
		FROM pca_certificate_authorities
		WHERE urn = $1
	`
	row := s.db.QueryRowContext(ctx, query, arn)
	var ca pcaCertificateAuthority
	var pathLength sql.NullInt32
	err := row.Scan(
		&ca.CAID, &ca.ARN, &ca.Type, &ca.KMSKeyID, &ca.SubjectDN, &ca.State, &ca.CACertB64,
		&pathLength, &ca.NotBefore, &ca.NotAfter, &ca.Description, &ca.Account, &ca.CreatedAt, &ca.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return pcaCertificateAuthority{}, fmt.Errorf("certificate authority not found")
		}
		return pcaCertificateAuthority{}, fmt.Errorf("query CA: %w", err)
	}
	if pathLength.Valid {
		pl := int(pathLength.Int32)
		ca.PathLength = &pl
	}
	return ca, nil
}

// ListCertificateAuthorities returns all CAs for the current account
func (s *dbStore) ListCertificateAuthorities(ctx context.Context) ([]pcaCertificateAuthority, error) {
	query := `
		SELECT ca_id, urn, type, kms_key_id, subject_dn, state, ca_cert_b64,
		       path_length, not_before, not_after, description, account, created_at, updated_at
		FROM pca_certificate_authorities
		ORDER BY created_at DESC
	`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query CAs: %w", err)
	}
	defer rows.Close()

	var cas []pcaCertificateAuthority
	for rows.Next() {
		var ca pcaCertificateAuthority
		var pathLength sql.NullInt32
		err := rows.Scan(
			&ca.CAID, &ca.ARN, &ca.Type, &ca.KMSKeyID, &ca.SubjectDN, &ca.State, &ca.CACertB64,
			&pathLength, &ca.NotBefore, &ca.NotAfter, &ca.Description, &ca.Account, &ca.CreatedAt, &ca.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan CA: %w", err)
		}
		if pathLength.Valid {
			pl := int(pathLength.Int32)
			ca.PathLength = &pl
		}
		cas = append(cas, ca)
	}
	return cas, rows.Err()
}

// CreateCertificate inserts a new certificate record into the database
func (s *dbStore) CreateCertificate(ctx context.Context, cert pcaCertificate) error {
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
func (s *dbStore) GetCertificate(ctx context.Context, certID string) (pcaCertificate, error) {
	query := `
		SELECT cert_id, ca_id, serial, csr_b64, cert_b64, status,
		       not_before, not_after, revoked_at, revocation_reason, template, created_at, updated_at
		FROM pca_certificates
		WHERE cert_id = $1
	`
	row := s.db.QueryRowContext(ctx, query, certID)
	var cert pcaCertificate
	var revokedAt sql.NullTime
	var revocationReason sql.NullString
	err := row.Scan(
		&cert.CertID, &cert.CAID, &cert.Serial, &cert.CSRB64, &cert.CertB64, &cert.Status,
		&cert.NotBefore, &cert.NotAfter, &revokedAt, &revocationReason, &cert.Template, &cert.CreatedAt, &cert.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return pcaCertificate{}, fmt.Errorf("certificate not found")
		}
		return pcaCertificate{}, fmt.Errorf("query certificate: %w", err)
	}
	if revokedAt.Valid {
		cert.RevokedAt = &revokedAt.Time
	}
	if revocationReason.Valid {
		cert.RevocationReason = revocationReason.String
	}
	return cert, nil
}

// ListCertificates returns all certificates issued by a CA
func (s *dbStore) ListCertificates(ctx context.Context, caID string) ([]pcaCertificate, error) {
	query := `
		SELECT cert_id, ca_id, serial, csr_b64, cert_b64, status,
		       not_before, not_after, revoked_at, revocation_reason, template, created_at, updated_at
		FROM pca_certificates
		WHERE ca_id = $1
		ORDER BY created_at DESC
	`
	rows, err := s.db.QueryContext(ctx, query, caID)
	if err != nil {
		return nil, fmt.Errorf("query certificates: %w", err)
	}
	defer rows.Close()

	var certs []pcaCertificate
	for rows.Next() {
		var cert pcaCertificate
		var revokedAt sql.NullTime
		var revocationReason sql.NullString
		err := rows.Scan(
			&cert.CertID, &cert.CAID, &cert.Serial, &cert.CSRB64, &cert.CertB64, &cert.Status,
			&cert.NotBefore, &cert.NotAfter, &revokedAt, &revocationReason, &cert.Template, &cert.CreatedAt, &cert.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan certificate: %w", err)
		}
		if revokedAt.Valid {
			cert.RevokedAt = &revokedAt.Time
		}
		if revocationReason.Valid {
			cert.RevocationReason = revocationReason.String
		}
		certs = append(certs, cert)
	}
	return certs, rows.Err()
}

// RevokeCertificate marks a certificate as revoked
func (s *dbStore) RevokeCertificate(ctx context.Context, certID, reason string) error {
	query := `
		UPDATE pca_certificates
		SET status = 'REVOKED', revoked_at = NOW(), revocation_reason = $1, updated_at = NOW()
		WHERE cert_id = $2
	`
	result, err := s.db.ExecContext(ctx, query, reason, certID)
	if err != nil {
		return fmt.Errorf("revoke certificate: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("certificate not found")
	}
	return nil
}

// inMemoryStore CA implementations (unsupported)
func (s *inMemoryStore) CreateCertificateAuthority(_ context.Context, _ pcaCertificateAuthority) error {
	return errUnsupported
}

func (s *inMemoryStore) DescribeCertificateAuthority(_ context.Context, _ string) (pcaCertificateAuthority, error) {
	return pcaCertificateAuthority{}, errUnsupported
}

func (s *inMemoryStore) ListCertificateAuthorities(_ context.Context) ([]pcaCertificateAuthority, error) {
	return nil, errUnsupported
}

func (s *inMemoryStore) CreateCertificate(_ context.Context, _ pcaCertificate) error {
	return errUnsupported
}

func (s *inMemoryStore) GetCertificate(_ context.Context, _ string) (pcaCertificate, error) {
	return pcaCertificate{}, errUnsupported
}

func (s *inMemoryStore) ListCertificates(_ context.Context, _ string) ([]pcaCertificate, error) {
	return nil, errUnsupported
}

func (s *inMemoryStore) RevokeCertificate(_ context.Context, _, _ string) error {
	return errUnsupported
}
