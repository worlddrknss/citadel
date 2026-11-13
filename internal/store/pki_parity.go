package store

import (
	"context"
	"errors"
	"time"
)

// ErrCANotPending is returned when a CA certificate is installed on a CA that
// is not waiting for one (state PENDING_CERTIFICATE).
var ErrCANotPending = errors.New("certificate authority is not pending a certificate")

// CAStatePendingCertificate is the state of a subordinate CA created through
// the ACM PCA API until its signed certificate is imported.
const CAStatePendingCertificate = "PENDING_CERTIFICATE"

// ACMIdempotencyWindow is how long an ACM IdempotencyToken maps to the
// certificate its first request created, as in AWS.
const ACMIdempotencyWindow = time.Hour

// ACMIdempotencyRecord ties an ACM IdempotencyToken to the certificate the
// first request using it created. ParamsHash is a digest of the request
// parameters, so a reuse with different parameters can be told apart.
type ACMIdempotencyRecord struct {
	AccountID  string
	Operation  string // RequestCertificate or ImportCertificate
	Token      string
	ParamsHash string
	ARN        string
	CreatedAt  time.Time
}

// PKIParityStore holds the state behind ACM idempotency tokens and the ACM
// PCA subordinate-CA flow (a CA created without a certificate, its CSR, and
// installing the certificate its parent signed). Reads and writes are scoped
// to the caller account on the context.
type PKIParityStore interface {
	// ClaimACMIdempotencyToken records rec unless the account already holds a
	// record for (rec.Operation, rec.Token) created at or after notBefore. It
	// returns the record now in force and whether rec was stored; an older
	// record is replaced.
	ClaimACMIdempotencyToken(ctx context.Context, rec ACMIdempotencyRecord, notBefore time.Time) (ACMIdempotencyRecord, bool, error)
	// ReleaseACMIdempotencyToken drops a claim whose request failed. It only
	// removes the record if it still names arn.
	ReleaseACMIdempotencyToken(ctx context.Context, operation, token, arn string) error

	// PutCertificateAuthorityCSR stores the CSR (base64 PEM) of a pending CA.
	PutCertificateAuthorityCSR(ctx context.Context, caID, csrB64 string) error
	// GetCertificateAuthorityCSR returns ErrCANotFound when the CA has none.
	GetCertificateAuthorityCSR(ctx context.Context, caID string) (string, error)
	// ActivateCertificateAuthority installs ca's certificate (CACertB64,
	// SubjectDN, PathLength, NotBefore, NotAfter, ParentCAID) and moves it to
	// ACTIVE. It returns ErrCANotFound for an unknown CA and ErrCANotPending
	// unless the CA is in PENDING_CERTIFICATE.
	ActivateCertificateAuthority(ctx context.Context, ca PCACertificateAuthority) error
}
