package store

import (
	"context"
	"errors"
	"time"
)

// CA states used by the lifecycle (AWS ACM PCA names).
const (
	CAStateActive   = "ACTIVE"
	CAStateDisabled = "DISABLED"
	CAStateDeleted  = "DELETED"
)

// ErrCAStateConflict: the CA is not in a state the transition starts from.
var ErrCAStateConflict = errors.New("certificate authority is not in the required state")

// ACMELERenewalResult is the outcome of one automatic renewal attempt.
type ACMELERenewalResult struct {
	At time.Time
	// NewCertID is the replacement certificate; set on success.
	NewCertID string
	// Error and NextAttemptAt describe a failure.
	Error         string
	NextAttemptAt time.Time
}

// PKILifecycleStore covers deleting and restoring CAs (AWS PCA semantics),
// removing certificates from the console inventory, and the automatic
// renewal state of Let's Encrypt certificates. Reads and writes are scoped
// to the caller account on the context when one is present; without one
// (background jobs) they span every account.
type PKILifecycleStore interface {
	// TransitionCertificateAuthority moves a CA whose state is one of from
	// to state, setting RestorableUntil (nil clears it). It returns
	// ErrCANotFound, or ErrCAStateConflict when the CA is in another state.
	TransitionCertificateAuthority(ctx context.Context, caID string, from []string, state string, restorableUntil *time.Time) (PCACertificateAuthority, error)
	// CountOutstandingCertificates counts what a CA issued that is still
	// trusted at now: unexpired, unrevoked certificates, and unexpired
	// subordinate CAs that are not DELETED.
	CountOutstandingCertificates(ctx context.Context, caID string, now time.Time) (int, error)
	// ListCertificateAuthoritiesDueForPurge returns DELETED CAs whose
	// restore window ended before now.
	ListCertificateAuthoritiesDueForPurge(ctx context.Context, now time.Time) ([]PCACertificateAuthority, error)
	// PurgeCertificateAuthority permanently removes a DELETED CA past its
	// window, with its certificates; it reports false when the CA is not
	// (or no longer) due.
	PurgeCertificateAuthority(ctx context.Context, caID string, now time.Time) (bool, error)
	// HideCertificate removes a private CA certificate from the inventory.
	// The row is kept (with DeletedAt) so the CRL still lists it if revoked.
	HideCertificate(ctx context.Context, certID string, at time.Time) error

	DeleteACMELECertificate(ctx context.Context, certID string) error
	SetACMELEAutoRenew(ctx context.Context, certID string, on bool) error
	// ListACMELERenewalsDue returns auto-renewing, not yet renewed, issued
	// certificates expiring before renewBefore whose next attempt is due.
	ListACMELERenewalsDue(ctx context.Context, renewBefore, now time.Time, limit int) ([]ACMELECertificate, error)
	// ClaimACMELERenewal leases a due renewal until leaseUntil so only one
	// replica attempts it; it reports false when it is not due (any more).
	ClaimACMELERenewal(ctx context.Context, certID string, now, leaseUntil time.Time) (bool, error)
	RecordACMELERenewal(ctx context.Context, certID string, r ACMELERenewalResult) error
}
