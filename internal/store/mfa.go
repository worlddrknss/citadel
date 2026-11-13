package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrMFANotFound is returned when a user has no (or no matching)
	// enrolment.
	ErrMFANotFound = errors.New("mfa enrollment not found")
	// ErrMFAAlreadyEnabled is returned when starting an enrolment for a
	// user whose MFA is already active.
	ErrMFAAlreadyEnabled = errors.New("mfa already enabled")
)

// SessionMethodMFAEnrollment marks a restricted console session: a password
// sign-in by a user without MFA while the organization requires it. It can
// reach only the MFA enrolment endpoints.
const SessionMethodMFAEnrollment = "mfa_enrollment"

// MFAEnrollment is a console user's TOTP enrolment. SecretEnc is the shared
// secret sealed with AES-GCM by the server (the store never sees it in the
// clear). An enrolment is pending until confirmed with a valid code.
type MFAEnrollment struct {
	Username  string
	SecretEnc []byte
	Enabled   bool
	// LastStep is the last TOTP time step accepted, for replay protection.
	LastStep  int64
	CreatedAt time.Time
	EnabledAt time.Time // zero while pending
	// RecoveryCodesLeft counts unused recovery codes.
	RecoveryCodesLeft int
}

// MFAStore persists console multi-factor authentication: TOTP enrolments,
// single-use recovery codes (PBKDF2 hashes) and used pending-login tokens.
type MFAStore interface {
	// GetMFA returns username's enrolment, or ErrMFANotFound.
	GetMFA(ctx context.Context, username string) (MFAEnrollment, error)
	// PutPendingMFA stores a new unconfirmed enrolment, replacing any
	// pending one. It returns ErrMFAAlreadyEnabled when MFA is active.
	PutPendingMFA(ctx context.Context, username string, secretEnc []byte, now time.Time) error
	// EnableMFA atomically activates the pending enrolment whose sealed
	// secret is secretEnc, records step as the last accepted step and
	// replaces the recovery codes. ErrMFANotFound when no such pending
	// enrolment exists (it was replaced or already confirmed).
	EnableMFA(ctx context.Context, username string, secretEnc []byte, step int64, recoveryHashes []string, now time.Time) error
	// AdvanceMFAStep records step as the last accepted step when it is
	// later than the stored one. It reports false (a replay) otherwise, so
	// two concurrent uses of one code cannot both succeed.
	AdvanceMFAStep(ctx context.Context, username string, step int64) (bool, error)
	// DeleteMFA removes username's enrolment and recovery codes and reports
	// whether an enrolment existed.
	DeleteMFA(ctx context.Context, username string) (bool, error)
	// ListMFARecoveryCodeHashes returns the hashes of username's unused
	// recovery codes.
	ListMFARecoveryCodeHashes(ctx context.Context, username string) ([]string, error)
	// ConsumeMFARecoveryCode marks one unused recovery code used and
	// reports whether it was still unused (exactly one caller wins).
	ConsumeMFARecoveryCode(ctx context.Context, username, codeHash string) (bool, error)
	// ReplaceMFARecoveryCodes swaps all of username's recovery codes for
	// new ones. It returns ErrMFANotFound when MFA is not enabled.
	ReplaceMFARecoveryCodes(ctx context.Context, username string, hashes []string) error
	// ListMFAEnabledUsers returns the usernames with active MFA.
	ListMFAEnabledUsers(ctx context.Context) ([]string, error)
	// UseMFALoginToken records a pending-login token ID as spent and
	// reports false when it already was. Expired records may be purged.
	UseMFALoginToken(ctx context.Context, id string, expiresAt, now time.Time) (bool, error)
}
