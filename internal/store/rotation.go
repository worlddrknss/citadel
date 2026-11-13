package store

import (
	"context"
	"errors"
	"time"
)

// Built-in secret rotation: the rotator configured for a secret, its
// schedule, the state of the latest rotation (with a lease so only one
// replica runs it) and a history of attempts.
//
// The schedule's next window start stays in sm_secrets.next_rotation_date
// (SecretMetadataRecord.NextRotationDate), as before; everything else lives in
// a row per secret that exists once rotation has been configured.

// Rotator types.
const (
	RotatorRandom     = "random"
	RotatorPostgreSQL = "postgresql"
	RotatorWebhook    = "webhook"
)

// Rotation statuses (SecretRotation.Status).
const (
	RotationStatusNever     = ""
	RotationStatusRunning   = "running"
	RotationStatusSucceeded = "succeeded"
	// RotationStatusRetrying: the last attempt failed and another is
	// scheduled (NextAttemptAt).
	RotationStatusRetrying = "retrying"
	// RotationStatusFailed: retries are exhausted; the rotation is
	// reattempted at the next window.
	RotationStatusFailed = "failed"
)

var (
	// ErrRotationLeaseLost: the lease on a rotation expired and was taken by
	// someone else before its state was saved.
	ErrRotationLeaseLost = errors.New("rotation lease lost")
	// ErrRotationNotConfigured: the secret has no rotation row.
	ErrRotationNotConfigured = errors.New("rotation is not configured for this secret")
)

// SecretRotation is a secret's built-in rotation configuration and state.
type SecretRotation struct {
	SecretName string
	// RotatorType is "" for a schedule without a built-in rotator (a Lambda
	// ARN Citadel cannot run).
	RotatorType string
	// ConfigSecret names a secret in the same account whose JSON value holds
	// the rotator's configuration ("" when Config is used).
	ConfigSecret string
	// Config is the rotator's inline configuration, JSON without secrets.
	Config string
	// SigningKeySealed is the webhook rotator's HMAC key, sealed by the
	// server (nil when none).
	SigningKeySealed []byte
	// ScheduleExpression is rate(...) or cron(...); "" when the schedule is
	// SecretMetadataRecord.RotationDays (AutomaticallyAfterDays).
	ScheduleExpression string
	// Duration is the rotation window ("3h"); "" for AWS's default.
	Duration string

	Status        string
	LastStep      string
	LastError     string
	Attempts      int
	LastAttemptAt *time.Time
	NextAttemptAt *time.Time
	LastRotatedAt *time.Time
	LeaseOwner    string
	LeaseUntil    *time.Time
	UpdatedAt     time.Time
	UpdatedBy     string
}

// SecretRotationConfig enables rotation on a secret and stores its rotator
// and schedule. State (status, attempts, history) is kept, except that a
// reconfiguration clears pending retries.
type SecretRotationConfig struct {
	SecretID           string
	LambdaARN          string
	AfterDays          int
	ScheduleExpression string
	Duration           string
	NextRotationDate   *time.Time
	RotatorType        string
	ConfigSecret       string
	Config             string
	// SigningKeySealed replaces the stored signing key when non-nil; the
	// existing one is kept otherwise, unless ClearSigningKey is set.
	SigningKeySealed []byte
	ClearSigningKey  bool
}

// SecretRotationStateUpdate records the outcome of (a step of) a rotation.
// Nil pointers leave LastRotatedAt and NextRotationDate unchanged;
// NextAttemptAt nil clears it.
type SecretRotationStateUpdate struct {
	Status           string
	LastStep         string
	LastError        string
	Attempts         int
	LastAttemptAt    time.Time
	NextAttemptAt    *time.Time
	LastRotatedAt    *time.Time
	NextRotationDate *time.Time
	// KeepLease keeps the caller's lease (a progress update); otherwise the
	// lease is released.
	KeepLease bool
}

// DueSecretRotation names a secret whose rotation should run now.
type DueSecretRotation struct {
	AccountID  string
	SecretName string
}

// SecretRotationEvent is one rotation attempt in a secret's history.
type SecretRotationEvent struct {
	ID          int64
	Token       string
	RotatorType string
	Trigger     string // "schedule", "immediate", "retry"
	Status      string // RotationStatusSucceeded or RotationStatusFailed
	Step        string // the step that failed, or "finishSecret"
	Error       string
	StartedAt   time.Time
	FinishedAt  time.Time
	Actor       string
}

// SecretRotationSummary is the list view of a secret's rotation state.
type SecretRotationSummary struct {
	RotatorType string
	Status      string
}

// SecretRotationStore persists built-in rotation. Reads and writes are scoped
// to the caller account, except ListDueSecretRotations (the background job
// spans every account).
type SecretRotationStore interface {
	// GetSecretRotation returns the secret's rotation row, or
	// ErrRotationNotConfigured.
	GetSecretRotation(ctx context.Context, secretID string) (SecretRotation, error)
	// ConfigureSecretRotation turns rotation on with cfg (sm_secrets fields
	// and the rotation row) in one transaction.
	ConfigureSecretRotation(ctx context.Context, cfg SecretRotationConfig) (SecretMetadataRecord, error)
	// PutPendingSecretVersion stores a new version labelled AWSPENDING only
	// (the label moves off any other version). A version with the same
	// token is returned unchanged.
	PutPendingSecretVersion(ctx context.Context, secretID, token, secretString, secretBinary string) (SecretValueRecord, error)
	// FinishSecretRotation moves AWSCURRENT to token, AWSPREVIOUS to the
	// version that was current, and removes AWSPENDING from token, in one
	// transaction. It is a no-op when token is already AWSCURRENT.
	FinishSecretRotation(ctx context.Context, secretID, token string) (SecretMetadataRecord, error)
	// ClaimSecretRotation takes the secret's rotation lease for owner when
	// it is free or expired, reporting whether it did.
	ClaimSecretRotation(ctx context.Context, secretID, owner string, lease time.Duration) (bool, error)
	// SaveSecretRotationState stores upd if owner holds the lease
	// (ErrRotationLeaseLost otherwise).
	SaveSecretRotationState(ctx context.Context, secretID, owner string, upd SecretRotationStateUpdate) error
	// ReleaseSecretRotation gives up owner's lease without changing state.
	ReleaseSecretRotation(ctx context.Context, secretID, owner string) error
	// ListDueSecretRotations returns, across all accounts, secrets with a
	// built-in rotator whose next window or retry has come and whose lease
	// is free.
	ListDueSecretRotations(ctx context.Context, now time.Time, limit int) ([]DueSecretRotation, error)
	AppendSecretRotationHistory(ctx context.Context, secretID string, e SecretRotationEvent) error
	// ListSecretRotationHistory returns the newest events first.
	ListSecretRotationHistory(ctx context.Context, secretID string, limit int) ([]SecretRotationEvent, error)
	// ListSecretRotationSummaries maps secret names to their rotation state
	// for every configured secret in the account.
	ListSecretRotationSummaries(ctx context.Context) (map[string]SecretRotationSummary, error)
}

// MaxRotationHistory is how many history events are kept per secret.
const MaxRotationHistory = 50

// FinishRotationStages applies finishSecret's label moves to meta: AWSCURRENT
// to token, AWSPREVIOUS to the version that was current, and AWSPENDING off
// token. It reports whether AWSCURRENT moved (false when token was already
// current; a leftover AWSPENDING on it is still removed).
func FinishRotationStages(meta *SecretMetadataRecord, token string) bool {
	EnsureSecretStageMap(meta)
	moved := meta.CurrentVersionID != token
	if moved {
		PromoteSecretVersion(meta, token)
	}
	RemoveSecretStage(meta, PendingVersionStage, token)
	return moved
}

// RotationIsDue reports whether a secret with rotation row r should rotate at
// now: a built-in rotator, rotation enabled, not deleted, lease free, and
// either a retry that has come or (with no retry scheduled) a window that
// has started.
func RotationIsDue(meta SecretMetadataRecord, r *SecretRotation, now time.Time) bool {
	if r == nil || r.RotatorType == "" || !meta.RotationEnabled || meta.DeletedDate != nil {
		return false
	}
	if r.LeaseUntil != nil && r.LeaseUntil.After(now) {
		return false
	}
	if r.NextAttemptAt != nil {
		return !r.NextAttemptAt.After(now)
	}
	return meta.NextRotationDate != nil && !meta.NextRotationDate.After(now)
}

// PendingRotationToken returns the version carrying AWSPENDING when it is not
// also AWSCURRENT: an unfinished rotation to resume ("" when none).
func PendingRotationToken(meta SecretMetadataRecord) string {
	EnsureSecretStageMap(&meta)
	for id, stages := range meta.VersionStages {
		if ContainsString(stages, PendingVersionStage) && !ContainsString(stages, CurrentVersionStage) {
			return id
		}
	}
	return ""
}
