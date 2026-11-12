package store

import (
	"context"
	"errors"
	"time"
)

// Change requests and approval policies.
//
// An approval policy says that value writes into one project/environment of an
// account need approvalsRequired distinct approvals before they apply. A change
// request is one proposed write held until then. Its proposed value is stored
// only as ciphertext, sealed under the account's default KMS key exactly like a
// secret version (see BuildSecretCiphertext), never in plaintext.
//
// Everything here is scoped to the caller account on the context.

// Change request states.
const (
	ChangeRequestPending  = "pending"
	ChangeRequestApproved = "approved"
	ChangeRequestRejected = "rejected"
)

var (
	ErrChangeRequestNotFound = errors.New("change request not found")
	// ErrChangeRequestDecided means the request is no longer in the state the
	// caller expected (someone else approved, rejected or applied it first).
	ErrChangeRequestDecided = errors.New("change request already decided")
	// ErrAlreadyApproved means this approver has already approved it.
	ErrAlreadyApproved = errors.New("already approved by this user")
)

// ApprovalPolicy requires approvals for value writes in one environment.
type ApprovalPolicy struct {
	Project           string
	Env               string
	ApprovalsRequired int
	// ApproverRoles are console roles allowed to approve ("admin",
	// "editor"); a role at or above any listed role qualifies.
	ApproverRoles []string
	UpdatedAt     time.Time
	UpdatedBy     string
}

// ChangeRequestApproval is one approver's sign-off.
type ChangeRequestApproval struct {
	Username  string
	Comment   string
	DecidedAt time.Time
}

// ChangeRequestRecord is a persisted change request.
type ChangeRequestRecord struct {
	ID      string
	Project string
	Env     string
	// Path is the folder in "/" or "/a/b" form.
	Path string
	Key  string

	Requester     string
	RequesterRole string
	Title         string
	Comment       string
	Status        string

	// ProposedCiphertext is the base64 envelope (cryptoutil blob) of the
	// proposed value, sealed under ProposedKMSKeyID (the account default key
	// at creation time).
	ProposedCiphertext string
	ProposedKMSKeyID   string
	// ProposedLength is the proposed value's length in characters.
	ProposedLength int
	// TargetKMSKeyID is the KMS key requested for the item ("" = the item's
	// current key, or the default for a new item).
	TargetKMSKeyID string
	// BaseVersionID is the item's current version when the request was made
	// ("" for a new item); it identifies the "previous" value.
	BaseVersionID string

	CreatedAt       time.Time
	DecidedBy       string
	DecidedAt       *time.Time
	DecisionComment string
	Approvals       []ChangeRequestApproval
}

// ApprovalPolicyReader is the read side of approval policies. It is the
// supported way for other parts of Citadel (for example an organization-wide
// "approvalEnvironments" setting) to ask whether an environment requires
// approval: GetApprovalPolicy reports ok=false when no policy applies.
type ApprovalPolicyReader interface {
	ListApprovalPolicies(ctx context.Context) ([]ApprovalPolicy, error)
	GetApprovalPolicy(ctx context.Context, project, env string) (ApprovalPolicy, bool, error)
}

// ApprovalStore persists approval policies and change requests.
type ApprovalStore interface {
	ApprovalPolicyReader
	// PutApprovalPolicy creates or replaces a policy; ApprovalsRequired <= 0
	// removes it.
	PutApprovalPolicy(ctx context.Context, p ApprovalPolicy) error

	CreateChangeRequest(ctx context.Context, cr ChangeRequestRecord) (ChangeRequestRecord, error)
	GetChangeRequest(ctx context.Context, id string) (ChangeRequestRecord, error)
	// ListChangeRequests returns the account's requests, newest first.
	ListChangeRequests(ctx context.Context) ([]ChangeRequestRecord, error)
	// AddChangeRequestApproval records an approval on a pending request. It
	// fails with ErrChangeRequestDecided when the request is not pending and
	// ErrAlreadyApproved when this username already approved it.
	AddChangeRequestApproval(ctx context.Context, id string, a ChangeRequestApproval) (ChangeRequestRecord, error)
	// TransitionChangeRequest atomically moves a request from one status to
	// another, returning ErrChangeRequestDecided when it is not in from.
	// Moving back to pending clears the decision fields.
	TransitionChangeRequest(ctx context.Context, id, from, to, decidedBy, comment string) (ChangeRequestRecord, error)
}

// SecretSettings are per-account secrets settings.
type SecretSettings struct {
	// ViewersCanReveal lets the viewer role read secret values (reveal,
	// version values, .env export, SecureString parameters). The default,
	// false, limits value reads to editors and admins.
	ViewersCanReveal bool
	UpdatedAt        time.Time
	UpdatedBy        string
}

// SecretSettingsStore persists SecretSettings for the caller account.
type SecretSettingsStore interface {
	GetSecretSettings(ctx context.Context) (SecretSettings, error)
	PutSecretSettings(ctx context.Context, s SecretSettings) error
}

// PurgedSecret identifies a secret removed by PurgeExpiredSecrets.
type PurgedSecret struct {
	AccountID string
	Name      string
	KMSKeyID  string
}

// SecretLifecycleStore holds secret operations beyond the AWS API surface.
type SecretLifecycleStore interface {
	// RenameSecret moves a secret, with its versions, stages, tags and
	// policy, to a new name in the same account. It fails with
	// ErrSecretExists when newName is taken.
	RenameSecret(ctx context.Context, oldName, newName string) (SecretMetadataRecord, error)
	// PurgeExpiredSecrets permanently deletes, across ALL accounts, every
	// secret whose scheduled deletion date is at or before now. It is meant
	// for the background purge job only.
	PurgeExpiredSecrets(ctx context.Context, now time.Time) ([]PurgedSecret, error)
}
