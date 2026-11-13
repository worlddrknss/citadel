package store

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
)

// Just-in-time agent access (2.3): access requests and leases.
//
//   - AgentAccessRequest: an agent asking a person for access. Created when
//     a grant with requiresApproval is used without a lease (origin
//     "policy"), or when the agent asks for access it does not have (origin
//     "agent"). At most one pending request exists per (agent, credential,
//     actions, task ID); asking again returns it. A request is pending until
//     it is approved, denied, cancelled or it expires.
//   - AgentLease: time-boxed access to a credential for some actions, made
//     by an approval or by a grant's leaseTtl. A lease is single use
//     ("once"), valid until it expires ("duration"), or bound to one task ID
//     ("task"). Leases end at expiry, when their uses run out, when revoked
//     in the console, and when the agent is suspended or revoked or the
//     account's kill switch is used.

// Access request statuses.
const (
	AgentRequestPending   = "pending"
	AgentRequestApproved  = "approved"
	AgentRequestDenied    = "denied"
	AgentRequestExpired   = "expired"
	AgentRequestCancelled = "cancelled"
)

// Access request origins.
const (
	// AgentRequestOriginPolicy: a grant with requiresApproval was used
	// without a lease.
	AgentRequestOriginPolicy = "policy"
	// AgentRequestOriginAgent: the agent asked (request_access).
	AgentRequestOriginAgent = "agent"
)

// Lease scopes.
const (
	AgentLeaseOnce     = "once"
	AgentLeaseDuration = "duration"
	AgentLeaseTask     = "task"
)

var (
	ErrAgentAccessRequestNotFound = errors.New("agent access request not found")
	// ErrAgentAccessRequestDecided: the request is no longer pending
	// (decided, cancelled or expired).
	ErrAgentAccessRequestDecided = errors.New("the agent access request is no longer pending")
	ErrAgentLeaseNotFound        = errors.New("agent lease not found")
	// ErrAgentLeaseEnded: the lease is already revoked or expired.
	ErrAgentLeaseEnded = errors.New("the agent lease has already ended")
)

// AgentAccessRequest is an agent's request for access.
type AgentAccessRequest struct {
	AccountID  string
	RequestID  string
	AgentID    string
	Credential string
	// Actions are sorted and unique.
	Actions []string
	// Reason is the agent's explanation (never a secret, but untrusted
	// text: render it as text).
	Reason string
	// TaskID is the agent's task ID ("" for none). A task-scoped approval
	// binds the lease to it.
	TaskID string
	// DurationSeconds is how long the agent asked for (0: no preference).
	DurationSeconds int
	Origin          string
	Status          string
	CreatedAt       time.Time
	// ExpiresAt is when a pending request lapses.
	ExpiresAt time.Time
	DecidedAt *time.Time
	DecidedBy string
	// DecisionComment is the approver's comment or the denial reason.
	DecisionComment string
	// Scope and LeaseID are set when approved.
	Scope   string
	LeaseID string
}

// EffectiveStatus is Status, reporting a pending request past its expiry as
// expired.
func (r AgentAccessRequest) EffectiveStatus(now time.Time) string {
	if r.Status == AgentRequestPending && !now.Before(r.ExpiresAt) {
		return AgentRequestExpired
	}
	return r.Status
}

// AgentActionsKey is the canonical form of actions used to match requests.
func AgentActionsKey(actions []string) string {
	a := slices.Clone(actions)
	slices.Sort(a)
	return strings.Join(slices.Compact(a), ",")
}

// AgentLease is time-boxed access to a credential.
type AgentLease struct {
	AccountID  string
	LeaseID    string
	AgentID    string
	Credential string
	Actions    []string
	Scope      string
	// TaskID binds a task-scoped lease.
	TaskID string
	// UsesLeft is nil for unlimited uses (until expiry); 1 for once.
	UsesLeft  *int
	UseCount  int
	ExpiresAt time.Time
	CreatedAt time.Time
	// CreatedBy is the approver, or "policy" for a lease made by a grant's
	// leaseTtl.
	CreatedBy string
	// RequestID is the access request the lease answers ("" for leaseTtl).
	RequestID   string
	LastUsedAt  *time.Time
	EndedAt     *time.Time
	EndedBy     string
	EndedReason string
}

// HasAction reports whether the lease covers action.
func (l AgentLease) HasAction(action string) bool { return slices.Contains(l.Actions, action) }

// Active reports whether the lease is usable at now.
func (l AgentLease) Active(now time.Time) bool {
	return l.EndedAt == nil && now.Before(l.ExpiresAt) && (l.UsesLeft == nil || *l.UsesLeft > 0)
}

// AgentLeaseMatch selects a lease to use.
type AgentLeaseMatch struct {
	AccountID  string
	AgentID    string
	Credential string
	Action     string
	// TaskID is the caller's task ID; task-scoped leases match only it.
	TaskID string
	Now    time.Time
}

// AgentAccessRequestFilter narrows ListAgentAccessRequests.
type AgentAccessRequestFilter struct {
	// AgentID limits to one agent ("" for every agent in the account).
	AgentID string
	// Pending limits to requests still pending (not expired) at Now.
	Pending bool
	Now     time.Time
	// Limit caps the result (newest first); 0 means 200.
	Limit int
}

// AgentAccessDecision decides a pending request.
type AgentAccessDecision struct {
	// Status is AgentRequestApproved, AgentRequestDenied or
	// AgentRequestCancelled.
	Status  string
	By      string
	Comment string
	At      time.Time
	// Lease is stored with an approval (its RequestID is set by the store).
	Lease *AgentLease
}

// AgentAccessStore persists access requests and leases.
type AgentAccessStore interface {
	// OpenAgentAccessRequest returns the pending request for the same
	// agent, credential, actions and task ID, or stores r as a new one
	// (created reports which). Pending requests past their expiry are
	// marked expired first. Concurrent calls return the same request.
	OpenAgentAccessRequest(ctx context.Context, r AgentAccessRequest, now time.Time) (out AgentAccessRequest, created bool, err error)
	GetAgentAccessRequest(ctx context.Context, accountID, requestID string) (AgentAccessRequest, error)
	ListAgentAccessRequests(ctx context.Context, accountID string, f AgentAccessRequestFilter) ([]AgentAccessRequest, error)
	// CountPendingAgentAccessRequests counts an agent's unexpired pending
	// requests.
	CountPendingAgentAccessRequests(ctx context.Context, accountID, agentID string, now time.Time) (int, error)
	// DecideAgentAccessRequest moves a pending, unexpired request to
	// d.Status, storing d.Lease with an approval, atomically
	// (ErrAgentAccessRequestDecided when it is no longer pending, so two
	// concurrent decisions can't both win).
	DecideAgentAccessRequest(ctx context.Context, accountID, requestID string, d AgentAccessDecision) (AgentAccessRequest, error)
	// CancelAgentAccessRequests cancels an agent's pending requests.
	CancelAgentAccessRequests(ctx context.Context, accountID, agentID, by, comment string, at time.Time) (int, error)

	CreateAgentLease(ctx context.Context, l AgentLease) error
	GetAgentLease(ctx context.Context, accountID, leaseID string) (AgentLease, error)
	// ListAgentLeases lists an agent's leases ("" for every agent in the
	// account), newest first; activeOnly keeps those usable at now.
	ListAgentLeases(ctx context.Context, accountID, agentID string, activeOnly bool, now time.Time) ([]AgentLease, error)
	// FindAgentLease returns a lease usable for m without using it (ok
	// false when there is none).
	FindAgentLease(ctx context.Context, m AgentLeaseMatch) (AgentLease, bool, error)
	// ConsumeAgentLease atomically uses one lease that matches m: a lease
	// with unlimited uses first, then the one expiring soonest. A
	// single-use lease is used at most once even under concurrency. ok is
	// false when no lease matches.
	ConsumeAgentLease(ctx context.Context, m AgentLeaseMatch) (AgentLease, bool, error)
	// EndAgentLease ends one active lease (ErrAgentLeaseEnded when it had
	// already ended or expired).
	EndAgentLease(ctx context.Context, accountID, leaseID, by, reason string, at time.Time) (AgentLease, error)
	// EndAgentLeases ends every active lease of an agent, or of every agent
	// in the account when agentID is "", returning how many ended.
	EndAgentLeases(ctx context.Context, accountID, agentID, by, reason string, at time.Time) (int, error)
}

// NewAgentAccessRequestID returns "aar_" + 16 base32 characters.
func NewAgentAccessRequestID() string { return NewAgentObjectID("aar_") }

// NewAgentLeaseID returns "als_" + 16 base32 characters.
func NewAgentLeaseID() string { return NewAgentObjectID("als_") }

// IsAgentObjectID reports whether s is prefix + 16 base32 characters.
func IsAgentObjectID(s, prefix string) bool {
	rest, ok := strings.CutPrefix(s, prefix)
	if !ok || len(rest) != 16 {
		return false
	}
	for _, c := range rest {
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}
