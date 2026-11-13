package citadel

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"
)

// Just-in-time agent access (Citadel 2.3): access requests and leases. See
// docs/agents.md, "Approvals and leases".
//
// Approving or denying takes a person signed in to the console; access keys
// are refused, so the SDK lists requests and leases and revokes leases but
// does not decide requests.

// AgentLease is time-boxed access to a credential, from an approval or a
// grant's LeaseTTLSeconds.
type AgentLease struct {
	LeaseID    string   `json:"leaseId"`
	AgentID    string   `json:"agentId"`
	AgentName  string   `json:"agentName,omitempty"`
	Credential string   `json:"credential"`
	Actions    []string `json:"actions"`
	// Scope is once, duration or task.
	Scope  string `json:"scope"`
	TaskID string `json:"taskId,omitempty"`
	// UsesLeft is nil for unlimited uses until ExpiresAt.
	UsesLeft  *int      `json:"usesLeft"`
	UseCount  int       `json:"useCount"`
	ExpiresAt time.Time `json:"expiresAt"`
	CreatedAt time.Time `json:"createdAt"`
	CreatedBy string    `json:"createdBy"`
	RequestID string    `json:"requestId,omitempty"`
	// Status is active, expired, used or ended.
	Status      string     `json:"status"`
	LastUsedAt  *time.Time `json:"lastUsedAt,omitempty"`
	EndedAt     *time.Time `json:"endedAt,omitempty"`
	EndedBy     string     `json:"endedBy,omitempty"`
	EndedReason string     `json:"endedReason,omitempty"`
}

// AgentAccessRequest is an agent's request for access.
type AgentAccessRequest struct {
	RequestID       string   `json:"requestId"`
	Credential      string   `json:"credential"`
	Actions         []string `json:"actions"`
	Reason          string   `json:"reason,omitempty"`
	TaskID          string   `json:"taskId,omitempty"`
	DurationSeconds int      `json:"durationSeconds,omitempty"`
	// Origin is policy (a requiresApproval grant was used) or agent.
	Origin string `json:"origin"`
	// Status is pending, approved, denied, expired or cancelled.
	Status    string     `json:"status"`
	CreatedAt time.Time  `json:"createdAt"`
	ExpiresAt time.Time  `json:"expiresAt"`
	DecidedAt *time.Time `json:"decidedAt,omitempty"`
	DecidedBy string     `json:"decidedBy,omitempty"`
	// DecisionComment is the approver's note or the reason for a denial.
	DecisionComment string `json:"decisionComment,omitempty"`
	Scope           string `json:"scope,omitempty"`
	// Lease is the lease an approval created.
	Lease *AgentLease `json:"lease,omitempty"`

	// Console listings only.
	AgentID     string `json:"agentId,omitempty"`
	AgentName   string `json:"agentName,omitempty"`
	AgentOwner  string `json:"agentOwner,omitempty"`
	CanDecide   bool   `json:"canDecide,omitempty"`
	MFARequired bool   `json:"mfaRequired,omitempty"`
}

// Access request statuses.
const (
	AccessRequestPending   = "pending"
	AccessRequestApproved  = "approved"
	AccessRequestDenied    = "denied"
	AccessRequestExpired   = "expired"
	AccessRequestCancelled = "cancelled"
)

// ListAgentAccessRequests lists access requests in the account, newest
// first. agentID "" lists every agent's; pendingOnly keeps those waiting for
// a decision.
func (c *Client) ListAgentAccessRequests(ctx context.Context, agentID string, pendingOnly bool) ([]AgentAccessRequest, error) {
	q := url.Values{}
	if agentID != "" {
		q.Set("agentId", agentID)
	}
	if pendingOnly {
		q.Set("status", "pending")
	}
	var out struct {
		Requests []AgentAccessRequest `json:"requests"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/agents/access-requests", q, nil, &out); err != nil {
		return nil, err
	}
	return out.Requests, nil
}

// ListAgentLeases lists leases in the account (agentID "" for every agent);
// activeOnly keeps the usable ones.
func (c *Client) ListAgentLeases(ctx context.Context, agentID string, activeOnly bool) ([]AgentLease, error) {
	q := url.Values{}
	if agentID != "" {
		q.Set("agentId", agentID)
	}
	if !activeOnly {
		q.Set("active", "false")
	}
	var out struct {
		Leases []AgentLease `json:"leases"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/agents/leases", q, nil, &out); err != nil {
		return nil, err
	}
	return out.Leases, nil
}

// RevokeAgentLease ends an active lease (the agent's owner or an admin).
func (c *Client) RevokeAgentLease(ctx context.Context, leaseID, reason string) (*AgentLease, error) {
	var out AgentLease
	if err := c.do(ctx, http.MethodPost, "/v1/agents/leases/revoke", nil, map[string]string{"leaseId": leaseID, "reason": reason}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Agent API (agent token) -------------------------------------------------

// AgentAccessInput asks for access. Actions default to use; Reason is
// required and shown to approvers; Duration (1 minute to 24 hours) is how
// long the access is wanted; TaskID binds a task-scoped approval.
type AgentAccessInput struct {
	Credential string
	Actions    []string
	Reason     string
	Duration   time.Duration
	TaskID     string
}

// AgentRequestAccess asks a person for access, or returns the pending
// request for the same credential, actions and task. The client must be
// configured with an agent token.
func (c *Client) AgentRequestAccess(ctx context.Context, in AgentAccessInput) (*AgentAccessRequest, error) {
	body := map[string]any{"credential": in.Credential, "reason": in.Reason}
	if len(in.Actions) > 0 {
		body["actions"] = in.Actions
	}
	if in.Duration > 0 {
		body["durationSeconds"] = int(in.Duration / time.Second)
	}
	if in.TaskID != "" {
		body["taskId"] = in.TaskID
	}
	var out AgentAccessRequest
	if err := c.do(ctx, http.MethodPost, "/v1/agent/access-requests", nil, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AgentAccessRequest returns one of the calling agent's requests.
func (c *Client) AgentAccessRequest(ctx context.Context, requestID string) (*AgentAccessRequest, error) {
	var out AgentAccessRequest
	if err := c.do(ctx, http.MethodGet, "/v1/agent/access-requests/"+url.PathEscape(requestID), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ErrAccessDenied is returned by WaitForAgentAccess when the request is
// denied, expires or is cancelled.
var ErrAccessDenied = errors.New("citadel: the access request was not approved")

// WaitForAgentAccess polls requestID every interval (default 5 seconds)
// until it is decided or ctx ends. It returns the approved request, or the
// final request with ErrAccessDenied.
func (c *Client) WaitForAgentAccess(ctx context.Context, requestID string, interval time.Duration) (*AgentAccessRequest, error) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	for {
		r, err := c.AgentAccessRequest(ctx, requestID)
		if err != nil {
			return nil, err
		}
		switch r.Status {
		case AccessRequestApproved:
			return r, nil
		case AccessRequestPending:
		default:
			return r, ErrAccessDenied
		}
		t := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			t.Stop()
			return r, ctx.Err()
		case <-t.C:
		}
	}
}

// AgentLeases lists the calling agent's active leases (credential "" for
// all).
func (c *Client) AgentLeases(ctx context.Context, credential string) ([]AgentLease, error) {
	q := url.Values{}
	if credential != "" {
		q.Set("credential", credential)
	}
	var out struct {
		Leases []AgentLease `json:"leases"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/agent/leases", q, nil, &out); err != nil {
		return nil, err
	}
	return out.Leases, nil
}
