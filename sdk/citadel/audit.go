package citadel

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// ---- Audit retention and chain verification --------------------------------

// AuditChainAnchor is where an account's audit chain starts after retention
// pruning: every event up to and including ChainSeq was deleted on purpose.
type AuditChainAnchor struct {
	ChainSeq     int64     `json:"chainSeq"`
	EventID      int64     `json:"eventId"`
	Hash         string    `json:"hash"`
	PrunedBefore time.Time `json:"prunedBefore"`
	PrunedEvents int64     `json:"prunedEvents"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

// AuditRetention is an account's audit retention policy.
type AuditRetention struct {
	// RetentionDays is the retention in force; 0 keeps events forever.
	RetentionDays int `json:"retentionDays"`
	// Source is "account" (the account's override) or "deployment".
	Source string `json:"source"`
	// AccountDays is the account's override (nil: the deployment default).
	AccountDays    *int   `json:"accountDays"`
	DeploymentDays int    `json:"deploymentDays"`
	MinDays        int    `json:"minDays"`
	MaxDays        int    `json:"maxDays"`
	UpdatedBy      string `json:"updatedBy,omitempty"`
	UpdatedAt      string `json:"updatedAt,omitempty"`
	// StreamHeld: SIEM streaming is on, so events are pruned only once
	// delivered.
	StreamHeld  bool              `json:"streamHeld"`
	Events      int64             `json:"events"`
	OldestEvent string            `json:"oldestEvent,omitempty"`
	Anchor      *AuditChainAnchor `json:"anchor,omitempty"`
	// Storage and LastRun are returned to platform admins only.
	Storage *struct {
		TableBytes        int64 `json:"tableBytes"`
		TableRowsEstimate int64 `json:"tableRowsEstimate"`
	} `json:"storage,omitempty"`
	LastRun *struct {
		StartedAt    string `json:"startedAt,omitempty"`
		FinishedAt   string `json:"finishedAt,omitempty"`
		PrunedEvents int64  `json:"prunedEvents"`
		Error        string `json:"error,omitempty"`
	} `json:"lastRun,omitempty"`
}

// AuditRetentionPreview is how many events a retention would prune now.
type AuditRetentionPreview struct {
	RetentionDays  int    `json:"retentionDays"`
	Cutoff         string `json:"cutoff,omitempty"`
	PrunableEvents int64  `json:"prunableEvents"`
	Events         int64  `json:"events"`
	OldestEvent    string `json:"oldestEvent,omitempty"`
}

// GetAuditRetention returns the account's audit retention policy.
func (c *Client) GetAuditRetention(ctx context.Context) (*AuditRetention, error) {
	var out AuditRetention
	if err := c.do(ctx, http.MethodGet, "/v1/audit/retention", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SetAuditRetention sets the account's retention in days (0 keeps events
// forever; otherwise 7 to 3650). A nil days returns the account to the
// deployment default. Requires the admin role; the change is audited.
func (c *Client) SetAuditRetention(ctx context.Context, days *int) (*AuditRetention, error) {
	body := struct {
		RetentionDays *int `json:"retentionDays"`
	}{days}
	var out AuditRetention
	if err := c.do(ctx, http.MethodPost, "/v1/audit/retention", nil, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PreviewAuditRetention counts the account's events older than the cut-off
// a retention of days would use now. Requires the admin role.
func (c *Client) PreviewAuditRetention(ctx context.Context, days int) (*AuditRetentionPreview, error) {
	var out AuditRetentionPreview
	q := url.Values{"days": {strconv.Itoa(days)}}
	if err := c.do(ctx, http.MethodGet, "/v1/audit/retention/preview", q, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AuditChainStatus is the result of an audit chain verification.
type AuditChainStatus struct {
	// Status is "verified", "broken" or "never".
	Status          string `json:"status"`
	VerifiedThrough int64  `json:"verifiedThrough,omitempty"`
	HeadHash        string `json:"headHash,omitempty"`
	CheckedAt       string `json:"checkedAt,omitempty"`
	BrokenAt        *int64 `json:"brokenAt,omitempty"`
	TotalEvents     *int64 `json:"totalEvents,omitempty"`
	// Anchor is set when the account's log has been pruned: verification
	// starts there.
	Anchor *AuditChainAnchor `json:"anchor,omitempty"`
}

// VerifyAuditChain verifies the account's audit chain from the last
// verified point (or from the pruning anchor) and returns the result.
func (c *Client) VerifyAuditChain(ctx context.Context) (*AuditChainStatus, error) {
	var out AuditChainStatus
	if err := c.do(ctx, http.MethodPost, "/v1/audit/verify", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
