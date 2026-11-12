package store

import (
	"context"
	"time"
)

// AuditQuery filters an account's audit events. The account is never taken
// from the query: backends scope reads to the caller account on the context
// (or the deployment account when there is none).
type AuditQuery struct {
	From, To *time.Time
	// Actor, Action and Resource are case-insensitive "contains" filters.
	// Actor matches the actor, display name and access key ID; Resource
	// matches the resource and the key ID.
	Actor    string
	Action   string
	Resource string
	// Result is "", success, denied or error.
	Result string
	Limit  int
	Offset int
	// BeforeID, when > 0, returns only events with a smaller ID (keyset
	// paging for exports). Offset is applied after it.
	BeforeID int64
}

// AuditChainHead is the tip of an account's chain.
type AuditChainHead struct {
	AccountID string
	ChainSeq  int64
	HeadHash  string
	HeadID    int64
}

// Audit verification statuses.
const (
	AuditChainVerified = "verified"
	AuditChainBroken   = "broken"
	AuditChainNever    = "never"
)

// AuditVerification is the remembered result of walking an account's chain.
type AuditVerification struct {
	AccountID string
	Status    string
	// VerifiedSeq / VerifiedID / VerifiedHash identify the last event known
	// good; the next incremental run continues after it.
	VerifiedSeq  int64
	VerifiedID   int64
	VerifiedHash string
	HeadHash     string
	// BrokenID is the ID of the first event that failed (0 when the break is
	// a missing tail: the head row points past the last stored event).
	BrokenID    int64
	BrokenSeq   int64
	TotalEvents int64
	CheckedAt   time.Time
}

// AuditStreamConfig is an account's SIEM streaming configuration. TokenSealed
// is the bearer token encrypted by the server; the store never sees it in
// clear.
type AuditStreamConfig struct {
	AccountID   string
	Enabled     bool
	URL         string
	Format      string // json | cef
	TokenSealed []byte
	UpdatedBy   string
	UpdatedAt   time.Time
}

// AuditOutboxItem is one event awaiting delivery to its account's stream.
type AuditOutboxItem struct {
	ID       int64
	Attempts int
	Event    AuditRecord
}

// AuditQueryStore is the audit read side: filtered listing, chain
// verification, SIEM stream settings and its delivery outbox.
type AuditQueryStore interface {
	QueryAuditEvents(ctx context.Context, q AuditQuery) ([]AuditRecord, error)
	CountAuditEvents(ctx context.Context, q AuditQuery) (int, error)

	// VerifyAuditChain walks accountID's chain (from the last verified point
	// unless full, or unless the last run found a break) and stores and
	// returns the result.
	VerifyAuditChain(ctx context.Context, accountID string, full bool) (AuditVerification, error)
	// GetAuditVerification returns the last stored result (Status "never"
	// when the chain has not been verified).
	GetAuditVerification(ctx context.Context, accountID string) (AuditVerification, error)

	GetAuditStreamConfig(ctx context.Context, accountID string) (AuditStreamConfig, error)
	PutAuditStreamConfig(ctx context.Context, cfg AuditStreamConfig) error
	// ClaimAuditOutbox leases up to limit due items for lease (so other
	// replicas skip them) and returns them with their events.
	ClaimAuditOutbox(ctx context.Context, limit int, lease time.Duration) ([]AuditOutboxItem, error)
	// CompleteAuditOutbox removes a delivered item.
	CompleteAuditOutbox(ctx context.Context, id int64) error
	// RetryAuditOutbox records a failed attempt and when to try next; dead
	// items are kept for inspection but never retried.
	RetryAuditOutbox(ctx context.Context, id int64, next time.Time, lastErr string, dead bool) error
}

// AuditChainSource is the minimal read/write surface RunAuditVerification
// needs from a backend.
type AuditChainSource interface {
	AuditChainHeadFor(ctx context.Context, accountID string) (AuditChainHead, bool, error)
	AuditChainBatch(ctx context.Context, accountID string, afterSeq int64, limit int) ([]AuditRecord, error)
	AuditEventCount(ctx context.Context, accountID string) (int64, error)
	LoadAuditVerification(ctx context.Context, accountID string) (AuditVerification, bool, error)
	SaveAuditVerification(ctx context.Context, v AuditVerification) error
}

// auditVerifyBatch is how many events one verification round trip reads.
const auditVerifyBatch = 1000

// RunAuditVerification is the backend-independent chain walk behind
// VerifyAuditChain. Each event must have the next sequence number, carry the
// previous event's MAC as its PrevHash and (for version-2 rows) a MAC that
// recomputes under key. The walk ends by checking that the last event is the
// chain head, which catches a truncated tail.
func RunAuditVerification(ctx context.Context, src AuditChainSource, key []byte, accountID string, full bool, now time.Time) (AuditVerification, error) {
	prev, hasPrev, err := src.LoadAuditVerification(ctx, accountID)
	if err != nil {
		return AuditVerification{}, err
	}
	res := AuditVerification{AccountID: accountID, CheckedAt: now.UTC()}
	if hasPrev && !full && prev.Status == AuditChainVerified {
		res.VerifiedSeq, res.VerifiedID, res.VerifiedHash = prev.VerifiedSeq, prev.VerifiedID, prev.VerifiedHash
	}
	total, err := src.AuditEventCount(ctx, accountID)
	if err != nil {
		return AuditVerification{}, err
	}
	res.TotalEvents = total

	head, hasHead, err := src.AuditChainHeadFor(ctx, accountID)
	if err != nil {
		return AuditVerification{}, err
	}

	seq, hash := res.VerifiedSeq, res.VerifiedHash
	broken := false
	if seq > 0 {
		// Incremental run: re-check the checkpoint event itself so a rewrite
		// of the last verified row is still caught. (Rows before it are only
		// re-walked by a full verification.)
		cp, err := src.AuditChainBatch(ctx, accountID, seq-1, 1)
		if err != nil {
			return AuditVerification{}, err
		}
		if len(cp) != 1 || cp[0].ChainSeq != seq || cp[0].EventHash != hash ||
			(cp[0].HashVersion >= AuditHashVersion && !AuditMACValid(key, cp[0])) {
			broken = true
			res.BrokenSeq = seq
			if len(cp) == 1 {
				res.BrokenID = cp[0].ID
			}
			res.VerifiedSeq, res.VerifiedID, res.VerifiedHash = 0, 0, ""
		}
	}
	for !broken {
		batch, err := src.AuditChainBatch(ctx, accountID, seq, auditVerifyBatch)
		if err != nil {
			return AuditVerification{}, err
		}
		for _, rec := range batch {
			ok := rec.ChainSeq == seq+1 && rec.PrevHash == hash && rec.AccountID == accountID
			if ok && rec.HashVersion >= AuditHashVersion {
				ok = AuditMACValid(key, rec)
			}
			if !ok {
				res.BrokenID, res.BrokenSeq = rec.ID, rec.ChainSeq
				broken = true
				break
			}
			seq, hash = rec.ChainSeq, rec.EventHash
			res.VerifiedSeq, res.VerifiedID, res.VerifiedHash = rec.ChainSeq, rec.ID, rec.EventHash
		}
		if len(batch) < auditVerifyBatch {
			break
		}
	}
	if hasHead {
		res.HeadHash = head.HeadHash
	}
	if !broken && hasHead && (head.ChainSeq != seq || head.HeadHash != hash) {
		// Events after the last one we could read are missing (or the head
		// was rewritten).
		broken = true
		res.BrokenID, res.BrokenSeq = head.HeadID, seq+1
	}
	if !broken && !hasHead && seq > 0 {
		broken = true
		res.BrokenSeq = seq
	}
	res.Status = AuditChainVerified
	if broken {
		res.Status = AuditChainBroken
	}
	if err := src.SaveAuditVerification(ctx, res); err != nil {
		return AuditVerification{}, err
	}
	return res, nil
}
