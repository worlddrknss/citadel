package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"time"
)

// Audit retention (2.5).
//
// An account's audit log may be pruned to a retention window: the deployment
// default (KMS_AUDIT_RETENTION_DAYS, 0 = keep forever) or a per-account
// override. Pruning always removes a contiguous prefix of the account's hash
// chain, oldest first, in small batches. Before each batch is deleted the
// backend records the account's chain anchor: the position and MAC of the
// last pruned event, keyed with the audit HMAC key. Verification starts from
// the anchor (checking that the first remaining event links to it), so a
// pruned prefix reads as "pruned before <time>" rather than as a break, while
// deleting rows any other way still breaks the chain.
//
// A batch stops early, and the rows stay, at the first event that:
//   - is newer than the cut-off (the window is never cut into);
//   - is the chain head (the newest event is always kept);
//   - does not verify (a gap in the sequence, a bad link or MAC): pruning
//     never destroys the evidence of a broken chain;
//   - is a write-ahead attempt whose outcome is newer than the cut-off;
//   - is still waiting in the SIEM stream outbox (not yet delivered). Items
//     that exhausted their retries ("dead") don't hold pruning back.

// Retention bounds, in days. 0 means keep forever.
const (
	AuditRetentionMinDays = 7
	AuditRetentionMaxDays = 3650
)

// ValidAuditRetentionDays reports whether days is 0 (keep forever) or within
// [AuditRetentionMinDays, AuditRetentionMaxDays].
func ValidAuditRetentionDays(days int) bool {
	return days == 0 || (days >= AuditRetentionMinDays && days <= AuditRetentionMaxDays)
}

// AuditRetentionSetting is an account's retention override. Days nil means
// "use the deployment default"; 0 means keep forever.
type AuditRetentionSetting struct {
	AccountID string
	Days      *int
	UpdatedBy string
	UpdatedAt time.Time
}

// AuditAnchor is the authenticated start of an account's chain after
// pruning: every event up to and including ChainSeq has been deleted.
type AuditAnchor struct {
	AccountID string
	// ChainSeq, EventID and EventHash identify the last pruned event; the
	// first remaining event must have ChainSeq+1 and PrevHash EventHash.
	ChainSeq  int64
	EventID   int64
	EventHash string
	// PrunedBefore is the timestamp of the last pruned event: everything
	// older is gone.
	PrunedBefore time.Time
	// PrunedEvents counts every event pruned from the account so far.
	PrunedEvents int64
	// UpdatedAt is when the anchor last advanced.
	UpdatedAt time.Time
	// MAC authenticates the fields above (AuditAnchorMAC).
	MAC string
}

// AuditAnchorMAC computes the anchor's MAC. Like AuditMAC it is a
// length-prefixed HMAC-SHA256 over every field.
func AuditAnchorMAC(key []byte, a AuditAnchor) string {
	if len(key) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	var lenBuf [4]byte
	field := func(v string) {
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(v)))
		mac.Write(lenBuf[:])
		mac.Write([]byte(v))
	}
	field("citadel-audit-anchor-v1")
	field(a.AccountID)
	field(strconv.FormatInt(a.ChainSeq, 10))
	field(strconv.FormatInt(a.EventID, 10))
	field(a.EventHash)
	field(AuditTimestamp(a.PrunedBefore))
	field(strconv.FormatInt(a.PrunedEvents, 10))
	field(AuditTimestamp(a.UpdatedAt))
	return hex.EncodeToString(mac.Sum(nil))
}

// AuditAnchorValid reports whether a's MAC matches its content.
func AuditAnchorValid(key []byte, a AuditAnchor) bool {
	return len(key) > 0 && hmac.Equal([]byte(AuditAnchorMAC(key, a)), []byte(a.MAC))
}

// Reasons a prune batch stopped before the cut-off.
const (
	AuditPruneStopWindow     = ""           // reached the cut-off (or nothing to do)
	AuditPruneStopHead       = "head"       // the next event is the newest one
	AuditPruneStopUnverified = "unverified" // the next event doesn't verify
	AuditPruneStopPending    = "pending"    // a write-ahead attempt whose outcome is in the window
	AuditPruneStopStream     = "stream"     // the next event awaits SIEM delivery
	AuditPruneStopBusy       = "busy"       // another replica is pruning this account
	AuditPruneStopBadAnchor  = "anchor"     // the stored anchor doesn't verify
)

// AuditPruneResult is the outcome of one prune batch.
type AuditPruneResult struct {
	Pruned int64
	// Anchor is the account's anchor after the batch (zero when the account
	// has never been pruned).
	Anchor AuditAnchor
	// Stop says why the batch ended before the cut-off; "" when it reached
	// it. A batch that pruned a full batch of rows may have more to do.
	Stop string
}

// AuditRetentionStats describes an account's log for the retention form.
type AuditRetentionStats struct {
	// Events is the account's stored event count; Oldest the timestamp of
	// its oldest stored event (zero when it has none).
	Events int64
	Oldest time.Time
	// Prunable counts the account's events older than the proposed cut-off
	// (0 when no cut-off was given). Pruning may remove fewer: see the stop
	// rules in this file.
	Prunable int64
	// TableBytes and TableRows are deployment-wide: the audit table's total
	// size on disk (with indexes and TOAST) and its estimated row count.
	// -1 when the backend can't tell.
	TableBytes int64
	TableRows  int64
}

// AuditRetentionStore is the retention side of the audit log.
type AuditRetentionStore interface {
	// GetAuditRetention returns accountID's override (Days nil when none).
	GetAuditRetention(ctx context.Context, accountID string) (AuditRetentionSetting, error)
	// PutAuditRetention stores (Days set) or clears (Days nil) an override.
	PutAuditRetention(ctx context.Context, s AuditRetentionSetting) error
	// ListAuditRetention returns every stored override.
	ListAuditRetention(ctx context.Context) ([]AuditRetentionSetting, error)
	// AuditAccounts lists the accounts that have an audit chain.
	AuditAccounts(ctx context.Context) ([]string, error)
	// GetAuditAnchor returns accountID's anchor (false when never pruned).
	GetAuditAnchor(ctx context.Context, accountID string) (AuditAnchor, bool, error)
	// AuditRetentionStats describes accountID's log; with cutoff set it also
	// counts the events older than it.
	AuditRetentionStats(ctx context.Context, accountID string, cutoff *time.Time) (AuditRetentionStats, error)
	// PruneAuditEvents deletes, in one transaction, at most limit of
	// accountID's oldest events created before cutoff (see the stop rules
	// above) and advances the anchor. Safe to call from several replicas at
	// once: only one prunes an account at a time, the others get Stop "busy".
	PruneAuditEvents(ctx context.Context, accountID string, cutoff time.Time, limit int) (AuditPruneResult, error)

	// ClaimAuditPruneRun takes the deployment-wide retention run lease for
	// holder until now+lease, unless another holder's lease is still
	// running. It reports whether holder got it.
	ClaimAuditPruneRun(ctx context.Context, holder string, now time.Time, lease time.Duration) (bool, error)
	// FinishAuditPruneRun releases holder's lease and records the run.
	FinishAuditPruneRun(ctx context.Context, holder string, run AuditPruneRun) error
	// GetAuditPruneRun returns the last recorded run (zero when none).
	GetAuditPruneRun(ctx context.Context) (AuditPruneRun, error)
}

// AuditPruneRun is what the last retention run did, deployment-wide.
type AuditPruneRun struct {
	StartedAt    time.Time
	FinishedAt   time.Time
	PrunedEvents int64
	// Error is a short, client-safe summary ("" when the run succeeded).
	Error string
}

// AuditPruneCandidate is one event a prune batch considers, with the facts
// the backend looked up about it.
type AuditPruneCandidate struct {
	Record AuditRecord
	// OutcomeInWindow: a pending attempt whose outcome is newer than the
	// cut-off.
	OutcomeInWindow bool
	// Undelivered: queued for SIEM delivery and not given up on.
	Undelivered bool
}

// AuditPrunePrefix decides how many of candidates (consecutive events of one
// account, ordered by ChainSeq, starting right after anchor or at the start
// of the chain) a batch may delete, and why it stopped. headSeq is the
// account's chain head position.
func AuditPrunePrefix(key []byte, anchor AuditAnchor, hasAnchor bool, candidates []AuditPruneCandidate, cutoff time.Time, headSeq int64) (int, string) {
	seq, hash := int64(0), ""
	if hasAnchor {
		seq, hash = anchor.ChainSeq, anchor.EventHash
	}
	for i, c := range candidates {
		rec := c.Record
		switch {
		case !rec.CreatedAt.Before(cutoff):
			return i, AuditPruneStopWindow
		case rec.ChainSeq >= headSeq:
			return i, AuditPruneStopHead
		case !auditLinkOK(key, rec, seq, hash):
			return i, AuditPruneStopUnverified
		case c.OutcomeInWindow:
			return i, AuditPruneStopPending
		case c.Undelivered:
			return i, AuditPruneStopStream
		}
		seq, hash = rec.ChainSeq, rec.EventHash
	}
	return len(candidates), AuditPruneStopWindow
}

// auditLinkOK applies the verification walk's per-event checks: the next
// sequence number, and for 2.0 events a valid MAC and a link to the previous
// event. Pre-2.0 events are checked for position only (their links may not
// connect; see AuditVerification).
func auditLinkOK(key []byte, rec AuditRecord, seq int64, hash string) bool {
	if rec.ChainSeq != seq+1 {
		return false
	}
	if rec.HashVersion < AuditHashVersion {
		return true
	}
	return rec.PrevHash == hash && AuditMACValid(key, rec)
}
