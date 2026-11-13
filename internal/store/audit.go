package store

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// Audit log model.
//
// Chain design: one hash chain PER ACCOUNT. Every event carries its account's
// chain sequence number (1, 2, 3 ...) and the MAC of the previous event in
// that account's chain. The MAC is HMAC-SHA256 over a length-prefixed
// encoding of every stored field, including the account ID and sequence
// number, so a row cannot be edited, re-ordered, dropped or moved to another
// tenant's chain without the break being detectable by anyone holding the
// key. Per-account chains (rather than one global chain) let a tenant verify
// its own history without the server reading or reporting positions in other
// tenants' events, and let appends for different accounts proceed in
// parallel. Appends within an account are serialized by the backend (a
// locked chain-head row in Postgres, a mutex in memory), and (account_id,
// chain_seq) is unique, so concurrent writers can never fork a chain.
//
// Rows written before this scheme (HashVersion 1) used an unkeyed or
// differently-keyed SHA-256 chain over a "|"-joined payload whose timestamp
// Postgres could not round-trip; they are verified for linkage only.

// Audit results. Legacy rows used "ok" for success.
const (
	AuditResultSuccess = "success"
	AuditResultDenied  = "denied"
	AuditResultError   = "error"
	// AuditResultPending marks a write-ahead attempt: the action was about
	// to be performed. Its outcome is a later event with the same
	// CorrelationID; an attempt without one means the outcome is unknown
	// (for example the process stopped in between).
	AuditResultPending = "pending"
)

// Actor types recorded on audit events.
const (
	AuditActorConsole     = "console"      // console (cookie) session user
	AuditActorAccessKey   = "access-key"   // long-lived access key (SigV4 or /v1 bearer)
	AuditActorAssumedRole = "assumed-role" // STS temporary credentials
	AuditActorDeployment  = "deployment"   // static KMS_ACCESS_KEY_ID credential
	AuditActorWebIdentity = "web-identity" // OIDC web identity token (STS)
	AuditActorAnonymous   = "anonymous"    // unauthenticated endpoint
	AuditActorSystem      = "system"       // background job
	AuditActorAgent       = "agent"        // AI agent (agent token or federation)
)

// AuditHashVersion is the chain format new events are written with.
const AuditHashVersion = 2

// AuditOrigin is who did something, from where, to what. It is embedded in
// AuditEvent and AuditRecord.
type AuditOrigin struct {
	AccountID        string
	Actor            string
	ActorType        string
	ActorDisplayName string
	AccessKeyID      string
	Resource         string
	SourceIP         string
	UserAgent        string
	// CorrelationID links a write-ahead attempt (Result pending) to its
	// outcome events. Empty for events written without an attempt.
	CorrelationID string
	// AgentID, AgentOwner and TaskID attribute an event to an AI agent:
	// requests the agent made, and console changes to the agent. TaskID is
	// the agent's own task or session ID (X-Citadel-Task-Id). Empty for
	// events that do not involve an agent.
	AgentID    string
	AgentOwner string
	TaskID     string
}

// AuditEvent is an event to append to the audit log.
type AuditEvent struct {
	Action    string
	KeyID     string
	Result    string
	ErrorType string
	AuditOrigin
}

// AuditRecord is a stored audit event.
type AuditRecord struct {
	ID          int64
	ChainSeq    int64
	HashVersion int
	Action      string
	KeyID       string
	Result      string
	ErrorType   string
	AuditOrigin
	PrevHash  string
	EventHash string
	CreatedAt time.Time
	// HashValid is set by reads that recompute the event's MAC (version 2
	// rows only): true when it matches. It says nothing about linkage.
	HashValid *bool
}

// AuditTimestamp is the canonical timestamp form inside the MAC. Microsecond
// precision, because that is what Postgres timestamptz stores.
func AuditTimestamp(t time.Time) string {
	return t.UTC().Truncate(time.Microsecond).Format("2006-01-02T15:04:05.000000Z07:00")
}

// AuditMAC computes the version-2 chain MAC of rec (whose PrevHash, ChainSeq
// and CreatedAt must be set). key must be non-empty: the audit chain is never
// unkeyed.
func AuditMAC(key []byte, rec AuditRecord) string {
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
	field("citadel-audit-v2")
	field(rec.AccountID)
	field(strconv.FormatInt(rec.ChainSeq, 10))
	field(rec.PrevHash)
	field(AuditTimestamp(rec.CreatedAt))
	field(rec.Action)
	field(rec.KeyID)
	field(rec.Resource)
	field(rec.Result)
	field(rec.ErrorType)
	field(rec.Actor)
	field(rec.ActorType)
	field(rec.ActorDisplayName)
	field(rec.AccessKeyID)
	field(rec.SourceIP)
	field(rec.UserAgent)
	// Added in 2.1. Hashed only when set, so every earlier row keeps its MAC.
	if rec.CorrelationID != "" {
		field("correlation")
		field(rec.CorrelationID)
	}
	// Added in 2.2, likewise hashed only when set.
	if rec.AgentID != "" || rec.AgentOwner != "" || rec.TaskID != "" {
		field("agent")
		field(rec.AgentID)
		field(rec.AgentOwner)
		field(rec.TaskID)
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// AuditMACValid reports whether rec's stored EventHash matches its content.
// Legacy (version 1) rows cannot be recomputed and report false.
func AuditMACValid(key []byte, rec AuditRecord) bool {
	if rec.HashVersion < AuditHashVersion || len(key) == 0 {
		return false
	}
	return hmac.Equal([]byte(AuditMAC(key, rec)), []byte(rec.EventHash))
}

// NormalizeAuditResult maps the result vocabulary handlers use ("ok",
// "error" + an access-denied error type) onto success | denied | error.
func NormalizeAuditResult(result, errorType string) string {
	switch strings.ToLower(strings.TrimSpace(result)) {
	case "ok", "success":
		return AuditResultSuccess
	case "denied":
		return AuditResultDenied
	case "pending":
		return AuditResultPending
	}
	et := strings.ToLower(errorType)
	if strings.Contains(et, "accessdenied") || strings.Contains(et, "forbidden") || strings.Contains(et, "unauthorized") {
		return AuditResultDenied
	}
	return AuditResultError
}

// Truncate s to at most n bytes without splitting a UTF-8 sequence.
func truncateAuditField(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut]
}

// SanitizeAuditEvent bounds attacker-influenced fields (user agent,
// resource, actor) so one request cannot bloat the log, and normalizes the
// result. Backends call it before computing the MAC.
func SanitizeAuditEvent(ev AuditEvent) AuditEvent {
	ev.Result = NormalizeAuditResult(ev.Result, ev.ErrorType)
	ev.Action = truncateAuditField(ev.Action, 128)
	ev.KeyID = truncateAuditField(ev.KeyID, 512)
	ev.ErrorType = truncateAuditField(ev.ErrorType, 128)
	ev.Actor = truncateAuditField(ev.Actor, 512)
	ev.ActorType = truncateAuditField(ev.ActorType, 32)
	ev.ActorDisplayName = truncateAuditField(ev.ActorDisplayName, 256)
	ev.AccessKeyID = truncateAuditField(ev.AccessKeyID, 128)
	ev.Resource = truncateAuditField(ev.Resource, 1024)
	ev.SourceIP = truncateAuditField(ev.SourceIP, 64)
	ev.UserAgent = truncateAuditField(ev.UserAgent, 512)
	ev.CorrelationID = truncateAuditField(ev.CorrelationID, 64)
	ev.AgentID = truncateAuditField(ev.AgentID, 64)
	ev.AgentOwner = truncateAuditField(ev.AgentOwner, 128)
	ev.TaskID = truncateAuditField(ev.TaskID, 128)
	if ev.Actor == "" {
		ev.Actor = AuditActorAnonymous
		if ev.ActorType == "" {
			ev.ActorType = AuditActorAnonymous
		}
	}
	return ev
}
