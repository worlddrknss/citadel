package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// Audit retention (2.5): a retention policy per account (the deployment
// default KMS_AUDIT_RETENTION_DAYS, or the account's own override), a job
// that prunes events older than it in small batches, and the chain anchor
// that lets verification start where pruning stopped. See
// store/audit_retention.go for the pruning rules and docs/audit.md.

func (s *Server) registerAuditRetentionRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/audit/retention", s.handleV1GetAuditRetention)
	mux.HandleFunc("POST /v1/audit/retention", s.handleV1PutAuditRetention)
	mux.HandleFunc("GET /v1/audit/retention/preview", s.handleV1PreviewAuditRetention)
	s.jobs.Every("audit-retention", auditRetentionInterval, s.auditRetentionJob)
}

const (
	// auditRetentionInterval is how often the retention job runs (and once
	// at startup).
	auditRetentionInterval = time.Hour
	// auditPruneBatch is how many events one prune transaction deletes at
	// most; auditPrunePause is the pause between batches, so pruning a large
	// backlog never holds locks for long or floods the WAL.
	auditPruneBatch = 5000
	auditPrunePause = 200 * time.Millisecond
	// auditRetentionLease bounds one run (and its deployment-wide lease).
	auditRetentionLease = 30 * time.Minute
	// auditPruneMaxBatches caps one account's batches per run; the rest
	// waits for the next run.
	auditPruneMaxBatches = 1000
)

// auditRetentionHolder identifies this process in the run lease.
var auditRetentionHolder = func() string {
	host, _ := os.Hostname()
	if len(host) > 64 {
		host = host[:64]
	}
	return host + "/" + cryptoutil.RandomHex(6)
}()

// effectiveAuditRetention is accountID's retention in days (0: keep
// forever) and where it comes from ("account" or "deployment").
func (s *Server) effectiveAuditRetention(ctx context.Context, accountID string) (int, string, store.AuditRetentionSetting, error) {
	set, err := s.store.GetAuditRetention(ctx, accountID)
	if err != nil {
		return 0, "", set, err
	}
	if set.Days != nil {
		return *set.Days, "account", set, nil
	}
	return s.cfg.AuditRetentionDays, "deployment", set, nil
}

// retentionCutoff is the instant events older than which a retention of
// days prunes.
func retentionCutoff(now time.Time, days int) time.Time {
	return now.UTC().Add(-time.Duration(days) * 24 * time.Hour)
}

// ---- JSON ------------------------------------------------------------------

type auditAnchorJSON struct {
	ChainSeq     int64  `json:"chainSeq"`
	EventID      int64  `json:"eventId"`
	Hash         string `json:"hash"`
	PrunedBefore string `json:"prunedBefore"`
	PrunedEvents int64  `json:"prunedEvents"`
	UpdatedAt    string `json:"updatedAt"`
}

func toAuditAnchorJSON(a store.AuditAnchor) *auditAnchorJSON {
	return &auditAnchorJSON{
		ChainSeq:     a.ChainSeq,
		EventID:      a.EventID,
		Hash:         a.EventHash,
		PrunedBefore: a.PrunedBefore.UTC().Format(time.RFC3339Nano),
		PrunedEvents: a.PrunedEvents,
		UpdatedAt:    a.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

// auditAnchorFor is accountID's anchor for a response (nil when the account
// was never pruned, or the read failed: the anchor is informational there).
func (s *Server) auditAnchorFor(ctx context.Context, accountID string) *auditAnchorJSON {
	a, ok, err := s.store.GetAuditAnchor(ctx, accountID)
	if err != nil {
		log.Printf("audit anchor read failed: %v", err)
		return nil
	}
	if !ok {
		return nil
	}
	return toAuditAnchorJSON(a)
}

type auditRetentionJSON struct {
	// RetentionDays is the retention in force (0: keep forever); Source is
	// "account" (the account's override) or "deployment" (the default).
	RetentionDays  int    `json:"retentionDays"`
	Source         string `json:"source"`
	AccountDays    *int   `json:"accountDays"`
	DeploymentDays int    `json:"deploymentDays"`
	MinDays        int    `json:"minDays"`
	MaxDays        int    `json:"maxDays"`
	UpdatedBy      string `json:"updatedBy,omitempty"`
	UpdatedAt      string `json:"updatedAt,omitempty"`
	// StreamHeld is true when SIEM streaming is on: events wait for
	// delivery before they can be pruned.
	StreamHeld bool                   `json:"streamHeld"`
	Events     int64                  `json:"events"`
	Oldest     string                 `json:"oldestEvent,omitempty"`
	Anchor     *auditAnchorJSON       `json:"anchor,omitempty"`
	Storage    *auditStorageJSON      `json:"storage,omitempty"`
	LastRun    *auditRetentionRunJSON `json:"lastRun,omitempty"`
}

// auditStorageJSON is deployment-wide, shown to platform admins only.
type auditStorageJSON struct {
	TableBytes        int64 `json:"tableBytes"`
	TableRowsEstimate int64 `json:"tableRowsEstimate"`
}

type auditRetentionRunJSON struct {
	StartedAt    string `json:"startedAt,omitempty"`
	FinishedAt   string `json:"finishedAt,omitempty"`
	PrunedEvents int64  `json:"prunedEvents"`
	Error        string `json:"error,omitempty"`
}

type auditRetentionPreviewJSON struct {
	RetentionDays  int    `json:"retentionDays"`
	Cutoff         string `json:"cutoff,omitempty"`
	PrunableEvents int64  `json:"prunableEvents"`
	Events         int64  `json:"events"`
	Oldest         string `json:"oldestEvent,omitempty"`
}

func (s *Server) auditRetentionView(ctx context.Context, sess *uiSession, account string) (auditRetentionJSON, error) {
	days, source, set, err := s.effectiveAuditRetention(ctx, account)
	if err != nil {
		return auditRetentionJSON{}, err
	}
	out := auditRetentionJSON{
		RetentionDays: days, Source: source, AccountDays: set.Days, DeploymentDays: s.cfg.AuditRetentionDays,
		MinDays: store.AuditRetentionMinDays, MaxDays: store.AuditRetentionMaxDays,
	}
	if set.Days != nil {
		out.UpdatedBy = set.UpdatedBy
		out.UpdatedAt = set.UpdatedAt.UTC().Format(time.RFC3339)
	}
	if cfg, err := s.store.GetAuditStreamConfig(ctx, account); err == nil {
		out.StreamHeld = cfg.Enabled
	}
	stats, err := s.store.AuditRetentionStats(ctx, account, nil)
	if err != nil {
		return auditRetentionJSON{}, err
	}
	out.Events = stats.Events
	if !stats.Oldest.IsZero() {
		out.Oldest = stats.Oldest.UTC().Format(time.RFC3339)
	}
	out.Anchor = s.auditAnchorFor(ctx, account)
	if sess != nil && sess.PlatformAdmin {
		out.Storage = &auditStorageJSON{TableBytes: stats.TableBytes, TableRowsEstimate: stats.TableRows}
		if run, err := s.store.GetAuditPruneRun(ctx); err == nil && !run.StartedAt.IsZero() {
			r := &auditRetentionRunJSON{StartedAt: run.StartedAt.UTC().Format(time.RFC3339), PrunedEvents: run.PrunedEvents, Error: run.Error}
			if !run.FinishedAt.IsZero() {
				r.FinishedAt = run.FinishedAt.UTC().Format(time.RFC3339)
			}
			out.LastRun = r
		}
	}
	return out, nil
}

// ---- handlers --------------------------------------------------------------

// GET /v1/audit/retention — viewer. The account's retention policy, its log
// size and pruning anchor; platform admins also see the audit table's size
// and the last run.
func (s *Server) handleV1GetAuditRetention(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	out, err := s.auditRetentionView(ctx, sess, s.auditAccount(ctx))
	if err != nil {
		log.Printf("audit retention read failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "retention_failed", "failed to read the audit retention")
		return
	}
	writeNativeJSON(w, http.StatusOK, out)
}

// parseRetentionDays validates a retention value from a client.
func parseRetentionDays(raw string) (int, string) {
	days, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || !store.ValidAuditRetentionDays(days) {
		return 0, fmt.Sprintf("retentionDays must be 0 (keep forever) or between %d and %d", store.AuditRetentionMinDays, store.AuditRetentionMaxDays)
	}
	return days, ""
}

// GET /v1/audit/retention/preview?days=N — admin. How many of the
// account's events a retention of N days would prune now.
func (s *Server) handleV1PreviewAuditRetention(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	days, msg := parseRetentionDays(r.URL.Query().Get("days"))
	if msg != "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", msg)
		return
	}
	var cutoff *time.Time
	out := auditRetentionPreviewJSON{RetentionDays: days}
	if days > 0 {
		c := retentionCutoff(time.Now(), days)
		cutoff = &c
		out.Cutoff = c.Format(time.RFC3339)
	}
	stats, err := s.store.AuditRetentionStats(ctx, s.auditAccount(ctx), cutoff)
	if err != nil {
		log.Printf("audit retention preview failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "retention_failed", "failed to preview the audit retention")
		return
	}
	out.PrunableEvents, out.Events = stats.Prunable, stats.Events
	if !stats.Oldest.IsZero() {
		out.Oldest = stats.Oldest.UTC().Format(time.RFC3339)
	}
	writeNativeJSON(w, http.StatusOK, out)
}

func retentionLabel(days *int, deploymentDays int) string {
	if days == nil {
		return "default(" + retentionDaysLabel(deploymentDays) + ")"
	}
	return retentionDaysLabel(*days)
}

func retentionDaysLabel(days int) string {
	if days == 0 {
		return "forever"
	}
	return strconv.Itoa(days) + "d"
}

// POST /v1/audit/retention — admin. {"retentionDays": N} sets the
// account's override (0 keeps events forever); {"retentionDays": null}
// returns the account to the deployment default. Audited as
// citadel.PutAuditRetention with the old and new values.
func (s *Server) handleV1PutAuditRetention(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	const action = "citadel.PutAuditRetention"
	origin := s.auditOrigin(r)
	origin.Resource = "audit-retention"
	fail := func(msg string) {
		s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", AuditOrigin: origin})
		writeNativeError(w, http.StatusBadRequest, "invalid_request", msg)
	}
	var req struct {
		RetentionDays json.RawMessage `json:"retentionDays"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		fail("invalid JSON body")
		return
	}
	var days *int
	switch raw := strings.TrimSpace(string(req.RetentionDays)); raw {
	case "":
		fail("retentionDays is required (a number of days, 0 to keep forever, or null for the deployment default)")
		return
	case "null":
	default:
		d, msg := parseRetentionDays(raw)
		if msg != "" {
			fail(msg)
			return
		}
		days = &d
	}
	account := s.auditAccount(ctx)
	prev, err := s.store.GetAuditRetention(ctx, account)
	if err != nil {
		log.Printf("audit retention read failed: %v", err)
		s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "error", ErrorType: "InternalFailure", AuditOrigin: origin})
		writeNativeError(w, http.StatusInternalServerError, "retention_failed", "failed to save the audit retention")
		return
	}
	origin.Resource = fmt.Sprintf("audit-retention: %s -> %s",
		retentionLabel(prev.Days, s.cfg.AuditRetentionDays), retentionLabel(days, s.cfg.AuditRetentionDays))
	if err := s.store.PutAuditRetention(ctx, store.AuditRetentionSetting{AccountID: account, Days: days, UpdatedBy: sess.Username}); err != nil {
		log.Printf("audit retention write failed: %v", err)
		s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "error", ErrorType: "InternalFailure", AuditOrigin: origin})
		writeNativeError(w, http.StatusInternalServerError, "retention_failed", "failed to save the audit retention")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "ok", AuditOrigin: origin})
	out, err := s.auditRetentionView(ctx, sess, account)
	if err != nil {
		log.Printf("audit retention read failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "retention_failed", "saved, but failed to read the audit retention back")
		return
	}
	writeNativeJSON(w, http.StatusOK, out)
}

// ---- job -------------------------------------------------------------------

// auditRetentionJob is the s.jobs entry point.
func (s *Server) auditRetentionJob(ctx context.Context) error {
	_, err := s.runAuditRetention(ctx, time.Now().UTC())
	return err
}

// runAuditRetention prunes every account with a retention to its cut-off
// and returns how many events it deleted. One replica at a time runs it
// (the deployment-wide lease); the others skip the run.
func (s *Server) runAuditRetention(ctx context.Context, now time.Time) (int64, error) {
	obs := s.obsRuntime()
	overrides, err := s.store.ListAuditRetention(ctx)
	if err != nil {
		obs.auditPruneRuns.Inc("error")
		return 0, fmt.Errorf("audit retention: %w", err)
	}
	perAccount := make(map[string]int, len(overrides))
	enabled := s.cfg.AuditRetentionDays > 0
	for _, o := range overrides {
		perAccount[o.AccountID] = *o.Days
		enabled = enabled || *o.Days > 0
	}
	if !enabled {
		return 0, nil // keep forever everywhere: nothing to do, no lease taken
	}
	claimed, err := s.store.ClaimAuditPruneRun(ctx, auditRetentionHolder, now, auditRetentionLease)
	if err != nil {
		obs.auditPruneRuns.Inc("error")
		return 0, fmt.Errorf("audit retention: claim run: %w", err)
	}
	if !claimed {
		obs.auditPruneRuns.Inc("skipped")
		return 0, nil
	}
	rctx, cancel := context.WithTimeout(ctx, auditRetentionLease-time.Minute)
	defer cancel()
	run := store.AuditPruneRun{StartedAt: now}
	defer func() {
		run.FinishedAt = time.Now().UTC()
		if err := s.store.FinishAuditPruneRun(context.WithoutCancel(ctx), auditRetentionHolder, run); err != nil {
			log.Printf("audit retention: recording the run failed: %v", err)
		}
		obs.auditPruneLastRun.Set(float64(run.FinishedAt.Unix()))
		obs.auditPruneLastN.Set(float64(run.PrunedEvents))
		if run.Error != "" {
			obs.auditPruneRuns.Inc("error")
		} else {
			obs.auditPruneRuns.Inc("ok")
		}
	}()

	accounts, err := s.store.AuditAccounts(rctx)
	if err != nil {
		run.Error = "listing accounts failed"
		return 0, fmt.Errorf("audit retention: %w", err)
	}
	var failed int
	for _, acct := range accounts {
		days, ok := perAccount[acct]
		if !ok {
			days = s.cfg.AuditRetentionDays
		}
		if days == 0 {
			continue
		}
		n, err := s.pruneAuditAccount(rctx, acct, days, retentionCutoff(now, days))
		run.PrunedEvents += n
		if err != nil {
			failed++
			log.Printf("audit retention: account=%s: %v (pruned %d before the error)", acct, err, n)
		}
		if rctx.Err() != nil {
			break
		}
	}
	if failed > 0 {
		run.Error = fmt.Sprintf("%d account(s) failed; see the server log", failed)
	}
	if run.PrunedEvents > 0 {
		log.Printf("audit retention: pruned %d event(s)", run.PrunedEvents)
	}
	return run.PrunedEvents, nil
}

// pruneAuditAccount prunes one account in batches, under a write-ahead
// attempt (citadel.PruneAuditEvents) written only when there is something
// older than the cut-off. The outcome records how many events went, the
// anchor and why pruning stopped short, if it did.
func (s *Server) pruneAuditAccount(ctx context.Context, acct string, days int, cutoff time.Time) (int64, error) {
	stats, err := s.store.AuditRetentionStats(ctx, acct, nil)
	if err != nil {
		return 0, err
	}
	// Nothing older than the cut-off, or only the newest event (which is
	// always kept): no attempt, no outcome.
	if stats.Events <= 1 || !stats.Oldest.Before(cutoff) {
		return 0, nil
	}
	origin := store.AuditOrigin{Actor: "system:audit-retention", ActorType: store.AuditActorSystem,
		Resource: fmt.Sprintf("events before %s (retention %d days)", cutoff.Format(time.RFC3339), days)}
	actx, err := s.beginJobAudit(store.WithCallerAccount(ctx, acct), store.AuditEvent{Action: "citadel.PruneAuditEvents", AuditOrigin: origin})
	if err != nil {
		return 0, fmt.Errorf("skipped, the audit log is unavailable")
	}
	var total int64
	var last store.AuditPruneResult
	var perr error
	for i := 0; i < auditPruneMaxBatches; i++ {
		res, err := s.store.PruneAuditEvents(ctx, acct, cutoff, auditPruneBatch)
		if err != nil {
			perr = err
			break
		}
		total += res.Pruned
		last = res
		s.obsRuntime().auditPruned.Add(float64(res.Pruned))
		if res.Pruned < auditPruneBatch || res.Stop != store.AuditPruneStopWindow {
			break
		}
		select {
		case <-ctx.Done():
			perr = ctx.Err()
		case <-time.After(auditPrunePause):
		}
		if perr != nil {
			break
		}
	}
	summary := fmt.Sprintf("%d event(s) before %s pruned", total, cutoff.Format(time.RFC3339))
	if last.Anchor.ChainSeq > 0 {
		summary += fmt.Sprintf("; chain anchored at seq %d (events before %s are gone)", last.Anchor.ChainSeq, last.Anchor.PrunedBefore.UTC().Format(time.RFC3339))
	}
	result, errType := "ok", ""
	switch {
	case perr != nil:
		result, errType = "error", "InternalFailure"
	case last.Stop == store.AuditPruneStopUnverified || last.Stop == store.AuditPruneStopBadAnchor:
		// Pruning never removes evidence of a broken chain.
		result, errType = "error", "AuditChainBroken"
		summary += "; stopped at an event that does not verify"
		log.Printf("audit retention: account=%s: pruning stopped at an event that does not verify; run a full chain verification", acct)
	case last.Stop == store.AuditPruneStopPending:
		summary += "; held at a write-ahead attempt whose outcome is inside the window"
	case last.Stop == store.AuditPruneStopStream:
		summary += "; held at an event not yet delivered to the SIEM stream"
	case last.Stop == store.AuditPruneStopBusy:
		summary += "; another replica is pruning this account"
	}
	origin.Resource = summary
	s.recordAudit(actx, store.AuditEvent{Action: "citadel.PruneAuditEvents", Result: result, ErrorType: errType, AuditOrigin: origin})
	if perr != nil {
		return total, perr
	}
	return total, nil
}
