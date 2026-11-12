package server

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// Audit API (contracts.md "Audit"): filtered listing, chain verification,
// export and SIEM streaming. Every read is scoped to the caller's account.

func (s *Server) registerAuditRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/audit/events", s.handleV1AuditEvents)
	mux.HandleFunc("GET /v1/audit/verify", s.handleV1AuditVerifyStatus)
	mux.HandleFunc("POST /v1/audit/verify", s.handleV1AuditVerify)
	mux.HandleFunc("GET /v1/audit/export", s.handleV1AuditExport)
	mux.HandleFunc("GET /v1/audit/stream", s.handleV1GetAuditStream)
	mux.HandleFunc("POST /v1/audit/stream", s.handleV1PutAuditStream)
	mux.HandleFunc("POST /v1/audit/stream/test", s.handleV1TestAuditStream)
}

const (
	auditPageDefault = 50
	auditPageMax     = 500
	auditOffsetMax   = 100000
	auditFilterMax   = 256
	// auditExportMax caps one export. Narrower filters get the rest.
	auditExportMax   = 100000
	auditExportBatch = 1000
	// auditExportPerMinute is how many exports one user may start per
	// minute in one account (per replica).
	auditExportPerMinute = 5
)

// auditAccount is the account whose log the request may see.
func (s *Server) auditAccount(ctx context.Context) string {
	if acct, ok := store.CallerAccountFromContext(ctx); ok {
		return acct
	}
	_, acct := s.store.DeploymentIdentity()
	return acct
}

type auditEventJSON struct {
	ID               int64  `json:"id"`
	CreatedAt        string `json:"createdAt"`
	Actor            string `json:"actor"`
	ActorType        string `json:"actorType,omitempty"`
	ActorDisplayName string `json:"actorDisplayName,omitempty"`
	AccessKeyID      string `json:"accessKeyId,omitempty"`
	Action           string `json:"action"`
	Resource         string `json:"resource,omitempty"`
	KeyID            string `json:"keyId,omitempty"`
	Result           string `json:"result"`
	ErrorType        string `json:"errorType,omitempty"`
	SourceIP         string `json:"sourceIp,omitempty"`
	UserAgent        string `json:"userAgent,omitempty"`
	ChainSeq         int64  `json:"chainSeq,omitempty"`
	PrevHash         string `json:"prevHash,omitempty"`
	Hash             string `json:"hash,omitempty"`
	HashValid        *bool  `json:"hashValid,omitempty"`
}

func toAuditEventJSON(rec store.AuditRecord) auditEventJSON {
	return auditEventJSON{
		ID:               rec.ID,
		CreatedAt:        rec.CreatedAt.UTC().Format(time.RFC3339Nano),
		Actor:            rec.Actor,
		ActorType:        rec.ActorType,
		ActorDisplayName: rec.ActorDisplayName,
		AccessKeyID:      rec.AccessKeyID,
		Action:           rec.Action,
		Resource:         rec.Resource,
		KeyID:            rec.KeyID,
		Result:           store.NormalizeAuditResult(rec.Result, rec.ErrorType),
		ErrorType:        rec.ErrorType,
		SourceIP:         rec.SourceIP,
		UserAgent:        rec.UserAgent,
		ChainSeq:         rec.ChainSeq,
		PrevHash:         rec.PrevHash,
		Hash:             rec.EventHash,
		HashValid:        rec.HashValid,
	}
}

// parseAuditFilters reads from, to, actor, action, result and resource.
func parseAuditFilters(r *http.Request) (store.AuditQuery, string) {
	q := r.URL.Query()
	var out store.AuditQuery
	parseTime := func(name string) (*time.Time, string) {
		v := strings.TrimSpace(q.Get(name))
		if v == "" {
			return nil, ""
		}
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			return nil, name + " must be an RFC 3339 timestamp"
		}
		return &t, ""
	}
	var msg string
	if out.From, msg = parseTime("from"); msg != "" {
		return out, msg
	}
	if out.To, msg = parseTime("to"); msg != "" {
		return out, msg
	}
	if out.From != nil && out.To != nil && out.To.Before(*out.From) {
		return out, "to must not be before from"
	}
	for _, f := range []struct {
		name string
		dst  *string
	}{{"actor", &out.Actor}, {"action", &out.Action}, {"resource", &out.Resource}} {
		v := strings.TrimSpace(q.Get(f.name))
		if len(v) > auditFilterMax {
			return out, fmt.Sprintf("%s must be at most %d characters", f.name, auditFilterMax)
		}
		*f.dst = v
	}
	switch v := strings.ToLower(strings.TrimSpace(q.Get("result"))); v {
	case "", store.AuditResultSuccess, store.AuditResultDenied, store.AuditResultError:
		out.Result = v
	default:
		return out, "result must be success, denied or error"
	}
	return out, ""
}

func parseBoundedInt(raw string, def, lo, hi int) (int, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return def, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < lo || n > hi {
		return 0, false
	}
	return n, true
}

// GET /v1/audit/events — viewer.
func (s *Server) handleV1AuditEvents(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	q, msg := parseAuditFilters(r)
	if msg != "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", msg)
		return
	}
	limit, ok := parseBoundedInt(r.URL.Query().Get("limit"), auditPageDefault, 1, auditPageMax)
	if !ok {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("limit must be between 1 and %d", auditPageMax))
		return
	}
	offset, ok := parseBoundedInt(r.URL.Query().Get("offset"), 0, 0, auditOffsetMax)
	if !ok {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("offset must be between 0 and %d", auditOffsetMax))
		return
	}
	q.Limit, q.Offset = limit, offset
	total, err := s.store.CountAuditEvents(ctx, q)
	if err != nil {
		log.Printf("audit count failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "list_failed", "failed to list audit events")
		return
	}
	records, err := s.store.QueryAuditEvents(ctx, q)
	if err != nil {
		log.Printf("audit query failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "list_failed", "failed to list audit events")
		return
	}
	events := make([]auditEventJSON, 0, len(records))
	for _, rec := range records {
		events = append(events, toAuditEventJSON(rec))
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"events": events, "total": total, "limit": limit, "offset": offset})
}

type auditChainStatusJSON struct {
	Status          string `json:"status"`
	VerifiedThrough int64  `json:"verifiedThrough,omitempty"`
	HeadHash        string `json:"headHash,omitempty"`
	CheckedAt       string `json:"checkedAt,omitempty"`
	BrokenAt        *int64 `json:"brokenAt,omitempty"`
	TotalEvents     *int64 `json:"totalEvents,omitempty"`
}

func toChainStatusJSON(v store.AuditVerification) auditChainStatusJSON {
	out := auditChainStatusJSON{Status: v.Status}
	if v.Status == store.AuditChainNever || v.Status == "" {
		out.Status = store.AuditChainNever
		return out
	}
	out.VerifiedThrough = v.VerifiedID
	out.HeadHash = v.HeadHash
	out.CheckedAt = v.CheckedAt.UTC().Format(time.RFC3339)
	total := v.TotalEvents
	out.TotalEvents = &total
	if v.Status == store.AuditChainBroken {
		// The event ID when the broken event exists; for a missing tail, the
		// ID the head says should be there.
		brokenAt := v.BrokenID
		out.BrokenAt = &brokenAt
	}
	return out
}

// GET /v1/audit/verify — viewer. The last verification result.
func (s *Server) handleV1AuditVerifyStatus(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	v, err := s.store.GetAuditVerification(ctx, s.auditAccount(ctx))
	if err != nil {
		log.Printf("audit verification read failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "verify_failed", "failed to read the verification status")
		return
	}
	writeNativeJSON(w, http.StatusOK, toChainStatusJSON(v))
}

// POST /v1/audit/verify[?full=true] — viewer (full re-walk: admin). Verifies
// the account's chain from the last verified point (or from the start after a
// break, or when full) and returns the result.
func (s *Server) handleV1AuditVerify(w http.ResponseWriter, r *http.Request) {
	full := strings.EqualFold(r.URL.Query().Get("full"), "true")
	minRole := "viewer"
	if full {
		minRole = "admin"
	}
	_, ctx, ok := s.nativeSession(w, r, minRole)
	if !ok {
		return
	}
	account := s.auditAccount(ctx)
	v, err := s.store.VerifyAuditChain(ctx, account, full)
	if err != nil {
		log.Printf("audit verification failed request_id=%s: %v", requestIDFromContext(ctx), err)
		s.recordAudit(ctx, store.AuditEvent{Action: "citadel.VerifyAuditChain", Result: "error", ErrorType: "InternalFailure", AuditOrigin: s.auditOrigin(r)})
		writeNativeError(w, http.StatusInternalServerError, "verify_failed", "failed to verify the audit chain")
		return
	}
	if v.Status == store.AuditChainBroken {
		log.Printf("AUDIT CHAIN BROKEN request_id=%s event=%d seq=%d", requestIDFromContext(ctx), v.BrokenID, v.BrokenSeq)
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.VerifyAuditChain", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, toChainStatusJSON(v))
}

// allowExport is a sliding one-minute window per (account, user).
func (s *Server) allowExport(key string, now time.Time) (bool, time.Duration) {
	rt := &s.audit
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.exports == nil {
		rt.exports = map[string][]time.Time{}
	}
	cutoff := now.Add(-time.Minute)
	hits := rt.exports[key][:0]
	for _, t := range rt.exports[key] {
		if t.After(cutoff) {
			hits = append(hits, t)
		}
	}
	if len(hits) >= auditExportPerMinute {
		rt.exports[key] = hits
		return false, hits[0].Sub(cutoff)
	}
	rt.exports[key] = append(hits, now)
	if len(rt.exports) > 10000 {
		// Bound memory: drop idle keys.
		for k, v := range rt.exports {
			if len(v) == 0 || !v[len(v)-1].After(cutoff) {
				delete(rt.exports, k)
			}
		}
	}
	return true, 0
}

// csvSafe neutralizes spreadsheet formula injection (OWASP): a cell that
// starts with a formula trigger is prefixed with a single quote.
func csvSafe(v string) string {
	if v == "" {
		return v
	}
	switch v[0] {
	case '=', '+', '-', '@', '\t', '\r', '\n', '|':
		return "'" + v
	}
	for _, p := range []string{"＝", "＋", "－", "＠"} { // full-width forms some spreadsheets honor
		if strings.HasPrefix(v, p) {
			return "'" + v
		}
	}
	return v
}

var auditCSVColumns = []string{"id", "createdAt", "actor", "actorType", "actorDisplayName", "accessKeyId", "action", "resource", "keyId", "result", "errorType", "sourceIp", "userAgent", "chainSeq", "prevHash", "hash"}

func auditCSVRow(e auditEventJSON) []string {
	row := []string{
		strconv.FormatInt(e.ID, 10), e.CreatedAt, e.Actor, e.ActorType, e.ActorDisplayName, e.AccessKeyID,
		e.Action, e.Resource, e.KeyID, e.Result, e.ErrorType, e.SourceIP, e.UserAgent,
		strconv.FormatInt(e.ChainSeq, 10), e.PrevHash, e.Hash,
	}
	for i := range row {
		row[i] = csvSafe(row[i])
	}
	return row
}

// GET /v1/audit/export?format=csv|json&<filters> — viewer; rate limited,
// capped at auditExportMax events, audited as citadel.ExportAudit (fail
// closed: no audit record, no export).
func (s *Server) handleV1AuditExport(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "csv"
	}
	if format != "csv" && format != "json" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "format must be csv or json")
		return
	}
	q, msg := parseAuditFilters(r)
	if msg != "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", msg)
		return
	}
	account := s.auditAccount(ctx)
	if ok, retry := s.allowExport(account+"|"+sess.Username, time.Now()); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
		writeNativeError(w, http.StatusTooManyRequests, "rate_limited", fmt.Sprintf("at most %d exports per minute; try again shortly", auditExportPerMinute))
		return
	}
	total, err := s.store.CountAuditEvents(ctx, q)
	if err != nil {
		log.Printf("audit export count failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "export_failed", "failed to export audit events")
		return
	}
	// Pin the export to the events that existed when it was counted (the
	// export's own audit event, and anything after, are not included).
	var snapshotBefore int64
	if total > 0 {
		newest, err := s.store.QueryAuditEvents(ctx, store.AuditQuery{From: q.From, To: q.To, Actor: q.Actor, Action: q.Action, Resource: q.Resource, Result: q.Result, Limit: 1})
		if err != nil || len(newest) == 0 {
			if err != nil {
				log.Printf("audit export snapshot failed: %v", err)
			}
			writeNativeError(w, http.StatusInternalServerError, "export_failed", "failed to export audit events")
			return
		}
		snapshotBefore = newest[0].ID + 1
	}
	origin := s.auditOrigin(r)
	origin.Resource = "audit-log?" + r.URL.RawQuery
	if total > auditExportMax {
		s.recordAudit(ctx, store.AuditEvent{Action: "citadel.ExportAudit", Result: "error", ErrorType: "ExportTooLarge", AuditOrigin: origin})
		writeNativeError(w, http.StatusBadRequest, "export_too_large",
			fmt.Sprintf("%d events match; an export is limited to %d. Narrow the time range or filters.", total, auditExportMax))
		return
	}
	if err := s.writeAudit(ctx, store.AuditEvent{Action: "citadel.ExportAudit", Result: "ok", AuditOrigin: origin}); err != nil {
		log.Printf("AUDIT WRITE FAILED action=citadel.ExportAudit fail_closed=true: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "audit_unavailable", "the audit log could not be written; export refused")
		return
	}

	stamp := time.Now().UTC().Format("20060102T150405Z")
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="citadel-audit-%s.%s"`, stamp, format))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	var cw *csv.Writer
	if format == "csv" {
		cw = csv.NewWriter(w)
		cw.UseCRLF = true
		_ = cw.Write(auditCSVColumns)
	} else {
		_, _ = w.Write([]byte("[\n"))
	}
	written := 0
	q.BeforeID = snapshotBefore
	for total > 0 && written < auditExportMax {
		q.Limit = auditExportBatch
		batch, err := s.store.QueryAuditEvents(ctx, q)
		if err != nil {
			// Headers are gone; end the body so the truncation is visible.
			log.Printf("audit export page failed after %d events: %v", written, err)
			break
		}
		if len(batch) == 0 {
			break
		}
		for _, rec := range batch {
			e := toAuditEventJSON(rec)
			if cw != nil {
				_ = cw.Write(auditCSVRow(e))
			} else {
				b, _ := json.Marshal(e)
				if written > 0 {
					_, _ = w.Write([]byte(",\n"))
				}
				_, _ = w.Write(b)
			}
			written++
		}
		q.BeforeID = batch[len(batch)-1].ID
		if cw != nil {
			cw.Flush()
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
	if cw != nil {
		cw.Flush()
	} else {
		_, _ = w.Write([]byte("\n]\n"))
	}
}
