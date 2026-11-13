package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// Write-ahead audit.
//
// A fail-closed audit write used to happen after the handler had already
// changed state: when it failed the response became a 500, but the change
// stayed committed and unaudited. Now no state change takes effect without
// an audit record:
//
//  1. Before a state-changing operation, an "attempt" event is appended
//     (action, actor, resource, result pending, a fresh correlation ID). If
//     that append fails the request is refused before anything changes.
//  2. The handler then runs and records its outcome as before; recordAudit
//     stamps those events with the attempt's correlation ID. If the outcome
//     append fails the change is still covered by the attempt, so the
//     response stands, the event goes to an in-process retry queue (flushed
//     by the "audit-outcome-retry" job) and the failure is logged loudly.
//  3. When the handler wrote no event of its own (a validation error, say),
//     withAuditContext appends an outcome derived from the response status.
//
// Entry points: handleKMS (every AWS JSON action), nativeSession (every
// state-changing /v1 request), and explicit calls where the handler
// authenticates on its own (STS, login, bootstrap, logout, the ACME server)
// and in background jobs (beginJobAudit). Reads and cryptographic operations
// that change nothing (Encrypt, Sign, GetSecretValue...) write no attempt:
// their responses are withheld when their audit write fails, which is
// enough because nothing was changed. See docs/security-model.md.

// auditAttempt is the write-ahead state of one request or job step.
type auditAttempt struct {
	id       string
	event    store.AuditEvent // the completed attempt event
	outcomes int              // outcome events recorded so far
}

func (i *auditRequestInfo) attemptState() (auditAttempt, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.attempt == nil {
		return auditAttempt{}, false
	}
	return *i.attempt, true
}

// linkOutcome returns the attempt's correlation ID ("" without an attempt)
// and counts one more outcome.
func (i *auditRequestInfo) linkOutcome() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.attempt == nil {
		return ""
	}
	i.attempt.outcomes++
	return i.attempt.id
}

func newCorrelationID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// beginAuditAttempt appends the write-ahead attempt for the request on ctx.
// It is a no-op when the request already has one, or when ctx carries no
// request audit state. On error the caller must refuse the request without
// changing anything.
func (s *Server) beginAuditAttempt(ctx context.Context, ev store.AuditEvent) error {
	info := auditInfoFrom(ctx)
	if info == nil {
		return nil
	}
	if _, ok := info.attemptState(); ok {
		return nil
	}
	return s.appendAttempt(ctx, info, ev)
}

func (s *Server) appendAttempt(ctx context.Context, info *auditRequestInfo, ev store.AuditEvent) error {
	ev.Result, ev.ErrorType = store.AuditResultPending, ""
	ev.CorrelationID = newCorrelationID()
	ev = s.completeAudit(ctx, ev)
	if err := s.store.RecordAudit(ctx, ev); err != nil {
		log.Printf("AUDIT WRITE FAILED action=%s result=pending: request refused before any change: %v", ev.Action, err)
		return err
	}
	info.mu.Lock()
	info.attempt = &auditAttempt{id: ev.CorrelationID, event: ev}
	info.mu.Unlock()
	return nil
}

// beginJobAudit is beginAuditAttempt for background work: it always starts
// a fresh attempt scope and returns the context to record outcomes with.
func (s *Server) beginJobAudit(ctx context.Context, ev store.AuditEvent) (context.Context, error) {
	info := &auditRequestInfo{}
	jctx := context.WithValue(ctx, auditInfoCtxKey{}, info)
	if err := s.appendAttempt(jctx, info, ev); err != nil {
		return ctx, err
	}
	return jctx, nil
}

// finishAudit records an outcome for the attempt on ctx unless the code
// path already recorded one.
func (s *Server) finishAudit(ctx context.Context, result, errType string) {
	info := auditInfoFrom(ctx)
	if info == nil {
		return
	}
	a, ok := info.attemptState()
	if !ok || a.outcomes > 0 {
		return
	}
	info.linkOutcome()
	ev := a.event
	ev.Result, ev.ErrorType = result, errType
	s.appendOutcome(context.WithoutCancel(ctx), ev)
}

// appendOutcome writes a completed, correlated outcome event, queueing it
// for retry when the store refuses it.
func (s *Server) appendOutcome(ctx context.Context, ev store.AuditEvent) {
	if err := s.store.RecordAudit(ctx, ev); err != nil {
		s.queueAuditOutcome(ev, err)
	}
}

// outcomeForStatus maps a response status onto an audit result.
func outcomeForStatus(code int) (result, errType string) {
	switch {
	case code == 0 || code < 400:
		return store.AuditResultSuccess, ""
	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		return store.AuditResultDenied, "AccessDenied"
	default:
		return store.AuditResultError, "HTTP" + strconv.Itoa(code)
	}
}

// ---- outcome retry queue ---------------------------------------------------

const (
	// auditOutcomeQueueMax bounds the queue. Beyond it the oldest event is
	// dropped (and logged): its attempt is already recorded.
	auditOutcomeQueueMax      = 50000
	auditOutcomeRetryInterval = 10 * time.Second
)

type auditOutcomeQueue struct {
	mu      sync.Mutex
	items   []store.AuditEvent
	dropped int64
}

func (s *Server) queueAuditOutcome(ev store.AuditEvent, cause error) {
	q := &s.audit.outcomes
	q.mu.Lock()
	if len(q.items) >= auditOutcomeQueueMax {
		lost := q.items[0]
		q.items = q.items[1:]
		q.dropped++
		log.Printf("AUDIT OUTCOME DROPPED action=%s correlation=%s: retry queue full (%d); the attempt event is recorded", lost.Action, lost.CorrelationID, auditOutcomeQueueMax)
	}
	q.items = append(q.items, ev)
	depth := len(q.items)
	q.mu.Unlock()
	log.Printf("AUDIT WRITE FAILED action=%s result=%s correlation=%s: outcome queued for retry (queue depth %d): %v", ev.Action, ev.Result, ev.CorrelationID, depth, cause)
	s.obsRuntime().auditQueue.Set(float64(depth))
}

// auditOutcomeBacklog is the number of outcome events waiting for retry.
func (s *Server) auditOutcomeBacklog() int {
	q := &s.audit.outcomes
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

// flushAuditOutcomes appends queued outcome events in order, stopping at the
// first failure (the store is still unavailable; the next run retries).
func (s *Server) flushAuditOutcomes(ctx context.Context) error {
	q := &s.audit.outcomes
	for {
		q.mu.Lock()
		if len(q.items) == 0 {
			q.mu.Unlock()
			s.obsRuntime().auditQueue.Set(0)
			return nil
		}
		ev := q.items[0]
		q.mu.Unlock()
		if err := s.store.RecordAudit(ctx, ev); err != nil {
			log.Printf("AUDIT OUTCOME RETRY FAILED: %d event(s) still queued: %v", s.auditOutcomeBacklog(), err)
			return err
		}
		q.mu.Lock()
		// Only this job removes from the front, so items[0] is still ev.
		q.items = q.items[1:]
		depth := len(q.items)
		q.mu.Unlock()
		s.obsRuntime().auditQueue.Set(float64(depth))
	}
}

// ---- request classification ------------------------------------------------

// awsNonMutatingVerbs are fail-closed AWS actions that change no state:
// cryptographic operations and secret disclosures. Their audit failure
// withholds the response; they need no write-ahead attempt.
var awsNonMutatingVerbs = map[string]bool{
	"Encrypt": true, "Decrypt": true, "ReEncrypt": true,
	"GenerateDataKey": true, "GenerateDataKeyWithoutPlaintext": true,
	"GenerateDataKeyPair": true, "GenerateDataKeyPairWithoutPlaintext": true,
	"GenerateRandom": true, "Sign": true, "Verify": true, "GenerateMac": true, "VerifyMac": true,
	"GetSecretValue": true, "BatchGetSecretValue": true, "GetRandomPassword": true,
	"GetParameter": true, "GetParameters": true, "GetParametersByPath": true,
	"ExportCertificate": true, "ValidateResourcePolicy": true,
}

// awsWriteAhead reports whether an AWS JSON action needs a write-ahead
// attempt: every fail-closed action except the non-mutating ones.
func awsWriteAhead(target string) bool {
	if !auditFailClosed(target) {
		return false
	}
	verb := target
	if i := strings.LastIndex(verb, "."); i >= 0 {
		verb = verb[i+1:]
	}
	return !awsNonMutatingVerbs[verb]
}

// nativeNonMutating are /v1 POST routes that change no state.
var nativeNonMutating = map[string]bool{
	"/v1/kms/encrypt": true, "/v1/kms/decrypt": true, "/v1/kms/sign": true, "/v1/kms/verify": true,
	"/v1/admin/sso/providers/test": true, "/v1/audit/stream/test": true,
	// Verification walks the chain; an attempt event would extend the chain
	// it is verifying. Its result is audited (fail-closed) as before.
	"/v1/audit/verify": true,
}

// nativeWriteAhead reports whether a /v1 request needs a write-ahead attempt.
func nativeWriteAhead(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return !nativeNonMutating[r.URL.Path]
}

// nativeAttemptAction names a /v1 request in its attempt event ("POST
// /v1/secrets"): the specific action name is chosen later by the handler
// and appears on the correlated outcome.
func nativeAttemptAction(r *http.Request) string {
	return r.Method + " " + r.URL.Path
}

// requestResource names the resource of a request whose target may be in a
// JSON body: the query string first, else the body's identifying field. The
// body is restored for the handler.
func requestResource(r *http.Request) string {
	if res := resourceFromQuery(r); res != "" {
		return res
	}
	return resourceFromBody(r)
}

// auditBodyPeek bounds how much of a body is read to name its resource.
const auditBodyPeek = 1 << 20

func resourceFromBody(r *http.Request) string {
	if r.Body == nil || r.Body == http.NoBody {
		return ""
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, auditBodyPeek+1))
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(buf), r.Body), r.Body}
	if err != nil || len(buf) > auditBodyPeek {
		return ""
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(buf, &fields) != nil {
		return ""
	}
	v := url.Values{}
	for k, raw := range fields {
		var str string
		if json.Unmarshal(raw, &str) == nil && str != "" {
			v.Set(k, str)
		}
	}
	return resourceFromValues(v, bodyResourceKeys)
}

// bodyResourceKeys are the identifying fields of AWS and native bodies, in
// priority order. Value fields (SecretString, plaintext...) are never used.
var bodyResourceKeys = []string{
	"SecretId", "KeyId", "CertificateArn", "CertificateAuthorityArn", "AliasName", "Name", "GrantId",
	"providerArn", "arn", "certificateArn", "keyId", "aliasName", "roleName", "username", "clientId",
	"accessKeyId", "accountId", "name", "id",
}

// ensureAudit is beginJobAudit unless ctx already carries an attempt (work
// shared by a request handler and a job).
func (s *Server) ensureAudit(ctx context.Context, ev store.AuditEvent) (context.Context, error) {
	if info := auditInfoFrom(ctx); info != nil {
		if _, ok := info.attemptState(); ok {
			return ctx, nil
		}
	}
	return s.beginJobAudit(ctx, ev)
}
