package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/worlddrknss/citadel/internal/agentbroker"
	"github.com/worlddrknss/citadel/internal/providertoken"
	"github.com/worlddrknss/citadel/internal/store"
)

// Agent broker and reveal (2.2), see docs/design/agent-credentials.md and
// docs/agents.md.
//
//   - POST /v1/agent/http: Citadel performs an HTTP request with a
//     credential injected; the agent never sees the value.
//   - POST /v1/agent/credentials/reveal: returns the value, only with an
//     explicit reveal grant.
//
// Both accept only an agent Bearer credential: never a console cookie,
// never SigV4 or an access key. That is also why they (and /mcp) are exempt
// from the CSRF checks (see withCSRFProtection).

const (
	actionAgentHTTP            = "citadel.AgentHTTP"
	actionAgentReveal          = "citadel.AgentReveal"
	actionAgentListCredentials = "citadel.AgentListCredentials"
	actionMCPInitialize        = "citadel.MCPInitialize"
	actionMCPEndSession        = "citadel.MCPEndSession"

	agentActionUse    = "use"
	agentActionReveal = "reveal"

	// agentBrokerBodyMax bounds the JSON envelope: a 1 MiB body, base64
	// encoded, plus headers and the rest.
	agentBrokerBodyMax = 2 << 20

	maxAgentCredentialNameLen = 256
)

func (s *Server) registerAgentBrokerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/agent/http", s.handleAgentHTTP)
	mux.HandleFunc("POST /v1/agent/credentials/reveal", s.handleAgentReveal)
	mux.HandleFunc("/mcp", s.handleMCP)
}

// agentOnlyPath reports whether path is an agent endpoint, which only ever
// accepts an agent Bearer credential.
func agentOnlyPath(path string) bool {
	return path == "/mcp" || strings.HasPrefix(path, "/v1/agent/")
}

// agentBrokerError is the agent error shape: the native error plus the
// stable denial reason.
type agentBrokerError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Reason  string `json:"reason,omitempty"`
}

func writeAgentBrokerError(w http.ResponseWriter, status int, code, reason, msg string) {
	writeNativeJSON(w, status, agentBrokerError{Error: code, Message: msg, Reason: reason})
}

// agentFailure is a refused or failed agent operation, ready for the
// client.
type agentFailure struct {
	Status     int
	Code       string
	Reason     string
	Message    string
	RetryAfter int // seconds; 0 when none
}

func (f *agentFailure) write(w http.ResponseWriter) {
	if f.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(f.RetryAfter))
	}
	writeAgentBrokerError(w, f.Status, f.Code, f.Reason, f.Message)
}

// denialFailure maps an access denial onto a response. The messages never
// say whether a credential the agent has no grant for exists.
func denialFailure(u agentUse) *agentFailure {
	switch u.Reason {
	case "rate_limited":
		secs := int(u.RetryAfter.Seconds()) + 1
		return &agentFailure{Status: http.StatusTooManyRequests, Code: "rate_limited", Reason: u.Reason, Message: "the grant's hourly limit is used up; try again later", RetryAfter: secs}
	case "internal_error", "":
		return &agentFailure{Status: http.StatusInternalServerError, Code: "internal_error", Reason: "internal_error", Message: "the request could not be checked"}
	case "no_grant":
		return &agentFailure{Status: http.StatusForbidden, Code: "forbidden", Reason: u.Reason, Message: "this agent has no grant for that credential"}
	case "action_not_granted":
		return &agentFailure{Status: http.StatusForbidden, Code: "forbidden", Reason: u.Reason, Message: "the grant does not allow this action"}
	case "credential_unavailable":
		return &agentFailure{Status: http.StatusForbidden, Code: "forbidden", Reason: u.Reason, Message: "the credential's secret is not available"}
	}
	return &agentFailure{Status: http.StatusForbidden, Code: "forbidden", Reason: u.Reason, Message: "access to the credential is denied right now"}
}

func brokerFailure(e *agentbroker.Error) *agentFailure {
	code := "invalid_request"
	switch {
	case e.Status == http.StatusForbidden:
		code = "forbidden"
	case e.Status == http.StatusRequestEntityTooLarge:
		code = "too_large"
	case e.Status >= 500:
		code = "upstream_error"
	}
	return &agentFailure{Status: e.Status, Code: code, Reason: e.Reason, Message: e.Message}
}

// decodeAgentJSON reads a JSON body of at most max bytes, refusing unknown
// members.
func decodeAgentJSON(w http.ResponseWriter, r *http.Request, max int64, target any) *agentFailure {
	defer r.Body.Close()
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "application/json") {
		return &agentFailure{Status: http.StatusUnsupportedMediaType, Code: "invalid_request", Reason: "invalid_request", Message: "the body must be application/json"}
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, max))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return &agentFailure{Status: http.StatusRequestEntityTooLarge, Code: "too_large", Reason: agentbroker.ReasonBodyTooLarge, Message: "the request is too large"}
		}
		return &agentFailure{Status: http.StatusBadRequest, Code: "invalid_request", Reason: "invalid_request", Message: sanitizeJSONError(err).Error()}
	}
	if dec.More() {
		return &agentFailure{Status: http.StatusBadRequest, Code: "invalid_request", Reason: "invalid_request", Message: "the body must be one JSON object"}
	}
	return nil
}

// validCredentialName reports whether a credential name is safe to look up
// and record.
func validCredentialName(n string) bool {
	if n == "" || len(n) > maxAgentCredentialNameLen {
		return false
	}
	for _, c := range n {
		if c < 0x21 || c == 0x7f {
			return false
		}
	}
	return true
}

// validBrokerTaskID reports whether a task ID is safe to record.
func validBrokerTaskID(v string) bool {
	if v == "" || len(v) > 128 {
		return false
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-_.:/@#+=", c)) {
			return false
		}
	}
	return true
}

// applyTaskID adopts a task ID given in the body when no header named one.
func applyTaskID(c *agentCaller, taskID string) *agentFailure {
	if taskID == "" {
		return nil
	}
	if !validBrokerTaskID(taskID) {
		return &agentFailure{Status: http.StatusBadRequest, Code: "invalid_request", Reason: "invalid_task_id", Message: "taskId must be 1-128 letters, digits or -_.:/@#+="}
	}
	if c.TaskID != "" && c.TaskID != taskID {
		return &agentFailure{Status: http.StatusBadRequest, Code: "invalid_request", Reason: "invalid_task_id", Message: "taskId differs from the X-Citadel-Task-Id header"}
	}
	c.TaskID = taskID
	return nil
}

// agentHTTPAudit is what an AgentHTTP audit event records. Never the URL's
// query string, headers, bodies or the secret.
type agentHTTPAudit struct {
	credential string
	method     string
	host       string
	path       string
	status     int
	reqBytes   int
	respBytes  int
	redirects  int
	truncated  bool
	redacted   bool
	via        string
}

// resource renders the audit resource: space-separated key=value pairs.
func (a agentHTTPAudit) resource() string {
	var b strings.Builder
	fmt.Fprintf(&b, "credential=%s", auditToken(a.credential))
	if a.method != "" {
		fmt.Fprintf(&b, " method=%s", a.method)
	}
	if a.host != "" {
		fmt.Fprintf(&b, " host=%s", auditToken(a.host))
	}
	if a.path != "" {
		fmt.Fprintf(&b, " path=%s", auditToken(a.path))
	}
	if a.status > 0 {
		fmt.Fprintf(&b, " status=%d bytes=%d requestBytes=%d", a.status, a.respBytes, a.reqBytes)
	}
	if a.redirects > 0 {
		fmt.Fprintf(&b, " redirects=%d", a.redirects)
	}
	if a.truncated {
		b.WriteString(" truncated=true")
	}
	if a.redacted {
		b.WriteString(" redacted=true")
	}
	fmt.Fprintf(&b, " via=%s", a.via)
	return b.String()
}

// auditToken keeps a value on one token: spaces and controls become %XX.
func auditToken(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c <= 0x20 || c == 0x7f {
			fmt.Fprintf(&b, "%%%02X", c)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// brokerHTTP performs a brokered request for c. It records the audit event
// (before returning, so a failed fail-closed write withholds the response)
// and the metrics.
func (s *Server) brokerHTTP(ctx context.Context, r *http.Request, c *agentCaller, req agentbroker.Request, via string) (*agentbroker.Response, *agentFailure) {
	acc := s.agentAccess()
	rt := s.agentBrokerMetrics()
	ev := agentHTTPAudit{credential: req.Credential, method: strings.ToUpper(strings.TrimSpace(req.Method)), via: via}
	if ev.method == "" {
		ev.method = http.MethodGet
	}
	ev.host, ev.path = auditURLParts(req.URL)
	record := func(result, reason string) {
		s.recordAudit(ctx, store.AuditEvent{Action: actionAgentHTTP, KeyID: req.Credential, Result: result, ErrorType: reason, AuditOrigin: withResource(acc.auditOrigin(r, c), ev.resource())})
		rt.reqs.Inc(via, result, metricReason(reason))
	}
	fail := func(f *agentFailure, result string) (*agentbroker.Response, *agentFailure) {
		record(result, f.Reason)
		return nil, f
	}

	if !validCredentialName(req.Credential) {
		return fail(&agentFailure{Status: http.StatusBadRequest, Code: "invalid_request", Reason: "invalid_request", Message: "credential is required"}, store.AuditResultDenied)
	}
	if f := applyTaskID(c, req.TaskID); f != nil {
		return fail(f, store.AuditResultDenied)
	}
	release, ok := rt.acquire(c.AgentID)
	if !ok {
		return fail(&agentFailure{Status: http.StatusServiceUnavailable, Code: "busy", Reason: "broker_busy", Message: "too many brokered requests in flight; retry shortly", RetryAfter: 1}, store.AuditResultError)
	}
	defer release()

	use := acc.evaluate(ctx, c, req.Credential, agentActionUse)
	if !use.Allowed {
		f := denialFailure(use)
		result := store.AuditResultDenied
		if f.Status >= 500 {
			result = store.AuditResultError
		}
		return fail(f, result)
	}
	pr, err := agentbroker.Prepare(req, use.Profile, rt.limits)
	if err != nil {
		var be *agentbroker.Error
		if !errors.As(err, &be) {
			be = &agentbroker.Error{Status: http.StatusBadRequest, Reason: agentbroker.ReasonInvalidRequest, Message: "invalid request"}
		}
		return fail(brokerFailure(be), store.AuditResultDenied)
	}
	ev.method, ev.host, ev.path, ev.reqBytes = pr.Method, pr.Target.Host, pr.Target.AuditPath(), len(pr.Body)

	secret, err := s.mintAgentCredential(ctx, c, use)
	if err != nil {
		log.Printf("agent broker: credential value unavailable: %v", err)
		return fail(&agentFailure{Status: http.StatusForbidden, Code: "forbidden", Reason: "credential_unavailable", Message: "the credential's secret is not available"}, store.AuditResultError)
	}
	resp, res, err := agentbroker.Do(ctx, pr, secret, agentbroker.Options{
		Client:    rt.httpClient(use.Profile.AllowedCIDRs),
		IsBlocked: isOutboundBlocked,
		Limits:    rt.limits,
		UserAgent: AppName + "-agent-broker",
	})
	ev.method, ev.host, ev.path = res.Method, res.Target.Host, res.Target.AuditPath()
	ev.status, ev.respBytes, ev.redirects, ev.truncated, ev.redacted = res.Status, res.ResponseBytes, res.Redirects, res.Truncated, res.Redacted
	if res.Status > 0 {
		rt.upstream.Inc(strconv.Itoa(res.Status/100) + "xx")
		rt.duration.Observe(res.Duration.Seconds(), via)
	}
	if err != nil {
		var be *agentbroker.Error
		if !errors.As(err, &be) {
			be = &agentbroker.Error{Status: http.StatusBadGateway, Reason: agentbroker.ReasonUpstreamUnreachable, Message: "the upstream could not be reached"}
		}
		result := store.AuditResultError
		if be.Reason == agentbroker.ReasonDestinationBlocked {
			result = store.AuditResultDenied
		}
		return fail(brokerFailure(be), result)
	}
	record(store.AuditResultSuccess, "")
	return resp, nil
}

// mintAgentCredential produces the credential's value for an allowed use
// through its minter. The value must never be logged or audited.
func (s *Server) mintAgentCredential(ctx context.Context, c *agentCaller, u agentUse) (string, error) {
	m, err := s.agentAccess().minter(ctx, c, u)
	if err != nil {
		return "", err
	}
	tok, err := m.Mint(ctx, providertoken.Params{})
	if err != nil {
		return "", err
	}
	return tok.Value, nil
}

// auditURLParts extracts host and path (no query) from a URL the broker
// refused, for the audit record.
func auditURLParts(raw string) (string, string) {
	if len(raw) > 2048 {
		raw = raw[:2048]
	}
	rest, ok := strings.CutPrefix(raw, "https://")
	if !ok {
		if rest, ok = strings.CutPrefix(raw, "http://"); !ok {
			return "", ""
		}
	}
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	host, path, _ := strings.Cut(rest, "/")
	if at := strings.LastIndex(host, "@"); at >= 0 {
		host = host[at+1:] // never record userinfo
	}
	return strings.ToLower(host), "/" + path
}

func withResource(o store.AuditOrigin, resource string) store.AuditOrigin {
	o.Resource = resource
	return o
}

// handleAgentHTTP is POST /v1/agent/http.
func (s *Server) handleAgentHTTP(w http.ResponseWriter, r *http.Request) {
	c, ctx, ok := s.agentAccess().authenticate(w, r, actionAgentHTTP)
	if !ok {
		return
	}
	var req agentbroker.Request
	if f := decodeAgentJSON(w, r, agentBrokerBodyMax, &req); f != nil {
		f.write(w)
		return
	}
	resp, f := s.brokerHTTP(ctx, r, c, req, "api")
	if f != nil {
		f.write(w)
		return
	}
	writeNativeJSON(w, http.StatusOK, resp)
}

// agentRevealRequest is the body of POST /v1/agent/credentials/reveal.
type agentRevealRequest struct {
	Credential string `json:"credential"`
	TaskID     string `json:"taskId,omitempty"`
}

// agentRevealResponse carries a revealed value.
type agentRevealResponse struct {
	Credential string `json:"credential"`
	Kind       string `json:"kind"`
	Value      string `json:"value"`
}

// revealCredential returns the value of a credential the agent holds a
// reveal grant for. The audit event is written before the value is
// returned.
func (s *Server) revealCredential(ctx context.Context, r *http.Request, c *agentCaller, req agentRevealRequest, via string) (*agentRevealResponse, *agentFailure) {
	acc := s.agentAccess()
	rt := s.agentBrokerMetrics()
	record := func(result, reason string) {
		res := "credential=" + auditToken(req.Credential) + " via=" + via
		s.recordAudit(ctx, store.AuditEvent{Action: actionAgentReveal, KeyID: req.Credential, Result: result, ErrorType: reason, AuditOrigin: withResource(acc.auditOrigin(r, c), res)})
		rt.reveals.Inc(via, result, metricReason(reason))
	}
	fail := func(f *agentFailure, result string) (*agentRevealResponse, *agentFailure) {
		record(result, f.Reason)
		return nil, f
	}
	if !validCredentialName(req.Credential) {
		return fail(&agentFailure{Status: http.StatusBadRequest, Code: "invalid_request", Reason: "invalid_request", Message: "credential is required"}, store.AuditResultDenied)
	}
	if f := applyTaskID(c, req.TaskID); f != nil {
		return fail(f, store.AuditResultDenied)
	}
	use := acc.evaluate(ctx, c, req.Credential, agentActionReveal)
	if !use.Allowed {
		f := denialFailure(use)
		result := store.AuditResultDenied
		if f.Status >= 500 {
			result = store.AuditResultError
		}
		return fail(f, result)
	}
	value, err := s.mintAgentCredential(ctx, c, use)
	if err != nil {
		log.Printf("agent reveal: credential value unavailable: %v", err)
		return fail(&agentFailure{Status: http.StatusForbidden, Code: "forbidden", Reason: "credential_unavailable", Message: "the credential's secret is not available"}, store.AuditResultError)
	}
	record(store.AuditResultSuccess, "")
	if info := auditInfoFrom(ctx); info != nil && info.hasFailed() {
		return nil, &agentFailure{Status: http.StatusInternalServerError, Code: "audit_unavailable", Reason: "audit_unavailable", Message: "the audit log could not be written; the value is withheld"}
	}
	kind := use.Credential.Kind
	if kind == "" {
		kind = use.Profile.Kind
	}
	return &agentRevealResponse{Credential: req.Credential, Kind: kind, Value: value}, nil
}

// handleAgentReveal is POST /v1/agent/credentials/reveal.
func (s *Server) handleAgentReveal(w http.ResponseWriter, r *http.Request) {
	c, ctx, ok := s.agentAccess().authenticate(w, r, actionAgentReveal)
	if !ok {
		return
	}
	var req agentRevealRequest
	if f := decodeAgentJSON(w, r, 16<<10, &req); f != nil {
		f.write(w)
		return
	}
	resp, f := s.revealCredential(ctx, r, c, req, "api")
	if f != nil {
		f.write(w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeNativeJSON(w, http.StatusOK, resp)
}
