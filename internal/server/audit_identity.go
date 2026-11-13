package server

import (
	"context"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"sync"

	"github.com/worlddrknss/citadel/internal/store"
)

// Audit identity.
//
// Handlers record events as
//
//	s.recordAudit(ctx, store.AuditEvent{Action: ..., Result: ..., AuditOrigin: s.auditOrigin(r)})
//
// auditOrigin captures who made the request (the verified SigV4 caller, or
// the console/bearer session nativeSession resolved), the client IP (honoring
// X-Forwarded-For / X-Real-IP only from KMS_TRUSTED_PROXIES), the user agent
// and, for native requests, the resource named in the query string.
// recordAudit fills in what the origin could not know (the account, the
// session on ctx, the resource from the key ID) and enforces fail-closed.

// auditPrincipal is an authenticated identity.
type auditPrincipal struct {
	actor       string
	actorType   string
	displayName string
	accessKeyID string
	accountID   string
	// agentID, agentOwner and taskID are set for agent principals.
	agentID    string
	agentOwner string
	taskID     string
}

// auditRequestInfo is per-request audit state, installed by withAuditContext.
// Auth fills in the principal; recordAudit flags a failed fail-closed write.
type auditRequestInfo struct {
	mu        sync.Mutex
	principal *auditPrincipal
	failed    bool
	// attempt is the request's write-ahead attempt (audit_writeahead.go).
	attempt *auditAttempt
}

type auditInfoCtxKey struct{}
type auditPrincipalCtxKey struct{}

func auditInfoFrom(ctx context.Context) *auditRequestInfo {
	info, _ := ctx.Value(auditInfoCtxKey{}).(*auditRequestInfo)
	return info
}

func (i *auditRequestInfo) setPrincipal(p *auditPrincipal) {
	i.mu.Lock()
	i.principal = p
	i.mu.Unlock()
}

func (i *auditRequestInfo) getPrincipal() *auditPrincipal {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.principal
}

func (i *auditRequestInfo) markFailed() {
	i.mu.Lock()
	i.failed = true
	i.mu.Unlock()
}

func (i *auditRequestInfo) hasFailed() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.failed
}

// nativeSession resolves the caller of a native /v1 request (see
// resolveNativeSession) and remembers the identity for the audit log.
func (s *Server) nativeSession(w http.ResponseWriter, r *http.Request, minRole string) (*uiSession, context.Context, bool) {
	sess, ctx, ok := s.resolveNativeSession(w, r, minRole)
	if !ok || sess == nil {
		return sess, ctx, ok
	}
	p := principalForSession(r, sess)
	if info := auditInfoFrom(r.Context()); info != nil {
		info.setPrincipal(p)
	}
	if ctx == nil {
		ctx = r.Context()
	}
	ctx = context.WithValue(ctx, auditPrincipalCtxKey{}, p)
	if nativeWriteAhead(r) {
		origin := s.auditOrigin(r)
		origin.Resource = requestResource(r)
		if err := s.beginAuditAttempt(ctx, store.AuditEvent{Action: nativeAttemptAction(r), AuditOrigin: origin}); err != nil {
			writeNativeError(w, http.StatusInternalServerError, "audit_unavailable", "the audit log could not be written; nothing was changed")
			return nil, nil, false
		}
	}
	return sess, ctx, true
}

// principalForSession describes a native session. Bearer-token sessions carry
// the access key ID as their username; the owner is resolved lazily when an
// event is written.
func principalForSession(r *http.Request, sess *uiSession) *auditPrincipal {
	p := &auditPrincipal{actor: sess.Username, actorType: store.AuditActorConsole, displayName: sess.DisplayName, accountID: sess.AccountID}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(auth) > 7 && strings.EqualFold(auth[:7], "bearer ") {
		keyID, _, _ := strings.Cut(strings.TrimSpace(auth[7:]), ":")
		if strings.TrimSpace(keyID) != sess.Username {
			return p // some other bearer identity (OIDC)
		}
		p.actorType = store.AuditActorAccessKey
		p.accessKeyID = sess.Username
		p.displayName = ""
	}
	return p
}

func principalForAWSCaller(s *Server, c awsCaller) *auditPrincipal {
	p := &auditPrincipal{actor: c.Username, actorType: store.AuditActorAccessKey, accessKeyID: c.AccessKeyID, accountID: c.AccountID}
	switch {
	case c.Temporary:
		p.actor = c.PrincipalARN()
		p.actorType = store.AuditActorAssumedRole
	case s.cfg.ExpectedAccessKey != "" && c.AccessKeyID == s.cfg.ExpectedAccessKey:
		p.actor = "deployment-credential"
		p.actorType = store.AuditActorDeployment
	}
	return p
}

func (p *auditPrincipal) apply(o *store.AuditOrigin) {
	o.Actor, o.ActorType, o.ActorDisplayName, o.AccessKeyID = p.actor, p.actorType, p.displayName, p.accessKeyID
	if p.agentID != "" {
		o.AgentID, o.AgentOwner, o.TaskID = p.agentID, p.agentOwner, p.taskID
	}
	if o.AccountID == "" {
		o.AccountID = p.accountID
	}
}

// auditOrigin captures the request's identity, source and resource.
func (s *Server) auditOrigin(r *http.Request) store.AuditOrigin {
	o := store.AuditOrigin{
		SourceIP:  s.clientIP(r),
		UserAgent: r.UserAgent(),
		Resource:  resourceFromQuery(r),
	}
	if c, ok := awsCallerFromContext(r.Context()); ok {
		principalForAWSCaller(s, c).apply(&o)
	} else if info := auditInfoFrom(r.Context()); info != nil {
		if p := info.getPrincipal(); p != nil {
			p.apply(&o)
		}
	}
	return o
}

// stsAuditOrigin is auditOrigin for STS credential issuance, where the
// handler authenticated the caller itself. resource is the assumed-role ARN;
// the issued temporary access key ID is appended so later events made with it
// (whose AccessKeyID it is) can be traced back to this issuance.
func (s *Server) stsAuditOrigin(r *http.Request, actorType, actor, assumedARN, issuedKeyID string) store.AuditOrigin {
	o := s.auditOrigin(r)
	o.Actor, o.ActorType, o.ActorDisplayName, o.AccessKeyID = actor, actorType, "", ""
	o.Resource = assumedARN
	if issuedKeyID != "" {
		o.Resource += "#" + issuedKeyID
	}
	return o
}

// resourceFromQuery names the resource of a native request from its query
// string: "project/env/path/key" for the secrets hierarchy, otherwise the
// first identifying parameter. Requests whose target is in the body get the
// key ID (or nothing) instead.
func resourceFromQuery(r *http.Request) string {
	if r.URL == nil || r.URL.RawQuery == "" {
		return ""
	}
	return resourceFromValues(r.URL.Query(), queryResourceKeys)
}

var queryResourceKeys = []string{"providerArn", "arn", "keyId", "aliasName", "roleName", "username", "accessKeyId", "accountId", "agentId", "name", "id"}

// resourceFromValues names a resource from request parameters: the secrets
// hierarchy path when a project is given, else the first of keys present.
func resourceFromValues(q url.Values, keys []string) string {
	if project := strings.TrimSpace(q.Get("project")); project != "" {
		parts := []string{project}
		for _, k := range []string{"env", "path", "key", "name"} {
			if v := strings.Trim(strings.TrimSpace(q.Get(k)), "/"); v != "" {
				parts = append(parts, v)
			}
		}
		return path.Clean(strings.Join(parts, "/"))
	}
	for _, k := range keys {
		if v := strings.TrimSpace(q.Get(k)); v != "" {
			return v
		}
	}
	return ""
}

// clientIP is the request's source address. X-Forwarded-For and X-Real-IP
// are honored only when the direct peer is a trusted proxy; the client is
// then the right-most X-Forwarded-For entry that is not itself a trusted
// proxy (entries left of it are client-controlled).
func (s *Server) clientIP(r *http.Request) string {
	peer := r.RemoteAddr
	if host, _, err := net.SplitHostPort(peer); err == nil {
		peer = host
	}
	peerAddr, err := netip.ParseAddr(peer)
	if err != nil {
		return peer
	}
	peerAddr = peerAddr.Unmap()
	if !s.trustedProxy(peerAddr) {
		return peerAddr.String()
	}
	if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
		hops := strings.Split(strings.Join(xff, ","), ",")
		var leftmost string
		for i := len(hops) - 1; i >= 0; i-- {
			a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
			if err != nil {
				break // malformed hop: stop trusting the chain here
			}
			a = a.Unmap()
			leftmost = a.String()
			if !s.trustedProxy(a) {
				return a.String()
			}
		}
		if leftmost != "" {
			return leftmost
		}
	}
	if real := strings.TrimSpace(r.Header.Get("X-Real-IP")); real != "" {
		if a, err := netip.ParseAddr(real); err == nil {
			return a.Unmap().String()
		}
	}
	return peerAddr.String()
}

func (s *Server) trustedProxy(a netip.Addr) bool {
	for _, p := range s.cfg.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// auditFailClosed reports whether a failed audit write must fail the
// request. Only pure metadata reads (List*, Describe*, Get* that disclose no
// secret material) fail open; every state change, every cryptographic
// operation and every disclosure of a secret value fails closed.
func auditFailClosed(action string) bool {
	verb := action
	if i := strings.LastIndex(verb, "."); i >= 0 {
		verb = verb[i+1:]
	}
	switch verb {
	case "GetSecretValue", "BatchGetSecretValue", "GetParameter", "GetParameters", "GetParametersByPath":
		return true
	}
	for _, p := range []string{"List", "Describe", "Get"} {
		if strings.HasPrefix(verb, p) {
			return false
		}
	}
	return true
}

// recordAudit appends event to the audit log. Under a write-ahead attempt
// (audit_writeahead.go) the event is the attempt's outcome: it carries the
// attempt's correlation ID, and a failed write is queued for retry rather
// than failing the request, because the attempt already records the change.
// Without an attempt, a failed write logs loudly and, for fail-closed
// actions, flags the request so withAuditContext replaces the response with
// a 500 (when it has not been sent yet).
func (s *Server) recordAudit(ctx context.Context, event store.AuditEvent) {
	var correlation string
	if info := auditInfoFrom(ctx); info != nil {
		correlation = info.linkOutcome()
	}
	if correlation != "" && event.CorrelationID == "" {
		event.CorrelationID = correlation
	}
	event = s.completeAudit(ctx, event)
	err := s.store.RecordAudit(ctx, event)
	if err == nil {
		return
	}
	if correlation != "" {
		s.queueAuditOutcome(event, err)
		return
	}
	closed := auditFailClosed(event.Action) && store.NormalizeAuditResult(event.Result, event.ErrorType) == store.AuditResultSuccess
	// Nothing request-scoped is logged here; the request log line for the
	// same request (status 500 when fail-closed) carries the request ID.
	log.Printf("AUDIT WRITE FAILED action=%s result=%s fail_closed=%t: %v", event.Action, event.Result, closed, err)
	if closed {
		if info := auditInfoFrom(ctx); info != nil {
			info.markFailed()
		}
	}
}

// writeAudit completes event from ctx and appends it.
func (s *Server) writeAudit(ctx context.Context, event store.AuditEvent) error {
	return s.store.RecordAudit(ctx, s.completeAudit(ctx, event))
}

// completeAudit fills in what the handler's event could not know: the
// principal, the account and the resource.
func (s *Server) completeAudit(ctx context.Context, event store.AuditEvent) store.AuditEvent {
	if event.Actor == "" {
		if p, ok := ctx.Value(auditPrincipalCtxKey{}).(*auditPrincipal); ok {
			p.apply(&event.AuditOrigin)
		} else if c, ok := awsCallerFromContext(ctx); ok {
			principalForAWSCaller(s, c).apply(&event.AuditOrigin)
		} else if info := auditInfoFrom(ctx); info != nil {
			if p := info.getPrincipal(); p != nil {
				p.apply(&event.AuditOrigin)
			}
		}
	}
	if event.ActorType == store.AuditActorAccessKey && event.AccessKeyID != "" && event.Actor == event.AccessKeyID {
		// Bearer sessions know only the key; name its owner.
		if owner, _, _, _, err := s.store.GetAccessKeyByID(ctx, event.AccessKeyID); err == nil && owner != "" {
			event.Actor = owner
		}
	}
	if acct, ok := store.CallerAccountFromContext(ctx); ok {
		event.AccountID = acct
	} else if event.AccountID == "" {
		_, event.AccountID = s.store.DeploymentIdentity()
	}
	if event.Resource == "" {
		event.Resource = event.KeyID
	}
	return event
}

// withAuditContext installs the per-request audit state and enforces
// fail-closed: if a fail-closed audit write failed before the handler started
// its response, the response is replaced with a 500. When the request wrote
// a write-ahead attempt but no outcome, it records one from the status.
func (s *Server) withAuditContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info := &auditRequestInfo{}
		aw := &auditFailWriter{ResponseWriter: w, info: info, native: strings.HasPrefix(r.URL.Path, "/v1/")}
		ctx := context.WithValue(r.Context(), auditInfoCtxKey{}, info)
		next.ServeHTTP(aw, r.WithContext(ctx))
		if a, ok := info.attemptState(); ok && a.outcomes == 0 {
			result, errType := outcomeForStatus(aw.status)
			s.finishAudit(ctx, result, errType)
		}
	})
}

type auditFailWriter struct {
	http.ResponseWriter
	info        *auditRequestInfo
	native      bool
	wroteHeader bool
	suppressed  bool
	status      int
}

func (w *auditFailWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = code
	if w.info.hasFailed() {
		w.suppressed = true
		w.status = http.StatusInternalServerError
		h := w.ResponseWriter.Header()
		for k := range h {
			delete(h, k)
		}
		if w.native {
			writeNativeError(w.ResponseWriter, http.StatusInternalServerError, "audit_unavailable", "the audit log could not be written; the request was not confirmed")
		} else {
			writeAWSJSONError(w.ResponseWriter, http.StatusInternalServerError, "InternalFailure", "the audit log could not be written")
		}
		return
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *auditFailWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.suppressed {
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

func (w *auditFailWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok && !w.suppressed {
		f.Flush()
	}
}

func (w *auditFailWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
