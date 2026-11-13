package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/jose"
	"github.com/worlddrknss/citadel/internal/ratelimit"
	"github.com/worlddrknss/citadel/internal/store"
)

// Agent authentication (2.2).
//
// An agent authenticates every request on its own; it never gets a console
// session and never uses IAM access keys. Two credentials are accepted, both
// as "Authorization: Bearer ...":
//
//   - An agent token "cagt_<agentId>_<secret>". The secret is 256 random
//     bits stored as a PBKDF2 hash; its first eight characters are kept in
//     clear as a lookup hint so a request costs one hash, not one per token.
//     Verified tokens are remembered (by SHA-256 of the token, together with
//     the stored hash) so repeat requests skip PBKDF2; the token row and the
//     agent are still read on every request, so revocation is immediate.
//   - A workload identity JWT (Citadel's own /oidc issuer, or an issuer
//     registered as an IAM OIDC provider in the agent's account) whose
//     issuer, subject and audience exactly match one of the agent's
//     bindings. X-Citadel-Agent-Id names the agent when the same identity is
//     bound to more than one.
//
// Then: the agent must be active and the account's kill switch off. Every
// refusal of an identified agent is audited (citadel.AgentAuth, denied, with
// the reason); malformed or unknown credentials are only counted against the
// client address.
//
// Handlers call s.agentRequest, which authenticates, applies the per-agent
// request limits, reads X-Citadel-Task-Id and installs the agent as the
// audit principal: every event recorded for the request carries agentId,
// owner and taskId.

// AgentPrincipal is an authenticated agent request.
type AgentPrincipal struct {
	Agent     store.Agent
	AccountID string
	// Method is "token" or "federation".
	Method string
	// TokenID and TokenExpiresAt identify the agent token used ("" for
	// federation).
	TokenID        string
	TokenExpiresAt *time.Time
	// BindingID is the federation binding that matched ("" for tokens).
	BindingID string
	// TaskID is the caller's task or session ID (X-Citadel-Task-Id), "" when
	// not sent.
	TaskID string
}

// Agent authentication methods.
const (
	agentAuthToken      = "token"
	agentAuthFederation = "federation"
)

// Denial reasons. They appear in audit events (ErrorType) and in the
// "reason" member of agent error responses.
const (
	agentReasonInvalidCredential = "invalid_credential"
	agentReasonTokenExpired      = "token_expired"
	agentReasonTokenRevoked      = "token_revoked"
	agentReasonAgentSuspended    = "agent_suspended"
	agentReasonAgentRevoked      = "agent_revoked"
	agentReasonAgentsSuspended   = "agents_suspended"
	agentReasonFederationNoMatch = "federation_no_match"
	agentReasonAmbiguous         = "federation_ambiguous"
	agentReasonRateLimited       = "rate_limited"
	agentReasonInvalidTaskID     = "invalid_task_id"
	// agentReasonFederationRequired: the agent requires workload identity
	// federation and presented an agent token (2.3).
	agentReasonFederationRequired = "federation_required"
)

// agentAuthError is a refused agent authentication. msg is safe to return;
// agent is set when the credential identified an agent (the refusal is then
// audited in its account).
type agentAuthError struct {
	status int
	code   string
	reason string
	msg    string
	agent  *store.Agent
	wait   time.Duration
}

func (e *agentAuthError) Error() string { return e.reason }

func agentUnauthorized(reason string, agent *store.Agent) *agentAuthError {
	return &agentAuthError{status: http.StatusUnauthorized, code: "unauthorized", reason: reason, msg: "invalid or inactive agent credential", agent: agent}
}

// AgentTaskHeader carries the agent's own task or session ID.
const AgentTaskHeader = "X-Citadel-Task-Id"

// AgentIDHeader names the agent for federated authentication.
const AgentIDHeader = "X-Citadel-Agent-Id"

const (
	agentTouchInterval  = time.Minute
	agentTokenCacheTTL  = 5 * time.Minute
	agentTokenCacheMax  = 10000
	maxAgentTaskIDLen   = 128
	maxAgentBearerLen   = 8192
	agentCacheSweepSize = 1000
)

// Per-agent request limits. The local bucket runs first; the shared counter
// holds the limit across replicas.
var sharedLimitAgentRequests = sharedLimit{"agent-requests", 1200, time.Minute} // bucket: 50 burst + 10/s

type agentRuntime struct {
	requests *ratelimit.Limiter
	failIP   *ratelimit.Backoff

	mu       sync.Mutex
	verified map[string]agentVerified // sha256(token) -> stored hash
	touched  map[string]time.Time     // agentID -> last TouchAgentUsed
	grants   map[string]*ratelimit.Limiter
}

type agentVerified struct {
	hash    string
	expires time.Time
}

var agentRuntimes sync.Map // *Server -> *agentRuntime

func (s *Server) agentRT() *agentRuntime {
	if v, ok := agentRuntimes.Load(s); ok {
		return v.(*agentRuntime)
	}
	rt := &agentRuntime{
		requests: ratelimit.New(100*time.Millisecond, 50),
		failIP:   ratelimit.NewBackoff(20, time.Second, 5*time.Minute, time.Hour),
		verified: map[string]agentVerified{},
		touched:  map[string]time.Time{},
		grants:   map[string]*ratelimit.Limiter{},
	}
	v, _ := agentRuntimes.LoadOrStore(s, rt)
	return v.(*agentRuntime)
}

func agentTokenDigest(tok string) string {
	sum := sha256.Sum256([]byte("citadel-agent-token\x00" + tok))
	return hex.EncodeToString(sum[:])
}

// verifyAgentTokenHash checks secret against the stored hash, using the
// cache of recently verified tokens.
func (rt *agentRuntime) verifyAgentTokenHash(token, secret, stored string, now time.Time) bool {
	key := agentTokenDigest(token)
	rt.mu.Lock()
	v, ok := rt.verified[key]
	rt.mu.Unlock()
	if ok && v.hash == stored && now.Before(v.expires) {
		return true
	}
	if !cryptoutil.VerifyPassword(stored, secret) {
		return false
	}
	rt.mu.Lock()
	if len(rt.verified) >= agentTokenCacheMax {
		n := 0
		for k := range rt.verified {
			delete(rt.verified, k)
			if n++; n >= agentCacheSweepSize {
				break
			}
		}
	}
	rt.verified[key] = agentVerified{hash: stored, expires: now.Add(agentTokenCacheTTL)}
	rt.mu.Unlock()
	return true
}

// bearerToken returns the request's bearer credential ("" when none).
func bearerToken(r *http.Request) string {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(auth) < 7 || !strings.EqualFold(auth[:7], "bearer ") {
		return ""
	}
	return strings.TrimSpace(auth[7:])
}

// authenticateAgent validates the request's agent token or federated token
// and returns the agent. Errors are *agentAuthError. It does not read
// X-Citadel-Task-Id or apply request limits (agentRequest does).
func (s *Server) authenticateAgent(r *http.Request) (*AgentPrincipal, error) {
	tok := bearerToken(r)
	if tok == "" || len(tok) > maxAgentBearerLen {
		return nil, agentUnauthorized(agentReasonInvalidCredential, nil)
	}
	ctx := r.Context()
	now := time.Now().UTC()
	var p *AgentPrincipal
	if strings.HasPrefix(tok, store.AgentTokenPrefix) {
		var err error
		if p, err = s.authenticateAgentToken(ctx, tok, now); err != nil {
			return nil, err
		}
	} else {
		var err error
		if p, err = s.authenticateFederatedAgent(ctx, tok, strings.TrimSpace(r.Header.Get(AgentIDHeader)), now); err != nil {
			return nil, err
		}
	}
	if err := s.agentActive(ctx, &p.Agent); err != nil {
		return nil, err
	}
	s.touchAgent(ctx, p, now)
	return p, nil
}

func (s *Server) authenticateAgentToken(ctx context.Context, tok string, now time.Time) (*AgentPrincipal, error) {
	agentID, secret, ok := store.ParseAgentToken(tok)
	if !ok {
		return nil, agentUnauthorized(agentReasonInvalidCredential, nil)
	}
	agent, err := s.store.LookupAgent(ctx, agentID)
	if err != nil {
		if !errors.Is(err, store.ErrAgentNotFound) {
			log.Printf("agent auth: lookup failed: %v", err)
			return nil, &agentAuthError{status: http.StatusInternalServerError, code: "internal_error", reason: "lookup_failed", msg: "could not authenticate the agent"}
		}
		return nil, agentUnauthorized(agentReasonInvalidCredential, nil)
	}
	tokens, err := s.store.FindAgentTokens(ctx, agentID, secret[:store.AgentTokenHintLen])
	if err != nil {
		log.Printf("agent auth: token lookup failed: %v", err)
		return nil, &agentAuthError{status: http.StatusInternalServerError, code: "internal_error", reason: "lookup_failed", msg: "could not authenticate the agent"}
	}
	rt := s.agentRT()
	for _, t := range tokens {
		if t.AccountID != agent.AccountID || !rt.verifyAgentTokenHash(tok, secret, t.Hash, now) {
			continue
		}
		switch {
		case t.RevokedAt != nil:
			return nil, agentUnauthorized(agentReasonTokenRevoked, &agent)
		case t.ExpiresAt != nil && !now.Before(*t.ExpiresAt):
			return nil, agentUnauthorized(agentReasonTokenExpired, &agent)
		case agent.RequireFederation:
			return nil, &agentAuthError{status: http.StatusForbidden, code: "forbidden", reason: agentReasonFederationRequired,
				msg: "this agent must authenticate with workload identity federation", agent: &agent}
		}
		return &AgentPrincipal{Agent: agent, AccountID: agent.AccountID, Method: agentAuthToken, TokenID: t.TokenID, TokenExpiresAt: t.ExpiresAt}, nil
	}
	return nil, agentUnauthorized(agentReasonInvalidCredential, nil)
}

// agentActive refuses suspended and revoked agents and agents in an account
// whose kill switch is on.
func (s *Server) agentActive(ctx context.Context, a *store.Agent) error {
	switch a.Status {
	case store.AgentStatusActive:
	case store.AgentStatusSuspended:
		return &agentAuthError{status: http.StatusForbidden, code: "agent_suspended", reason: agentReasonAgentSuspended, msg: "this agent is suspended", agent: a}
	default:
		return agentUnauthorized(agentReasonAgentRevoked, a)
	}
	settings, err := s.store.GetAgentSettings(ctx, a.AccountID)
	if err != nil {
		log.Printf("agent auth: settings read failed: %v", err)
		return &agentAuthError{status: http.StatusInternalServerError, code: "internal_error", reason: "lookup_failed", msg: "could not authenticate the agent", agent: a}
	}
	if settings.AgentsSuspended {
		return &agentAuthError{status: http.StatusForbidden, code: "agent_suspended", reason: agentReasonAgentsSuspended, msg: "all agents in this account are suspended", agent: a}
	}
	return nil
}

// touchAgent records the use, at most once a minute per agent and replica.
func (s *Server) touchAgent(ctx context.Context, p *AgentPrincipal, now time.Time) {
	rt := s.agentRT()
	rt.mu.Lock()
	last, seen := rt.touched[p.Agent.AgentID]
	due := !seen || now.Sub(last) >= agentTouchInterval
	if due {
		if len(rt.touched) >= agentTokenCacheMax {
			rt.touched = map[string]time.Time{}
		}
		rt.touched[p.Agent.AgentID] = now
	}
	rt.mu.Unlock()
	if !due {
		return
	}
	if err := s.store.TouchAgentUsed(context.WithoutCancel(ctx), p.AccountID, p.Agent.AgentID, p.TokenID, now); err != nil {
		log.Printf("agent auth: record last use failed: %v", err)
	}
	p.Agent.LastUsedAt = &now
}

// ---- federation -------------------------------------------------------------

// federatedClaims are a verified workload identity token's claims.
type federatedClaims struct {
	issuer    string
	subject   string
	audiences []string
	// account is the citadel.account claim of a token from Citadel's own
	// issuer ("" for external issuers).
	account string
}

func (s *Server) authenticateFederatedAgent(ctx context.Context, tok, wantAgent string, now time.Time) (*AgentPrincipal, error) {
	jws, err := jose.ParseCompact(tok)
	if err != nil {
		return nil, agentUnauthorized(agentReasonInvalidCredential, nil)
	}
	claims, err := jose.ParseClaims(jws.Payload)
	if err != nil {
		return nil, agentUnauthorized(agentReasonInvalidCredential, nil)
	}
	iss, _ := claims.String("iss")
	sub, _ := claims.String("sub")
	iss = store.NormalizeIssuerURL(iss)
	if iss == "" || sub == "" {
		return nil, agentUnauthorized(agentReasonInvalidCredential, nil)
	}
	if wantAgent != "" && !store.IsAgentID(wantAgent) {
		return nil, agentUnauthorized(agentReasonInvalidCredential, nil)
	}
	// Candidate bindings come from the unverified issuer and subject; they
	// only choose which issuer's keys to verify the token with.
	bindings, err := s.store.FindAgentBindings(ctx, iss, sub)
	if err != nil {
		log.Printf("agent auth: binding lookup failed: %v", err)
		return nil, &agentAuthError{status: http.StatusInternalServerError, code: "internal_error", reason: "lookup_failed", msg: "could not authenticate the agent"}
	}
	var candidates []store.AgentBinding
	for _, b := range bindings {
		if wantAgent == "" || b.AgentID == wantAgent {
			candidates = append(candidates, b)
		}
	}
	if len(candidates) == 0 {
		return nil, agentUnauthorized(agentReasonInvalidCredential, nil)
	}

	// Verify once per account (external issuers must be registered as an
	// IAM OIDC provider in the binding's account) and keep the bindings
	// whose audience the token carries.
	verified := map[string]*federatedClaims{}
	var matches []store.AgentBinding
	for _, b := range candidates {
		c, seen := verified[b.AccountID]
		if !seen {
			c = s.verifyFederatedToken(ctx, tok, iss, b.AccountID, now)
			verified[b.AccountID] = c
		}
		if c == nil || c.subject != b.Subject {
			continue
		}
		if c.account != "" && c.account != b.AccountID {
			continue
		}
		for _, a := range c.audiences {
			if a == b.Audience {
				matches = append(matches, b)
				break
			}
		}
	}
	agents := map[string]store.AgentBinding{}
	for _, m := range matches {
		if _, dup := agents[m.AgentID]; !dup {
			agents[m.AgentID] = m
		}
	}
	switch len(agents) {
	case 0:
		return nil, agentUnauthorized(agentReasonFederationNoMatch, nil)
	case 1:
	default:
		return nil, &agentAuthError{status: http.StatusUnauthorized, code: "unauthorized", reason: agentReasonAmbiguous,
			msg: "this identity is bound to more than one agent; name the agent in " + AgentIDHeader}
	}
	var b store.AgentBinding
	for _, m := range agents {
		b = m
	}
	agent, err := s.store.GetAgent(ctx, b.AccountID, b.AgentID)
	if err != nil {
		return nil, agentUnauthorized(agentReasonInvalidCredential, nil)
	}
	return &AgentPrincipal{Agent: agent, AccountID: agent.AccountID, Method: agentAuthFederation, BindingID: b.BindingID}, nil
}

// verifyFederatedToken verifies tok for a binding in accountID; nil when it
// does not verify.
func (s *Server) verifyFederatedToken(ctx context.Context, tok, iss, accountID string, now time.Time) *federatedClaims {
	if own := store.NormalizeIssuerURL(s.workloadIssuerURL()); own != "" && iss == own {
		issuer, err := s.workloadIssuer()
		if err != nil {
			return nil
		}
		keys, err := issuer.JWKS(ctx)
		if err != nil {
			return nil
		}
		jws, err := jose.Verify(ctx, tok, keys)
		if err != nil {
			return nil
		}
		claims, err := jose.ParseClaims(jws.Payload)
		if err != nil || (jose.Validator{Issuer: s.workloadIssuerURL(), Leeway: time.Minute, Now: func() time.Time { return now }}).Validate(claims) != nil {
			return nil
		}
		sub, _ := claims.String("sub")
		aud, _ := claims.Audience()
		out := &federatedClaims{issuer: iss, subject: sub, audiences: aud}
		if ns, ok := claims[workloadClaimsNSpace].(map[string]any); ok {
			out.account, _ = ns["account"].(string)
		}
		if out.account == "" {
			return nil // Citadel tokens always name their account
		}
		return out
	}
	// Fetch keys only from the provider URL registered in the account, never
	// from the token's own (still unverified) issuer claim.
	provider, err := s.store.GetOIDCProviderByURL(ctx, accountID, iss)
	if err != nil {
		return nil
	}
	c, err := verifyWebIdentityToken(ctx, s.oidcHTTPClient(), tok, store.NormalizeIssuerURL(provider.URL))
	if err != nil {
		return nil
	}
	return &federatedClaims{issuer: c.Issuer, subject: c.Subject, audiences: c.Audiences}
}

// ---- request middleware -----------------------------------------------------

// agentErrorBody is an agent API error: the native error shape plus the
// denial reason.
type agentErrorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Reason  string `json:"reason,omitempty"`
}

func writeAgentError(w http.ResponseWriter, status int, code, reason, msg string) {
	writeNativeJSON(w, status, agentErrorBody{Error: code, Message: msg, Reason: reason})
}

// validAgentTaskID reports whether a task ID is safe to record.
func validAgentTaskID(v string) bool {
	if v == "" || len(v) > maxAgentTaskIDLen {
		return false
	}
	for _, c := range v {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-_.:/@#+=", c)
		if !ok {
			return false
		}
	}
	return true
}

// agentPrincipalForAudit describes the agent as the audit principal.
func agentPrincipalForAudit(p *AgentPrincipal) *auditPrincipal {
	keyID := p.TokenID
	if p.Method == agentAuthFederation {
		keyID = p.BindingID
	}
	return &auditPrincipal{
		actor: p.Agent.AgentID, actorType: store.AuditActorAgent, displayName: p.Agent.Name, accessKeyID: keyID,
		accountID: p.AccountID, agentID: p.Agent.AgentID, agentOwner: p.Agent.Owner, taskID: p.TaskID,
	}
}

// agentAuditOrigin is the audit origin of an agent request.
func (s *Server) agentAuditOrigin(r *http.Request, p *AgentPrincipal) store.AuditOrigin {
	o := store.AuditOrigin{SourceIP: s.clientIP(r), UserAgent: r.UserAgent()}
	agentPrincipalForAudit(p).apply(&o)
	o.AccountID = p.AccountID
	return o
}

// agentRequest authenticates an agent request for action and prepares it:
// request limits, the task ID, the audit principal and, for state-changing
// methods, the write-ahead audit attempt. On failure it writes the response
// (and audits refusals of identified agents) and returns ok=false.
func (s *Server) agentRequest(w http.ResponseWriter, r *http.Request, action string) (*AgentPrincipal, context.Context, bool) {
	ip := s.clientIP(r)
	rt := s.agentRT()
	if blocked, wait := rt.failIP.Blocked(ip); blocked {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeAgentError(w, http.StatusTooManyRequests, "rate_limited", agentReasonRateLimited, "too many failed attempts; try again later")
		return nil, nil, false
	}
	p, err := s.authenticateAgent(r)
	if err != nil {
		var ae *agentAuthError
		if !errors.As(err, &ae) {
			ae = &agentAuthError{status: http.StatusInternalServerError, code: "internal_error", reason: "internal", msg: "could not authenticate the agent"}
		}
		if ae.status == http.StatusUnauthorized {
			rt.failIP.Fail(ip)
		}
		if ae.agent != nil {
			s.auditAgentRefusal(r, &AgentPrincipal{Agent: *ae.agent, AccountID: ae.agent.AccountID}, ae.reason)
		}
		writeAgentError(w, ae.status, ae.code, ae.reason, ae.msg)
		return nil, nil, false
	}
	rt.failIP.Reset(ip)
	if raw := strings.TrimSpace(r.Header.Get(AgentTaskHeader)); raw != "" {
		if !validAgentTaskID(raw) {
			s.auditAgentRefusal(r, p, agentReasonInvalidTaskID)
			writeAgentError(w, http.StatusBadRequest, "invalid_request", agentReasonInvalidTaskID, AgentTaskHeader+" must be 1-128 letters, digits or -_.:/@#+=")
			return nil, nil, false
		}
		p.TaskID = raw
	}
	ctx := store.WithCallerAccount(r.Context(), p.AccountID)
	if ok, wait := rt.requests.Reserve(p.Agent.AgentID); !ok {
		writeAgentThrottled(w, wait)
		return nil, nil, false
	}
	if ok, wait := s.sharedAllow(ctx, sharedLimitCheck{sharedLimitAgentRequests, p.Agent.AgentID}); !ok {
		writeAgentThrottled(w, wait)
		return nil, nil, false
	}
	ap := agentPrincipalForAudit(p)
	if info := auditInfoFrom(r.Context()); info != nil {
		info.setPrincipal(ap)
	}
	ctx = context.WithValue(ctx, auditPrincipalCtxKey{}, ap)
	ctx = withAgentPrincipal(ctx, p)
	if nativeWriteAhead(r) {
		if err := s.beginAuditAttempt(ctx, store.AuditEvent{Action: action, AuditOrigin: s.agentAuditOrigin(r, p)}); err != nil {
			writeAgentError(w, http.StatusInternalServerError, "audit_unavailable", "", "the audit log could not be written; nothing was done")
			return nil, nil, false
		}
	}
	return p, ctx, true
}

func writeAgentThrottled(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
	writeAgentError(w, http.StatusTooManyRequests, "rate_limited", agentReasonRateLimited, "too many requests; slow down")
}

// auditAgentRefusal records a refused request of an identified agent.
func (s *Server) auditAgentRefusal(r *http.Request, p *AgentPrincipal, reason string) {
	ctx := store.WithCallerAccount(r.Context(), p.AccountID)
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.AgentAuth", KeyID: p.Agent.AgentID, Result: "denied", ErrorType: reason, AuditOrigin: s.agentAuditOrigin(r, p)})
}

type agentPrincipalCtxKey struct{}

func withAgentPrincipal(ctx context.Context, p *AgentPrincipal) context.Context {
	return context.WithValue(ctx, agentPrincipalCtxKey{}, p)
}

// agentPrincipalFrom returns the agent agentRequest installed on ctx.
func agentPrincipalFrom(ctx context.Context) (*AgentPrincipal, bool) {
	p, ok := ctx.Value(agentPrincipalCtxKey{}).(*AgentPrincipal)
	return p, ok
}
