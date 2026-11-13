package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// Agent access requests and leases API (2.3). See agent_access.go.
//
// Agent-facing (agent token or federated token):
//
//	POST /v1/agent/access-requests        ask for access
//	GET  /v1/agent/access-requests/{id}   poll a request
//	GET  /v1/agent/leases                 the caller's active leases
//
// Console (viewer reads; deciding needs a console session of the agent's
// owner or an account admin; revoking a lease, the owner or an admin):
//
//	GET  /v1/agents/access-requests
//	POST /v1/agents/access-requests/approve
//	POST /v1/agents/access-requests/deny
//	GET  /v1/agents/leases
//	POST /v1/agents/leases/revoke

func (s *Server) registerAgentAccessRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/agent/access-requests", s.handleV1AgentRequestAccess)
	mux.HandleFunc("GET /v1/agent/access-requests/{id}", s.handleV1AgentGetAccessRequest)
	mux.HandleFunc("GET /v1/agent/leases", s.handleV1AgentListLeases)

	mux.HandleFunc("GET /v1/agents/access-requests", s.handleV1ListAgentAccessRequests)
	mux.HandleFunc("POST /v1/agents/access-requests/approve", s.handleV1ApproveAgentAccess)
	mux.HandleFunc("POST /v1/agents/access-requests/deny", s.handleV1DenyAgentAccess)
	mux.HandleFunc("GET /v1/agents/leases", s.handleV1ListAgentLeases)
	mux.HandleFunc("POST /v1/agents/leases/revoke", s.handleV1RevokeAgentLease)
}

// ---- JSON models ------------------------------------------------------------

type agentLeaseJSON struct {
	LeaseID    string   `json:"leaseId"`
	AgentID    string   `json:"agentId"`
	AgentName  string   `json:"agentName,omitempty"`
	Credential string   `json:"credential"`
	Actions    []string `json:"actions"`
	Scope      string   `json:"scope"`
	TaskID     string   `json:"taskId,omitempty"`
	// UsesLeft is null for unlimited uses until expiry.
	UsesLeft  *int   `json:"usesLeft"`
	UseCount  int    `json:"useCount"`
	ExpiresAt string `json:"expiresAt"`
	CreatedAt string `json:"createdAt"`
	CreatedBy string `json:"createdBy"`
	RequestID string `json:"requestId,omitempty"`
	// Status is active, expired, used (a single-use lease that was used)
	// or ended (revoked, or ended by a suspension or the kill switch).
	Status      string `json:"status"`
	LastUsedAt  string `json:"lastUsedAt,omitempty"`
	EndedAt     string `json:"endedAt,omitempty"`
	EndedBy     string `json:"endedBy,omitempty"`
	EndedReason string `json:"endedReason,omitempty"`
	CanRevoke   bool   `json:"canRevoke,omitempty"`
}

func agentLeaseStatus(l store.AgentLease, now time.Time) string {
	switch {
	case l.EndedAt != nil:
		return "ended"
	case l.UsesLeft != nil && *l.UsesLeft <= 0:
		return "used"
	case !now.Before(l.ExpiresAt):
		return "expired"
	}
	return "active"
}

func agentLeaseOut(l store.AgentLease, now time.Time) agentLeaseJSON {
	actions := l.Actions
	if actions == nil {
		actions = []string{}
	}
	return agentLeaseJSON{
		LeaseID: l.LeaseID, AgentID: l.AgentID, Credential: l.Credential, Actions: actions, Scope: l.Scope, TaskID: l.TaskID,
		UsesLeft: l.UsesLeft, UseCount: l.UseCount, ExpiresAt: fmtTime(l.ExpiresAt), CreatedAt: fmtTime(l.CreatedAt), CreatedBy: l.CreatedBy,
		RequestID: l.RequestID, Status: agentLeaseStatus(l, now), LastUsedAt: fmtTimePtr(l.LastUsedAt), EndedAt: fmtTimePtr(l.EndedAt),
		EndedBy: l.EndedBy, EndedReason: l.EndedReason,
	}
}

// agentAccessRequestJSON is a request as the agent sees it.
type agentAccessRequestJSON struct {
	RequestID       string   `json:"requestId"`
	Credential      string   `json:"credential"`
	Actions         []string `json:"actions"`
	Reason          string   `json:"reason,omitempty"`
	TaskID          string   `json:"taskId,omitempty"`
	DurationSeconds int      `json:"durationSeconds,omitempty"`
	Origin          string   `json:"origin"`
	// Status is pending, approved, denied, expired or cancelled.
	Status    string `json:"status"`
	CreatedAt string `json:"createdAt"`
	ExpiresAt string `json:"expiresAt"`
	DecidedAt string `json:"decidedAt,omitempty"`
	DecidedBy string `json:"decidedBy,omitempty"`
	// DecisionComment is the approver's comment or the reason for a denial.
	DecisionComment string `json:"decisionComment,omitempty"`
	Scope           string `json:"scope,omitempty"`
	// Lease is the lease an approval created (its current state).
	Lease *agentLeaseJSON `json:"lease,omitempty"`
}

func agentAccessRequestOut(r store.AgentAccessRequest, now time.Time) agentAccessRequestJSON {
	return agentAccessRequestJSON{
		RequestID: r.RequestID, Credential: r.Credential, Actions: r.Actions, Reason: r.Reason, TaskID: r.TaskID, DurationSeconds: r.DurationSeconds,
		Origin: r.Origin, Status: r.EffectiveStatus(now), CreatedAt: fmtTime(r.CreatedAt), ExpiresAt: fmtTime(r.ExpiresAt),
		DecidedAt: fmtTimePtr(r.DecidedAt), DecidedBy: r.DecidedBy, DecisionComment: r.DecisionComment, Scope: r.Scope,
	}
}

// agentAccessRequestConsoleJSON adds what an approver needs.
type agentAccessRequestConsoleJSON struct {
	agentAccessRequestJSON
	AgentID     string `json:"agentId"`
	AgentName   string `json:"agentName"`
	AgentOwner  string `json:"agentOwner"`
	AgentStatus string `json:"agentStatus"`
	LeaseID     string `json:"leaseId,omitempty"`
	// CredentialKind is "" when no credential has the requested name.
	CredentialKind string `json:"credentialKind,omitempty"`
	// Grant describes the agent's grant for the credential (null when it
	// has none: approving then gives access the agent was never granted).
	Grant *agentAccessGrantJSON `json:"grant"`
	// MaxDurationSeconds is the longest lease an approval may give.
	MaxDurationSeconds int `json:"maxDurationSeconds"`
	// CanDecide reports whether the caller may approve or deny; when not,
	// CannotDecideReason says why.
	CanDecide          bool   `json:"canDecide"`
	CannotDecideReason string `json:"cannotDecideReason,omitempty"`
	// MFARequired: approving needs a current MFA code from this caller.
	MFARequired bool `json:"mfaRequired,omitempty"`
}

type agentAccessGrantJSON struct {
	Actions          []string `json:"actions"`
	RequiresApproval bool     `json:"requiresApproval"`
	LeaseTTLSeconds  int      `json:"leaseTtlSeconds,omitempty"`
	NotAfter         string   `json:"notAfter,omitempty"`
}

// ---- agent-facing -----------------------------------------------------------

type agentAccessRequestInput struct {
	Credential string   `json:"credential"`
	Actions    []string `json:"actions"`
	Reason     string   `json:"reason"`
	// Duration is a Go duration ("15m", "2h"); DurationSeconds the same in
	// seconds. Either may be sent (60 seconds to 24 hours).
	Duration        string `json:"duration"`
	DurationSeconds int    `json:"durationSeconds"`
	TaskID          string `json:"taskId"`
}

// validateAgentAccessInput checks an access request; "" when valid.
func validateAgentAccessInput(in *agentAccessRequestInput, headerTask string) string {
	in.Credential = strings.TrimSpace(in.Credential)
	if !agentCredNameRe.MatchString(in.Credential) {
		return "credential must be a credential name"
	}
	if len(in.Actions) == 0 {
		in.Actions = []string{store.AgentActionUse}
	}
	for _, a := range in.Actions {
		switch a {
		case store.AgentActionUse, store.AgentActionReveal, store.AgentActionTOTP:
		default:
			return "actions must be use, reveal or totp"
		}
	}
	in.Actions = strings.Split(store.AgentActionsKey(in.Actions), ",")
	in.Reason = strings.TrimSpace(in.Reason)
	if in.Reason == "" || !printable(in.Reason, maxAgentRequestReason) {
		return "reason is required: at most 512 printable characters saying why the access is needed"
	}
	if d := strings.TrimSpace(in.Duration); d != "" {
		v, err := time.ParseDuration(d)
		if err != nil {
			return "duration must be a duration such as 15m or 2h"
		}
		if in.DurationSeconds != 0 && in.DurationSeconds != int(v/time.Second) {
			return "send duration or durationSeconds, not both"
		}
		in.DurationSeconds = int(v / time.Second)
	}
	if in.DurationSeconds != 0 && (in.DurationSeconds < minAgentLeaseSeconds || in.DurationSeconds > maxAgentLeaseSeconds) {
		return "duration must be between 1 minute and 24 hours"
	}
	in.TaskID = strings.TrimSpace(in.TaskID)
	if in.TaskID == "" {
		in.TaskID = headerTask
	}
	if in.TaskID != "" && !validAgentTaskID(in.TaskID) {
		return "taskId must be 1-128 letters, digits or -_.:/@#+="
	}
	return ""
}

func (s *Server) handleV1AgentRequestAccess(w http.ResponseWriter, r *http.Request) {
	p, ctx, ok := s.agentRequest(w, r, auditAgentRequestAccess)
	if !ok {
		return
	}
	var in agentAccessRequestInput
	if err := decodeJSONBody(r, &in); err != nil {
		writeAgentError(w, http.StatusBadRequest, "invalid_request", "", "invalid JSON body")
		return
	}
	if msg := validateAgentAccessInput(&in, p.TaskID); msg != "" {
		writeAgentError(w, http.StatusBadRequest, "invalid_request", "", msg)
		return
	}
	now := time.Now().UTC().Truncate(time.Second)
	req, created, err := s.openAgentAccessRequest(ctx, p.Agent, store.AgentAccessRequest{
		Credential: in.Credential, Actions: in.Actions, Reason: in.Reason, TaskID: in.TaskID, DurationSeconds: in.DurationSeconds,
		Origin: store.AgentRequestOriginAgent,
	}, now)
	if errors.Is(err, errTooManyAgentRequests) {
		s.recordAudit(ctx, store.AuditEvent{Action: auditAgentRequestAccess, KeyID: p.Agent.AgentID, Result: "denied", ErrorType: "too_many_requests", AuditOrigin: s.agentAuditOrigin(r, p)})
		writeAgentError(w, http.StatusTooManyRequests, "too_many_requests", "too_many_requests", "this agent has too many pending access requests; wait for a decision")
		return
	}
	if err != nil {
		log.Printf("agent access: open request failed: %v", err)
		writeAgentError(w, http.StatusInternalServerError, "request_failed", "", "could not record the access request")
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	} else {
		// A reused request: nothing changed, but record that the agent asked.
		s.recordAudit(ctx, store.AuditEvent{Action: "citadel.AgentRequestAccess", KeyID: req.RequestID, Result: "ok", AuditOrigin: s.agentAuditOrigin(r, p)})
	}
	writeNativeJSON(w, status, s.agentRequestWithLease(r, p, req, now))
}

// agentRequestWithLease is the agent's view of req with its lease.
func (s *Server) agentRequestWithLease(r *http.Request, p *AgentPrincipal, req store.AgentAccessRequest, now time.Time) agentAccessRequestJSON {
	out := agentAccessRequestOut(req, now)
	if req.LeaseID != "" {
		if l, err := s.store.GetAgentLease(r.Context(), p.AccountID, req.LeaseID); err == nil {
			lj := agentLeaseOut(l, now)
			out.Lease = &lj
		}
	}
	return out
}

func (s *Server) handleV1AgentGetAccessRequest(w http.ResponseWriter, r *http.Request) {
	p, ctx, ok := s.agentRequest(w, r, auditAgentGetAccessRequest)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !store.IsAgentObjectID(id, "aar_") {
		writeAgentError(w, http.StatusBadRequest, "invalid_request", "", "the request ID is malformed")
		return
	}
	req, err := s.store.GetAgentAccessRequest(ctx, p.AccountID, id)
	if err == nil && req.AgentID != p.Agent.AgentID {
		err = store.ErrAgentAccessRequestNotFound // another agent's request
	}
	if errors.Is(err, store.ErrAgentAccessRequestNotFound) {
		writeAgentError(w, http.StatusNotFound, "not_found", "", "access request not found")
		return
	}
	if err != nil {
		log.Printf("agent access: read request failed: %v", err)
		writeAgentError(w, http.StatusInternalServerError, "internal_error", "", "could not read the access request")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.AgentGetAccessRequest", KeyID: req.RequestID, Result: "ok", AuditOrigin: s.agentAuditOrigin(r, p)})
	writeNativeJSON(w, http.StatusOK, s.agentRequestWithLease(r, p, req, time.Now().UTC()))
}

func (s *Server) handleV1AgentListLeases(w http.ResponseWriter, r *http.Request) {
	p, ctx, ok := s.agentRequest(w, r, auditAgentListLeases)
	if !ok {
		return
	}
	cred := strings.TrimSpace(r.URL.Query().Get("credential"))
	if cred != "" && !agentCredNameRe.MatchString(cred) {
		writeAgentError(w, http.StatusBadRequest, "invalid_request", "", "credential must be a credential name")
		return
	}
	now := time.Now().UTC()
	leases, err := s.store.ListAgentLeases(ctx, p.AccountID, p.Agent.AgentID, true, now)
	if err != nil {
		log.Printf("agent access: list leases failed: %v", err)
		writeAgentError(w, http.StatusInternalServerError, "list_failed", "", "could not list leases")
		return
	}
	out := make([]agentLeaseJSON, 0, len(leases))
	for _, l := range leases {
		if cred == "" || l.Credential == cred {
			out = append(out, agentLeaseOut(l, now))
		}
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.AgentListLeases", KeyID: p.Agent.AgentID, Result: "ok", AuditOrigin: s.agentAuditOrigin(r, p)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"leases": out})
}

// ---- console ----------------------------------------------------------------

// agentDecisionBlocker explains why sess may not decide requests of agent
// a, or "" when it may. Deciding is a human control: a console session of
// the agent's owner (an editor) or an account admin, never an access key
// (and never the agent, whose credentials never open a session).
func agentDecisionBlocker(sess *uiSession, a store.Agent) string {
	switch {
	case sess == nil:
		return "Sign in to decide."
	case sess.ViaToken:
		return "Agent access must be approved by a person signed in to the console, not with an access key."
	case !canManageAgent(sess, a):
		return "Only the agent's owner or an account admin can decide its access requests."
	}
	return ""
}

// approvalNeedsMFA reports whether approving needs a fresh MFA code from
// sess: the organization requires MFA and the session is a password sign-in
// (SSO sign-ins are exempt, as they are from requireMFA itself).
func (s *Server) approvalNeedsMFA(r *http.Request, sess *uiSession) bool {
	return s.orgSettings(r.Context()).RequireMFA && sess.Method != store.SessionMethodSSO
}

// agentLeaseCap is the longest lease an approval of req may give, and the
// grant (if any) that caps it.
func agentLeaseCap(grant *store.AgentGrant, now time.Time) int {
	limit := maxAgentLeaseSeconds
	if grant != nil {
		if grant.LeaseTTLSeconds != nil && *grant.LeaseTTLSeconds > 0 && *grant.LeaseTTLSeconds < limit {
			limit = *grant.LeaseTTLSeconds
		}
		if grant.NotAfter != nil {
			if left := int(grant.NotAfter.Sub(now) / time.Second); left < limit {
				limit = max(left, 0)
			}
		}
	}
	return limit
}

func findGrant(grants []store.AgentGrant, agentID, credential string) *store.AgentGrant {
	for i := range grants {
		if grants[i].AgentID == agentID && grants[i].Credential == credential {
			return &grants[i]
		}
	}
	return nil
}

func (s *Server) handleV1ListAgentAccessRequests(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	q := r.URL.Query()
	agentID := strings.TrimSpace(q.Get("agentId"))
	if agentID != "" && !store.IsAgentID(agentID) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "agentId is malformed")
		return
	}
	status := strings.TrimSpace(q.Get("status"))
	if status != "" && status != "pending" && status != "all" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "status must be pending or all")
		return
	}
	acct := s.agentAccount(ctx, sess)
	now := time.Now().UTC()
	reqs, err := s.store.ListAgentAccessRequests(ctx, acct, store.AgentAccessRequestFilter{AgentID: agentID, Pending: status == "pending", Now: now})
	var (
		agents []store.Agent
		grants []store.AgentGrant
		creds  []store.AgentCredential
	)
	if err == nil {
		agents, err = s.store.ListAgents(ctx, acct)
	}
	if err == nil {
		grants, err = s.store.ListAgentGrants(ctx, acct, "")
	}
	if err == nil {
		creds, err = s.store.ListAgentCredentials(ctx, acct)
	}
	if err != nil {
		log.Printf("agent access: list requests failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "internal_error", "could not list access requests")
		return
	}
	byID := map[string]store.Agent{}
	for _, a := range agents {
		byID[a.AgentID] = a
	}
	kinds := map[string]string{}
	for _, c := range creds {
		kinds[c.Name] = c.Kind
	}
	needMFA := s.approvalNeedsMFA(r, sess)
	out := make([]agentAccessRequestConsoleJSON, 0, len(reqs))
	for _, req := range reqs {
		a := byID[req.AgentID]
		out = append(out, s.agentAccessRequestConsoleOut(sess, req, a, findGrant(grants, req.AgentID, req.Credential), kinds[req.Credential], needMFA, now))
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"requests": out})
}

func (s *Server) agentAccessRequestConsoleOut(sess *uiSession, req store.AgentAccessRequest, a store.Agent, grant *store.AgentGrant, kind string, needMFA bool, now time.Time) agentAccessRequestConsoleJSON {
	j := agentAccessRequestConsoleJSON{
		agentAccessRequestJSON: agentAccessRequestOut(req, now), AgentID: req.AgentID, AgentName: a.Name, AgentOwner: a.Owner,
		AgentStatus: a.Status, LeaseID: req.LeaseID, CredentialKind: kind, MaxDurationSeconds: agentLeaseCap(grant, now),
	}
	if grant != nil {
		j.Grant = &agentAccessGrantJSON{Actions: grant.Actions, RequiresApproval: grant.RequiresApproval != nil && *grant.RequiresApproval, NotAfter: fmtTimePtr(grant.NotAfter)}
		if grant.LeaseTTLSeconds != nil {
			j.Grant.LeaseTTLSeconds = *grant.LeaseTTLSeconds
		}
	}
	if j.Status == store.AgentRequestPending {
		j.CannotDecideReason = agentDecisionBlocker(sess, a)
		j.CanDecide = j.CannotDecideReason == ""
		j.MFARequired = j.CanDecide && needMFA
	}
	return j
}

type agentDecisionInput struct {
	RequestID string `json:"requestId"`
	// Scope is once, duration or task (approve).
	Scope string `json:"scope"`
	// DurationSeconds is how long the lease lasts (approve; default the
	// requested duration or 1 hour, capped).
	DurationSeconds int `json:"durationSeconds"`
	// Comment is the approver's note (approve) or the reason (deny,
	// required).
	Comment string `json:"comment"`
	// MFACode or RecoveryCode confirm an approval when the organization
	// requires MFA.
	MFACode      string `json:"mfaCode"`
	RecoveryCode string `json:"recoveryCode"`
}

// loadDecidableRequest loads a pending request and its agent and checks the
// caller may decide it, writing the error response otherwise.
func (s *Server) loadDecidableRequest(w http.ResponseWriter, r *http.Request, sess *uiSession, in agentDecisionInput, action string) (store.AgentAccessRequest, store.Agent, bool) {
	ctx := r.Context()
	acct := s.agentAccount(ctx, sess)
	if !store.IsAgentObjectID(in.RequestID, "aar_") {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "requestId is required")
		return store.AgentAccessRequest{}, store.Agent{}, false
	}
	req, err := s.store.GetAgentAccessRequest(ctx, acct, in.RequestID)
	if errors.Is(err, store.ErrAgentAccessRequestNotFound) {
		writeNativeError(w, http.StatusNotFound, "not_found", "access request not found")
		return store.AgentAccessRequest{}, store.Agent{}, false
	}
	var a store.Agent
	if err == nil {
		a, err = s.store.GetAgent(ctx, acct, req.AgentID)
	}
	if err != nil {
		log.Printf("agent access: load request failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "internal_error", "could not load the access request")
		return store.AgentAccessRequest{}, store.Agent{}, false
	}
	o := s.agentOrigin(r, a)
	o.Resource = req.RequestID
	if blocker := agentDecisionBlocker(sess, a); blocker != "" {
		s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: req.RequestID, Result: "denied", ErrorType: "AccessDenied", AuditOrigin: o})
		writeNativeError(w, http.StatusForbidden, "forbidden", blocker)
		return store.AgentAccessRequest{}, store.Agent{}, false
	}
	if st := req.EffectiveStatus(time.Now().UTC()); st != store.AgentRequestPending {
		writeNativeError(w, http.StatusConflict, "already_decided", "this request is "+st)
		return store.AgentAccessRequest{}, store.Agent{}, false
	}
	return req, a, true
}

// checkApprovalMFA verifies the approver's step-up code when required. It
// writes the error response and returns false on failure.
func (s *Server) checkApprovalMFA(w http.ResponseWriter, r *http.Request, sess *uiSession, in agentDecisionInput, a store.Agent, requestID string) bool {
	if !s.approvalNeedsMFA(r, sess) {
		return true
	}
	ctx := r.Context()
	o := s.agentOrigin(r, a)
	o.Resource = requestID
	if strings.TrimSpace(in.MFACode) == "" && strings.TrimSpace(in.RecoveryCode) == "" {
		writeNativeError(w, http.StatusForbidden, "mfa_required", "your organization requires a current MFA code to approve agent access")
		return false
	}
	ip, userKey := s.clientIP(r), strings.ToLower(sess.Username)
	if wait, limited := s.mfaThrottled(ctx, ip, userKey); limited {
		writeMFAThrottled(w, wait)
		return false
	}
	e, err := s.store.GetMFA(ctx, sess.Username)
	if errors.Is(err, store.ErrMFANotFound) || (err == nil && !e.Enabled) {
		writeNativeError(w, http.StatusForbidden, "mfa_required", "turn on multi-factor authentication (My account → Security) to approve agent access")
		return false
	}
	if err != nil {
		log.Printf("agent access: MFA read failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "verify_failed", "could not verify the code")
		return false
	}
	usedRecovery, ok, err := s.checkSecondFactor(ctx, e, strings.TrimSpace(in.MFACode), in.RecoveryCode)
	if err != nil {
		log.Printf("agent access: MFA verify failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "verify_failed", "could not verify the code")
		return false
	}
	if !ok {
		s.mfaFailed(ip, userKey)
		s.recordAudit(ctx, store.AuditEvent{Action: auditApproveAgentAccess, KeyID: requestID, Result: "denied", ErrorType: "InvalidCode", AuditOrigin: o})
		writeNativeError(w, http.StatusForbidden, "invalid_mfa_code", "the MFA code is incorrect")
		return false
	}
	if usedRecovery {
		s.recordAudit(ctx, store.AuditEvent{Action: "citadel.MFARecoveryCodeUsed", KeyID: sess.Username, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	}
	s.mfaSucceeded(ip, userKey)
	return true
}

func (s *Server) handleV1ApproveAgentAccess(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var in agentDecisionInput
	if err := decodeJSONBody(r, &in); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	in.RequestID, in.Scope, in.Comment = strings.TrimSpace(in.RequestID), strings.TrimSpace(in.Scope), strings.TrimSpace(in.Comment)
	if in.Comment != "" && !printable(in.Comment, maxAgentRequestReason) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "comment must be at most 512 printable characters")
		return
	}
	req, a, ok := s.loadDecidableRequest(w, r.WithContext(ctx), sess, in, auditApproveAgentAccess)
	if !ok {
		return
	}
	switch in.Scope {
	case store.AgentLeaseOnce, store.AgentLeaseDuration:
	case store.AgentLeaseTask:
		if req.TaskID == "" {
			writeNativeError(w, http.StatusBadRequest, "invalid_request", "this request has no task ID; approve it once or for a duration")
			return
		}
	default:
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "scope must be once, duration or task")
		return
	}
	if a.Status != store.AgentStatusActive {
		writeNativeError(w, http.StatusConflict, "agent_not_active", "the agent is "+a.Status+"; resume it before approving its requests")
		return
	}
	cred, err := s.store.GetAgentCredential(ctx, a.AccountID, req.Credential)
	if errors.Is(err, store.ErrAgentCredentialNotFound) {
		writeNativeError(w, http.StatusConflict, "credential_not_found", "no agent credential has this name; deny the request")
		return
	}
	if err != nil {
		log.Printf("agent access: credential read failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "internal_error", "could not approve the request")
		return
	}
	if slices.Contains(req.Actions, store.AgentActionTOTP) && cred.Kind != store.AgentCredentialLogin {
		writeNativeError(w, http.StatusConflict, "invalid_action", "totp applies only to login credentials; deny the request")
		return
	}
	if slices.Contains(req.Actions, store.AgentActionUse) && cred.Kind == store.AgentCredentialRaw {
		writeNativeError(w, http.StatusConflict, "invalid_action", "raw credentials can only be revealed; deny the request")
		return
	}
	grants, err := s.store.ListAgentGrants(ctx, a.AccountID, a.AgentID)
	if err != nil {
		log.Printf("agent access: grants read failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "internal_error", "could not approve the request")
		return
	}
	now := time.Now().UTC().Truncate(time.Second)
	limit := agentLeaseCap(findGrant(grants, a.AgentID, req.Credential), now)
	dur := in.DurationSeconds
	if dur == 0 {
		dur = req.DurationSeconds
		if dur == 0 {
			dur = defaultAgentLeaseSeconds
		}
		dur = min(dur, limit)
	}
	if dur < minAgentLeaseSeconds || dur > limit {
		if limit < minAgentLeaseSeconds {
			writeNativeError(w, http.StatusConflict, "grant_expiring", "the agent's grant for this credential ends in less than a minute")
			return
		}
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "durationSeconds must be between 60 and "+strconv.Itoa(limit))
		return
	}
	if !s.checkApprovalMFA(w, r.WithContext(ctx), sess, in, a, req.RequestID) {
		return
	}
	lease := store.AgentLease{
		AccountID: a.AccountID, LeaseID: store.NewAgentLeaseID(), AgentID: a.AgentID, Credential: req.Credential, Actions: req.Actions,
		Scope: in.Scope, ExpiresAt: now.Add(time.Duration(dur) * time.Second), CreatedAt: now, CreatedBy: sess.Principal(),
	}
	switch in.Scope {
	case store.AgentLeaseOnce:
		one := 1
		lease.UsesLeft = &one
	case store.AgentLeaseTask:
		lease.TaskID = req.TaskID
	}
	decided, err := s.store.DecideAgentAccessRequest(ctx, a.AccountID, req.RequestID, store.AgentAccessDecision{
		Status: store.AgentRequestApproved, By: sess.Principal(), Comment: in.Comment, At: now, Lease: &lease,
	})
	if errors.Is(err, store.ErrAgentAccessRequestDecided) {
		writeNativeError(w, http.StatusConflict, "already_decided", "this request has already been decided or has expired")
		return
	}
	if err != nil {
		log.Printf("agent access: approve failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "approve_failed", "could not approve the request")
		return
	}
	o := s.agentOrigin(r, a)
	o.Resource = "request=" + decided.RequestID + " lease=" + lease.LeaseID + " credential=" + lease.Credential + " actions=" + strings.Join(lease.Actions, ",") + " scope=" + lease.Scope
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.ApproveAgentAccess", KeyID: decided.RequestID, Result: "ok", AuditOrigin: o})
	s.notifyAgentDecision(ctx, a, decided, sess.Principal(), &lease)
	writeNativeJSON(w, http.StatusOK, map[string]any{
		"request": s.agentAccessRequestConsoleOut(sess, decided, a, findGrant(grants, a.AgentID, req.Credential), cred.Kind, false, now),
		"lease":   agentLeaseOut(lease, now),
	})
}

func (s *Server) handleV1DenyAgentAccess(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var in agentDecisionInput
	if err := decodeJSONBody(r, &in); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	in.RequestID, in.Comment = strings.TrimSpace(in.RequestID), strings.TrimSpace(in.Comment)
	if in.Comment == "" || !printable(in.Comment, maxAgentRequestReason) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "a reason (comment) of at most 512 printable characters is required")
		return
	}
	req, a, ok := s.loadDecidableRequest(w, r.WithContext(ctx), sess, in, auditDenyAgentAccess)
	if !ok {
		return
	}
	now := time.Now().UTC().Truncate(time.Second)
	decided, err := s.store.DecideAgentAccessRequest(ctx, a.AccountID, req.RequestID, store.AgentAccessDecision{
		Status: store.AgentRequestDenied, By: sess.Principal(), Comment: in.Comment, At: now,
	})
	if errors.Is(err, store.ErrAgentAccessRequestDecided) {
		writeNativeError(w, http.StatusConflict, "already_decided", "this request has already been decided or has expired")
		return
	}
	if err != nil {
		log.Printf("agent access: deny failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "deny_failed", "could not deny the request")
		return
	}
	o := s.agentOrigin(r, a)
	o.Resource = "request=" + decided.RequestID + " credential=" + decided.Credential
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.DenyAgentAccess", KeyID: decided.RequestID, Result: "ok", AuditOrigin: o})
	s.notifyAgentDecision(ctx, a, decided, sess.Principal(), nil)
	writeNativeJSON(w, http.StatusOK, map[string]any{"request": s.agentAccessRequestConsoleOut(sess, decided, a, nil, "", false, now)})
}

// notifyAgentDecision raises agent.access_decided.
func (s *Server) notifyAgentDecision(ctx context.Context, a store.Agent, req store.AgentAccessRequest, by string, lease *store.AgentLease) {
	payload := map[string]any{
		"requestId": req.RequestID, "agentId": a.AgentID, "agentName": a.Name, "credential": req.Credential, "actions": req.Actions,
		"decision": req.Status, "decidedBy": by, "url": s.agentRequestURL(req.RequestID),
		"summary": by + " " + req.Status + " " + a.Name + "'s request to " + strings.Join(req.Actions, "/") + " " + req.Credential,
	}
	if lease != nil {
		payload["leaseId"], payload["scope"], payload["leaseExpiresAt"] = lease.LeaseID, lease.Scope, fmtTime(lease.ExpiresAt)
	}
	if req.Status == store.AgentRequestDenied && req.DecisionComment != "" {
		payload["comment"] = req.DecisionComment
	}
	if err := s.notify(context.WithoutCancel(ctx), a.AccountID, EventAgentAccessDecided, payload); err != nil {
		log.Printf("agent access: notify failed: %v", err)
	}
}

func (s *Server) handleV1ListAgentLeases(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	q := r.URL.Query()
	agentID := strings.TrimSpace(q.Get("agentId"))
	if agentID != "" && !store.IsAgentID(agentID) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "agentId is malformed")
		return
	}
	activeOnly := q.Get("active") != "false"
	acct := s.agentAccount(ctx, sess)
	now := time.Now().UTC()
	leases, err := s.store.ListAgentLeases(ctx, acct, agentID, activeOnly, now)
	var agents []store.Agent
	if err == nil {
		agents, err = s.store.ListAgents(ctx, acct)
	}
	if err != nil {
		log.Printf("agent access: list leases failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "internal_error", "could not list leases")
		return
	}
	byID := map[string]store.Agent{}
	for _, a := range agents {
		byID[a.AgentID] = a
	}
	out := make([]agentLeaseJSON, 0, len(leases))
	for _, l := range leases {
		a := byID[l.AgentID]
		j := agentLeaseOut(l, now)
		j.AgentName = a.Name
		j.CanRevoke = j.Status == "active" && canManageAgent(sess, a)
		out = append(out, j)
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"leases": out})
}

type agentLeaseRevokeInput struct {
	LeaseID string `json:"leaseId"`
	Reason  string `json:"reason"`
}

func (s *Server) handleV1RevokeAgentLease(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var in agentLeaseRevokeInput
	if err := decodeJSONBody(r, &in); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	in.LeaseID = strings.TrimSpace(in.LeaseID)
	reason, okReason := validReason(in.Reason)
	if !store.IsAgentObjectID(in.LeaseID, "als_") || !okReason {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "leaseId is required; reason must be at most 256 printable characters")
		return
	}
	acct := s.agentAccount(ctx, sess)
	l, err := s.store.GetAgentLease(ctx, acct, in.LeaseID)
	if errors.Is(err, store.ErrAgentLeaseNotFound) {
		writeNativeError(w, http.StatusNotFound, "not_found", "lease not found")
		return
	}
	if err != nil {
		log.Printf("agent access: lease read failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "internal_error", "could not revoke the lease")
		return
	}
	a, ok := s.loadManagedAgent(w, r, ctx, sess, l.AgentID, auditRevokeAgentLease)
	if !ok {
		return
	}
	now := time.Now().UTC().Truncate(time.Second)
	if reason == "" {
		reason = "revoked"
	}
	ended, err := s.store.EndAgentLease(ctx, acct, l.LeaseID, sess.Principal(), reason, now)
	if errors.Is(err, store.ErrAgentLeaseEnded) {
		writeNativeError(w, http.StatusConflict, "lease_ended", "the lease has already ended")
		return
	}
	if err != nil {
		log.Printf("agent access: revoke lease failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "revoke_failed", "could not revoke the lease")
		return
	}
	o := s.agentOrigin(r, a)
	o.Resource = "lease=" + ended.LeaseID + " credential=" + ended.Credential
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.RevokeAgentLease", KeyID: ended.LeaseID, Result: "ok", AuditOrigin: o})
	j := agentLeaseOut(ended, now)
	j.AgentName = a.Name
	writeNativeJSON(w, http.StatusOK, j)
}
