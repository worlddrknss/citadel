package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// Agents API (2.2).
//
// Console management (/v1/agents/...): session or access-key auth, scoped to
// the caller's account. Viewers can read. Creating an agent needs editor; an
// agent is then managed by account admins and by its owner (when the owner
// is at least an editor). Usage profiles on secrets need editor; the
// account-wide kill switch needs admin. Every change is audited (write-ahead
// through nativeSession, outcome events carry the agent's ID so its activity
// view shows console changes next to what the agent did).
//
// Agent-facing (/v1/agent/...): agent token or federated token only (see
// agent_auth.go). Values are never returned here; brokered use and reveal
// build on evaluateAgentAccess (agent_policy.go).

func (s *Server) registerAgentRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/agents", s.handleV1ListAgents)
	mux.HandleFunc("POST /v1/agents", s.handleV1CreateAgent)
	mux.HandleFunc("DELETE /v1/agents", s.handleV1DeleteAgent)
	mux.HandleFunc("GET /v1/agents/detail", s.handleV1AgentDetail)
	mux.HandleFunc("POST /v1/agents/update", s.handleV1UpdateAgent)
	mux.HandleFunc("POST /v1/agents/suspend", s.handleV1SuspendAgent)
	mux.HandleFunc("POST /v1/agents/resume", s.handleV1ResumeAgent)
	mux.HandleFunc("POST /v1/agents/revoke", s.handleV1RevokeAgent)
	mux.HandleFunc("POST /v1/agents/tokens", s.handleV1CreateAgentToken)
	mux.HandleFunc("POST /v1/agents/tokens/revoke", s.handleV1RevokeAgentToken)
	mux.HandleFunc("POST /v1/agents/bindings", s.handleV1CreateAgentBinding)
	mux.HandleFunc("DELETE /v1/agents/bindings", s.handleV1DeleteAgentBinding)
	mux.HandleFunc("POST /v1/agents/grants", s.handleV1PutAgentGrant)
	mux.HandleFunc("DELETE /v1/agents/grants", s.handleV1DeleteAgentGrant)
	mux.HandleFunc("GET /v1/agents/credentials", s.handleV1ListAgentCredentials)
	mux.HandleFunc("POST /v1/agents/credentials", s.handleV1CreateAgentCredential)
	mux.HandleFunc("POST /v1/agents/credentials/update", s.handleV1UpdateAgentCredential)
	mux.HandleFunc("DELETE /v1/agents/credentials", s.handleV1DeleteAgentCredential)
	mux.HandleFunc("GET /v1/agents/settings", s.handleV1GetAgentSettings)
	mux.HandleFunc("POST /v1/agents/settings", s.handleV1PutAgentSettings)

	mux.HandleFunc("GET /v1/agent/whoami", s.handleV1AgentWhoAmI)
	mux.HandleFunc("GET /v1/agent/credentials", s.handleV1AgentCredentials)
}

// Audit actions.
const (
	auditCreateAgent           = "citadel.CreateAgent"
	auditUpdateAgent           = "citadel.UpdateAgent"
	auditDeleteAgent           = "citadel.DeleteAgent"
	auditSuspendAgent          = "citadel.SuspendAgent"
	auditResumeAgent           = "citadel.ResumeAgent"
	auditRevokeAgent           = "citadel.RevokeAgent"
	auditCreateAgentToken      = "citadel.CreateAgentToken"
	auditRevokeAgentToken      = "citadel.RevokeAgentToken"
	auditCreateAgentBinding    = "citadel.CreateAgentBinding"
	auditDeleteAgentBinding    = "citadel.DeleteAgentBinding"
	auditPutAgentGrant         = "citadel.PutAgentGrant"
	auditDeleteAgentGrant      = "citadel.DeleteAgentGrant"
	auditCreateAgentCredential = "citadel.CreateAgentCredential"
	auditUpdateAgentCredential = "citadel.UpdateAgentCredential"
	auditDeleteAgentCredential = "citadel.DeleteAgentCredential"
	auditSuspendAllAgents      = "citadel.SuspendAllAgents"
	auditResumeAllAgents       = "citadel.ResumeAllAgents"
	auditAgentWhoAmI           = "citadel.AgentWhoAmI"
	auditAgentListCredentials  = "citadel.AgentListCredentials"
)

// Limits.
const (
	maxAgentsPerAccount     = 500
	maxAgentTokensActive    = 10
	maxAgentBindings        = 20
	maxAgentLabels          = 20
	maxAgentTokenDays       = 365
	maxAgentHosts           = 20
	maxAgentPathPrefixes    = 20
	maxAgentCIDRs           = 10
	maxAgentGrantUsesPerHr  = 100000
	maxAgentReasonLen       = 256
	maxAgentDescriptionLen  = 512
	maxAgentFederationField = 256
)

var (
	agentNameRe      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	agentLabelKeyRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,62}$`)
	agentCredNameRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	agentHostRe      = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(:[0-9]{1,5})?$`)
	agentHeaderRe    = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$")
	agentQueryRe     = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,64}$`)
	agentObjectIDRe  = regexp.MustCompile(`^a(tk|bd|gr)_[a-z2-7]{16}$`)
	agentHTTPMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	// Headers a credential may never be injected as: they frame the request
	// or address a proxy.
	agentForbiddenHeaders = []string{"host", "content-length", "transfer-encoding", "connection", "keep-alive", "te", "trailer", "upgrade", "expect"}
)

// ---- JSON models ------------------------------------------------------------

type agentJSON struct {
	AgentID          string            `json:"agentId"`
	Name             string            `json:"name"`
	Description      string            `json:"description"`
	Owner            string            `json:"owner"`
	Status           string            `json:"status"`
	Labels           map[string]string `json:"labels"`
	CreatedAt        string            `json:"createdAt"`
	CreatedBy        string            `json:"createdBy,omitempty"`
	UpdatedAt        string            `json:"updatedAt"`
	LastUsedAt       string            `json:"lastUsedAt,omitempty"`
	StatusChangedAt  string            `json:"statusChangedAt,omitempty"`
	StatusChangedBy  string            `json:"statusChangedBy,omitempty"`
	StatusReason     string            `json:"statusReason,omitempty"`
	GrantCount       int               `json:"grantCount"`
	ActiveTokenCount int               `json:"activeTokenCount"`
	BindingCount     int               `json:"bindingCount"`
	// RequireFederation: agent tokens are refused; the agent authenticates
	// with workload identity federation only.
	RequireFederation bool `json:"requireFederation"`
	// CanManage reports whether the caller may change the agent.
	CanManage bool `json:"canManage"`
}

func agentOut(a store.Agent) agentJSON {
	labels := a.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	return agentJSON{
		AgentID: a.AgentID, Name: a.Name, Description: a.Description, Owner: a.Owner, Status: a.Status, Labels: labels,
		CreatedAt: fmtTime(a.CreatedAt), CreatedBy: a.CreatedBy, UpdatedAt: fmtTime(a.UpdatedAt), LastUsedAt: fmtTimePtr(a.LastUsedAt),
		StatusChangedAt: fmtTimePtr(a.StatusChangedAt), StatusChangedBy: a.StatusChangedBy, StatusReason: a.StatusReason,
		RequireFederation: a.RequireFederation,
	}
}

type agentTokenJSON struct {
	TokenID    string `json:"tokenId"`
	Name       string `json:"name"`
	Prefix     string `json:"prefix"`
	Status     string `json:"status"`
	CreatedAt  string `json:"createdAt"`
	CreatedBy  string `json:"createdBy,omitempty"`
	ExpiresAt  string `json:"expiresAt,omitempty"`
	RevokedAt  string `json:"revokedAt,omitempty"`
	RevokedBy  string `json:"revokedBy,omitempty"`
	LastUsedAt string `json:"lastUsedAt,omitempty"`
}

func agentTokenOut(t store.AgentToken, now time.Time) agentTokenJSON {
	status := "active"
	switch {
	case t.RevokedAt != nil:
		status = "revoked"
	case t.ExpiresAt != nil && !now.Before(*t.ExpiresAt):
		status = "expired"
	}
	return agentTokenJSON{
		TokenID: t.TokenID, Name: t.Name, Prefix: store.FormatAgentToken(t.AgentID, t.Hint), Status: status,
		CreatedAt: fmtTime(t.CreatedAt), CreatedBy: t.CreatedBy, ExpiresAt: fmtTimePtr(t.ExpiresAt), RevokedAt: fmtTimePtr(t.RevokedAt),
		RevokedBy: t.RevokedBy, LastUsedAt: fmtTimePtr(t.LastUsedAt),
	}
}

type agentBindingJSON struct {
	BindingID   string `json:"bindingId"`
	Issuer      string `json:"issuer"`
	Subject     string `json:"subject"`
	Audience    string `json:"audience"`
	Description string `json:"description"`
	CreatedAt   string `json:"createdAt"`
	CreatedBy   string `json:"createdBy,omitempty"`
}

func agentBindingOut(b store.AgentBinding) agentBindingJSON {
	return agentBindingJSON{BindingID: b.BindingID, Issuer: b.Issuer, Subject: b.Subject, Audience: b.Audience, Description: b.Description, CreatedAt: fmtTime(b.CreatedAt), CreatedBy: b.CreatedBy}
}

type agentWindowJSON struct {
	Start    string   `json:"start"`
	End      string   `json:"end"`
	Days     []string `json:"days"`
	Timezone string   `json:"timezone"`
}

type agentGrantJSON struct {
	GrantID        string           `json:"grantId"`
	AgentID        string           `json:"agentId"`
	AgentName      string           `json:"agentName,omitempty"`
	Credential     string           `json:"credential"`
	Actions        []string         `json:"actions"`
	NotBefore      string           `json:"notBefore,omitempty"`
	NotAfter       string           `json:"notAfter,omitempty"`
	Window         *agentWindowJSON `json:"window"`
	MaxUsesPerHour int              `json:"maxUsesPerHour"`
	// RequiresApproval: every use needs a lease from an approved access
	// request. LeaseTTLSeconds caps approvals, or (without
	// RequiresApproval) opens a lease of that length on first use.
	RequiresApproval *bool  `json:"requiresApproval"`
	LeaseTTLSeconds  *int   `json:"leaseTtlSeconds"`
	CreatedAt        string `json:"createdAt"`
	CreatedBy        string `json:"createdBy,omitempty"`
	UpdatedAt        string `json:"updatedAt"`
	UpdatedBy        string `json:"updatedBy,omitempty"`
	// UsableNow is false when the grant's dates or window exclude now;
	// Reason says why.
	UsableNow bool   `json:"usableNow"`
	Reason    string `json:"reason,omitempty"`

	// Scope narrows minted tokens (2.4); absent when it narrows nothing.
	Scope *store.AgentGrantScope `json:"scope,omitempty"`
}

func agentGrantOut(g store.AgentGrant, now time.Time) agentGrantJSON {
	out := agentGrantJSON{
		GrantID: g.GrantID, AgentID: g.AgentID, Credential: g.Credential, Actions: g.Actions, NotBefore: fmtTimePtr(g.NotBefore), NotAfter: fmtTimePtr(g.NotAfter),
		MaxUsesPerHour: g.MaxUsesPerHour, RequiresApproval: g.RequiresApproval, LeaseTTLSeconds: g.LeaseTTLSeconds,
		CreatedAt: fmtTime(g.CreatedAt), CreatedBy: g.CreatedBy, UpdatedAt: fmtTime(g.UpdatedAt), UpdatedBy: g.UpdatedBy,
	}
	if out.Actions == nil {
		out.Actions = []string{}
	}
	if g.WindowStart != "" || g.WindowEnd != "" || len(g.WindowDays) > 0 {
		days := g.WindowDays
		if days == nil {
			days = []string{}
		}
		out.Window = &agentWindowJSON{Start: g.WindowStart, End: g.WindowEnd, Days: days, Timezone: g.Timezone}
	}
	out.Reason = agentGrantStatus(g, now)
	out.UsableNow = out.Reason == ""
	if !g.Scope.IsZero() {
		sc := g.Scope.Clone()
		out.Scope = &sc
	}
	return out
}

type agentCredentialGrantRef struct {
	GrantID   string   `json:"grantId"`
	AgentID   string   `json:"agentId"`
	AgentName string   `json:"agentName"`
	Actions   []string `json:"actions"`
}

type agentCredentialJSON struct {
	Name                string                    `json:"name"`
	SecretName          string                    `json:"secretName"`
	Project             string                    `json:"project,omitempty"`
	Env                 string                    `json:"env,omitempty"`
	Path                string                    `json:"path,omitempty"`
	Key                 string                    `json:"key,omitempty"`
	Kind                string                    `json:"kind"`
	Description         string                    `json:"description"`
	AllowedHosts        []string                  `json:"allowedHosts"`
	AllowedMethods      []string                  `json:"allowedMethods"`
	AllowedPathPrefixes []string                  `json:"allowedPathPrefixes"`
	HeaderName          string                    `json:"headerName,omitempty"`
	HeaderPrefix        string                    `json:"headerPrefix,omitempty"`
	QueryParam          string                    `json:"queryParam,omitempty"`
	AllowHTTP           bool                      `json:"allowHttp"`
	AllowedCIDRs        []string                  `json:"allowedCidrs"`
	CreatedAt           string                    `json:"createdAt"`
	CreatedBy           string                    `json:"createdBy,omitempty"`
	UpdatedAt           string                    `json:"updatedAt"`
	UpdatedBy           string                    `json:"updatedBy,omitempty"`
	Grants              []agentCredentialGrantRef `json:"grants"`

	// The kind-specific settings (2.4): login, awsSts, githubApp, oauth2.
	store.AgentCredentialConfig
}

func agentCredentialOut(c store.AgentCredential) agentCredentialJSON {
	nz := func(v []string) []string {
		if v == nil {
			return []string{}
		}
		return v
	}
	out := agentCredentialJSON{
		Name: c.Name, SecretName: c.SecretName, Kind: c.Kind, Description: c.Description, AllowedHosts: nz(c.AllowedHosts),
		AllowedMethods: nz(c.AllowedMethods), AllowedPathPrefixes: nz(c.AllowedPathPrefixes), HeaderName: c.HeaderName,
		HeaderPrefix: c.HeaderPrefix, QueryParam: c.QueryParam, AllowHTTP: c.AllowHTTP, AllowedCIDRs: nz(c.AllowedCIDRs),
		CreatedAt: fmtTime(c.CreatedAt), CreatedBy: c.CreatedBy, UpdatedAt: fmtTime(c.UpdatedAt), UpdatedBy: c.UpdatedBy,
		Grants: []agentCredentialGrantRef{}, AgentCredentialConfig: c.Config.Clone(),
	}
	if pi, ok := parseSecretName(c.SecretName); ok {
		out.Project, out.Env, out.Path, out.Key = pi.Project, pi.Env, strings.Join(pi.Folder, "/"), pi.Key
	}
	return out
}

type agentSettingsJSON struct {
	AgentsSuspended bool   `json:"agentsSuspended"`
	SuspendedAt     string `json:"suspendedAt,omitempty"`
	SuspendedBy     string `json:"suspendedBy,omitempty"`
	Reason          string `json:"reason,omitempty"`
}

func agentSettingsOut(st store.AgentSettings) agentSettingsJSON {
	return agentSettingsJSON{AgentsSuspended: st.AgentsSuspended, SuspendedAt: fmtTimePtr(st.SuspendedAt), SuspendedBy: st.SuspendedBy, Reason: st.Reason}
}

// ---- helpers ----------------------------------------------------------------

// agentAccount is the account a management request acts in.
func (s *Server) agentAccount(ctx context.Context, sess *uiSession) string {
	if acct := strings.TrimSpace(sess.AccountID); acct != "" {
		return acct
	}
	return s.callerAccount(ctx)
}

// canManageAgent: account admins, and the agent's owner when an editor.
func canManageAgent(sess *uiSession, a store.Agent) bool {
	return uiCanAdmin(sess) || (uiCanEdit(sess) && strings.EqualFold(a.Owner, sess.Principal()))
}

// agentOwnerAllowed reports whether username may own an agent in account:
// an existing user who belongs to it (or a platform admin).
func (s *Server) agentOwnerAllowed(ctx context.Context, account, username string) bool {
	u, ok := s.lookupUser(ctx, username)
	if !ok {
		return false
	}
	if s.isPlatformAdmin(u) {
		return true
	}
	_, member := accountRole(s.userMemberships(ctx, u), account)
	return member
}

// agentAudit records a console change to an agent, attributed to it.
func (s *Server) agentAudit(ctx context.Context, r *http.Request, action string, a store.Agent, keyID, result, errType string) {
	o := s.auditOrigin(r)
	o.AgentID, o.AgentOwner = a.AgentID, a.Owner
	o.Resource = a.AgentID
	if keyID == "" {
		keyID = a.AgentID
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: keyID, Result: result, ErrorType: errType, AuditOrigin: o})
}

// loadManagedAgent loads agentID in the caller's account and checks the
// caller may manage it, writing the error response otherwise.
func (s *Server) loadManagedAgent(w http.ResponseWriter, r *http.Request, ctx context.Context, sess *uiSession, agentID, action string) (store.Agent, bool) {
	if !store.IsAgentID(agentID) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "agentId is required")
		return store.Agent{}, false
	}
	a, err := s.store.GetAgent(ctx, s.agentAccount(ctx, sess), agentID)
	if errors.Is(err, store.ErrAgentNotFound) {
		writeNativeError(w, http.StatusNotFound, "not_found", "agent not found")
		return store.Agent{}, false
	}
	if err != nil {
		log.Printf("agents: load failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "internal_error", "could not load the agent")
		return store.Agent{}, false
	}
	if !canManageAgent(sess, a) {
		s.agentAudit(ctx, r, action, a, "", "denied", "AccessDenied")
		writeNativeError(w, http.StatusForbidden, "forbidden", "only the agent's owner or an account admin can change it")
		return store.Agent{}, false
	}
	return a, true
}

func validLabels(in map[string]string) (map[string]string, string) {
	if len(in) > maxAgentLabels {
		return nil, "at most 20 labels"
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		k = strings.TrimSpace(k)
		if !agentLabelKeyRe.MatchString(k) {
			return nil, "label keys must be 1-63 lowercase letters, digits, dots, dashes, underscores or slashes"
		}
		if len(v) > 128 || (v != "" && !printable(v, 128)) {
			return nil, "label values must be at most 128 printable characters"
		}
		out[k] = v
	}
	return out, ""
}

func validReason(v string) (string, bool) {
	v = strings.TrimSpace(v)
	return v, v == "" || printable(v, maxAgentReasonLen)
}

// ---- agents -----------------------------------------------------------------

func (s *Server) handleV1ListAgents(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	acct := s.agentAccount(ctx, sess)
	agents, err := s.store.ListAgents(ctx, acct)
	var grants []store.AgentGrant
	if err == nil {
		grants, err = s.store.ListAgentGrants(ctx, acct, "")
	}
	var settings store.AgentSettings
	if err == nil {
		settings, err = s.store.GetAgentSettings(ctx, acct)
	}
	if err != nil {
		log.Printf("agents: list failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "list_failed", "could not list agents")
		return
	}
	grantCount := map[string]int{}
	for _, g := range grants {
		grantCount[g.AgentID]++
	}
	now := time.Now().UTC()
	out := make([]agentJSON, 0, len(agents))
	for _, a := range agents {
		j := agentOut(a)
		j.GrantCount = grantCount[a.AgentID]
		if tokens, err := s.store.ListAgentTokens(ctx, acct, a.AgentID); err == nil {
			for _, t := range tokens {
				if t.Active(now) {
					j.ActiveTokenCount++
				}
			}
		}
		j.CanManage = canManageAgent(sess, a)
		out = append(out, j)
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"agents": out, "settings": agentSettingsOut(settings), "canCreate": uiCanEdit(sess)})
}

type agentInput struct {
	AgentID     string            `json:"agentId,omitempty"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Owner       string            `json:"owner"`
	Labels      map[string]string `json:"labels"`
	// RequireFederation is left unchanged on update when omitted.
	RequireFederation *bool `json:"requireFederation,omitempty"`
}

// validateAgentInput checks name, description, labels and owner; it returns
// the owner to store.
func (s *Server) validateAgentInput(ctx context.Context, sess *uiSession, acct string, in *agentInput, currentOwner string) (string, int, string) {
	in.Name, in.Description = strings.TrimSpace(in.Name), strings.TrimSpace(in.Description)
	if !agentNameRe.MatchString(in.Name) {
		return "", http.StatusBadRequest, "name must be 1-64 letters, digits, dots, dashes or underscores, starting with a letter or digit"
	}
	if len(in.Description) > maxAgentDescriptionLen || (in.Description != "" && !printable(in.Description, maxAgentDescriptionLen)) {
		return "", http.StatusBadRequest, "description must be at most 512 printable characters"
	}
	labels, msg := validLabels(in.Labels)
	if msg != "" {
		return "", http.StatusBadRequest, msg
	}
	in.Labels = labels
	owner := strings.TrimSpace(in.Owner)
	if owner == "" {
		owner = currentOwner
	}
	if owner == "" {
		owner = sess.Principal()
	}
	if !strings.EqualFold(owner, currentOwner) && !strings.EqualFold(owner, sess.Principal()) && !uiCanAdmin(sess) {
		return "", http.StatusForbidden, "only account admins can make someone else an agent's owner"
	}
	if !strings.EqualFold(owner, currentOwner) && !s.agentOwnerAllowed(ctx, acct, owner) {
		return "", http.StatusBadRequest, "the owner must be a user in this account"
	}
	return owner, 0, ""
}

func (s *Server) handleV1CreateAgent(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var in agentInput
	if err := decodeJSONBody(r, &in); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	acct := s.agentAccount(ctx, sess)
	owner, status, msg := s.validateAgentInput(ctx, sess, acct, &in, "")
	if msg != "" {
		writeNativeError(w, status, "invalid_request", msg)
		return
	}
	if existing, err := s.store.ListAgents(ctx, acct); err == nil && len(existing) >= maxAgentsPerAccount {
		writeNativeError(w, http.StatusConflict, "limit_exceeded", "this account has the maximum number of agents")
		return
	}
	now := time.Now().UTC().Truncate(time.Second)
	a := store.Agent{
		AccountID: acct, AgentID: store.NewAgentID(), Name: in.Name, Description: in.Description, Owner: owner,
		Status: store.AgentStatusActive, Labels: in.Labels, CreatedAt: now, CreatedBy: sess.Principal(), UpdatedAt: now,
		RequireFederation: in.RequireFederation != nil && *in.RequireFederation,
	}
	if err := s.store.CreateAgent(ctx, a); err != nil {
		if errors.Is(err, store.ErrAgentExists) {
			writeNativeError(w, http.StatusConflict, "already_exists", "an agent with that name already exists")
			return
		}
		log.Printf("agents: create failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "create_failed", "could not create the agent")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.CreateAgent", KeyID: a.AgentID, Result: "ok", AuditOrigin: s.agentOrigin(r, a)})
	j := agentOut(a)
	j.CanManage = canManageAgent(sess, a)
	writeNativeJSON(w, http.StatusCreated, j)
}

// agentOrigin is auditOrigin attributed to agent a.
func (s *Server) agentOrigin(r *http.Request, a store.Agent) store.AuditOrigin {
	o := s.auditOrigin(r)
	o.AgentID, o.AgentOwner, o.Resource = a.AgentID, a.Owner, a.AgentID
	return o
}

func (s *Server) handleV1AgentDetail(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	agentID := strings.TrimSpace(r.URL.Query().Get("agentId"))
	if !store.IsAgentID(agentID) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "agentId is required")
		return
	}
	acct := s.agentAccount(ctx, sess)
	a, err := s.store.GetAgent(ctx, acct, agentID)
	if errors.Is(err, store.ErrAgentNotFound) {
		writeNativeError(w, http.StatusNotFound, "not_found", "agent not found")
		return
	}
	var (
		tokens   []store.AgentToken
		bindings []store.AgentBinding
		grants   []store.AgentGrant
	)
	if err == nil {
		tokens, err = s.store.ListAgentTokens(ctx, acct, agentID)
	}
	if err == nil {
		bindings, err = s.store.ListAgentBindings(ctx, acct, agentID)
	}
	if err == nil {
		grants, err = s.store.ListAgentGrants(ctx, acct, agentID)
	}
	if err != nil {
		log.Printf("agents: detail failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "internal_error", "could not load the agent")
		return
	}
	now := time.Now().UTC()
	j := agentOut(a)
	j.GrantCount, j.BindingCount, j.CanManage = len(grants), len(bindings), canManageAgent(sess, a)
	tout := make([]agentTokenJSON, 0, len(tokens))
	for _, t := range tokens {
		if t.Active(now) {
			j.ActiveTokenCount++
		}
		tout = append(tout, agentTokenOut(t, now))
	}
	bout := make([]agentBindingJSON, 0, len(bindings))
	for _, b := range bindings {
		bout = append(bout, agentBindingOut(b))
	}
	gout := make([]agentGrantJSON, 0, len(grants))
	for _, g := range grants {
		gj := agentGrantOut(g, now)
		gj.AgentName = a.Name
		gout = append(gout, gj)
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"agent": j, "tokens": tout, "bindings": bout, "grants": gout})
}

func (s *Server) handleV1UpdateAgent(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var in agentInput
	if err := decodeJSONBody(r, &in); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	a, ok := s.loadManagedAgent(w, r, ctx, sess, strings.TrimSpace(in.AgentID), auditUpdateAgent)
	if !ok {
		return
	}
	if a.Status == store.AgentStatusRevoked {
		writeNativeError(w, http.StatusConflict, "agent_revoked", "a revoked agent can't be changed")
		return
	}
	owner, status, msg := s.validateAgentInput(ctx, sess, a.AccountID, &in, a.Owner)
	if msg != "" {
		writeNativeError(w, status, "invalid_request", msg)
		return
	}
	a.Name, a.Description, a.Owner, a.Labels, a.UpdatedAt = in.Name, in.Description, owner, in.Labels, time.Now().UTC().Truncate(time.Second)
	if in.RequireFederation != nil {
		a.RequireFederation = *in.RequireFederation
	}
	if err := s.store.UpdateAgent(ctx, a); err != nil {
		if errors.Is(err, store.ErrAgentExists) {
			writeNativeError(w, http.StatusConflict, "already_exists", "an agent with that name already exists")
			return
		}
		log.Printf("agents: update failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "update_failed", "could not update the agent")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.UpdateAgent", KeyID: a.AgentID, Result: "ok", AuditOrigin: s.agentOrigin(r, a)})
	j := agentOut(a)
	j.CanManage = canManageAgent(sess, a)
	writeNativeJSON(w, http.StatusOK, j)
}

func (s *Server) handleV1DeleteAgent(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	a, ok := s.loadManagedAgent(w, r, ctx, sess, strings.TrimSpace(r.URL.Query().Get("agentId")), auditDeleteAgent)
	if !ok {
		return
	}
	if err := s.store.DeleteAgent(ctx, a.AccountID, a.AgentID); err != nil {
		log.Printf("agents: delete failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "delete_failed", "could not delete the agent")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.DeleteAgent", KeyID: a.AgentID, Result: "ok", AuditOrigin: s.agentOrigin(r, a)})
	writeNativeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

type agentStatusRequest struct {
	AgentID string `json:"agentId"`
	Reason  string `json:"reason"`
}

// changeAgentStatus implements suspend, resume and revoke.
func (s *Server) changeAgentStatus(w http.ResponseWriter, r *http.Request, sess *uiSession, ctx context.Context, action, to string) (store.Agent, bool) {
	var in agentStatusRequest
	if err := decodeJSONBody(r, &in); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return store.Agent{}, false
	}
	reason, okReason := validReason(in.Reason)
	if !okReason {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "reason must be at most 256 printable characters")
		return store.Agent{}, false
	}
	a, ok := s.loadManagedAgent(w, r, ctx, sess, strings.TrimSpace(in.AgentID), action)
	if !ok {
		return store.Agent{}, false
	}
	switch {
	case a.Status == store.AgentStatusRevoked:
		writeNativeError(w, http.StatusConflict, "agent_revoked", "the agent is revoked; revoking is permanent")
		return store.Agent{}, false
	case to == store.AgentStatusActive && a.Status != store.AgentStatusSuspended:
		writeNativeError(w, http.StatusConflict, "not_suspended", "the agent is not suspended")
		return store.Agent{}, false
	case to == store.AgentStatusSuspended && a.Status == store.AgentStatusSuspended:
		writeNativeError(w, http.StatusConflict, "already_suspended", "the agent is already suspended")
		return store.Agent{}, false
	}
	updated, err := s.store.SetAgentStatus(ctx, a.AccountID, a.AgentID, to, sess.Principal(), reason, time.Now().UTC().Truncate(time.Second))
	if errors.Is(err, store.ErrAgentRevoked) {
		writeNativeError(w, http.StatusConflict, "agent_revoked", "the agent is revoked; revoking is permanent")
		return store.Agent{}, false
	}
	if err != nil {
		log.Printf("agents: status change failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "update_failed", "could not change the agent's status")
		return store.Agent{}, false
	}
	return updated, true
}

func (s *Server) writeAgent(w http.ResponseWriter, sess *uiSession, a store.Agent) {
	j := agentOut(a)
	j.CanManage = canManageAgent(sess, a)
	writeNativeJSON(w, http.StatusOK, j)
}

func (s *Server) handleV1SuspendAgent(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	a, ok := s.changeAgentStatus(w, r, sess, ctx, auditSuspendAgent, store.AgentStatusSuspended)
	if !ok {
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.SuspendAgent", KeyID: a.AgentID, Result: "ok", AuditOrigin: s.agentOrigin(r, a)})
	s.endAgentAccess(ctx, r, a, sess.Principal(), "agent suspended", false)
	s.writeAgent(w, sess, a)
}

func (s *Server) handleV1ResumeAgent(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	a, ok := s.changeAgentStatus(w, r, sess, ctx, auditResumeAgent, store.AgentStatusActive)
	if !ok {
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.ResumeAgent", KeyID: a.AgentID, Result: "ok", AuditOrigin: s.agentOrigin(r, a)})
	s.writeAgent(w, sess, a)
}

func (s *Server) handleV1RevokeAgent(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	a, ok := s.changeAgentStatus(w, r, sess, ctx, auditRevokeAgent, store.AgentStatusRevoked)
	if !ok {
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.RevokeAgent", KeyID: a.AgentID, Result: "ok", AuditOrigin: s.agentOrigin(r, a)})
	s.endAgentAccess(ctx, r, a, sess.Principal(), "agent revoked", true)
	s.writeAgent(w, sess, a)
}

// ---- tokens -----------------------------------------------------------------

type agentTokenRequest struct {
	AgentID       string `json:"agentId"`
	Name          string `json:"name"`
	ExpiresInDays int    `json:"expiresInDays"`
}

func (s *Server) handleV1CreateAgentToken(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var in agentTokenRequest
	if err := decodeJSONBody(r, &in); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name != "" && !printable(in.Name, 64) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "name must be at most 64 printable characters")
		return
	}
	if in.ExpiresInDays < 0 || in.ExpiresInDays > maxAgentTokenDays {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "expiresInDays must be 0 (no expiry) to 365")
		return
	}
	a, ok := s.loadManagedAgent(w, r, ctx, sess, strings.TrimSpace(in.AgentID), auditCreateAgentToken)
	if !ok {
		return
	}
	if a.Status == store.AgentStatusRevoked {
		writeNativeError(w, http.StatusConflict, "agent_revoked", "a revoked agent can't get new tokens")
		return
	}
	if a.RequireFederation {
		writeNativeError(w, http.StatusConflict, "federation_required", "this agent must authenticate with workload identity federation; turn off requireFederation to issue tokens")
		return
	}
	now := time.Now().UTC().Truncate(time.Second)
	existing, err := s.store.ListAgentTokens(ctx, a.AccountID, a.AgentID)
	if err != nil {
		log.Printf("agents: list tokens failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "create_failed", "could not create the token")
		return
	}
	active := 0
	for _, t := range existing {
		if t.Active(now) {
			active++
		}
	}
	if active >= maxAgentTokensActive {
		writeNativeError(w, http.StatusConflict, "limit_exceeded", "the agent has 10 active tokens; revoke one first")
		return
	}
	secret := store.NewAgentTokenSecret()
	hash, err := cryptoutil.HashAgentToken(secret)
	if err != nil {
		log.Printf("agents: hash token failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "create_failed", "could not create the token")
		return
	}
	t := store.AgentToken{
		AccountID: a.AccountID, AgentID: a.AgentID, TokenID: store.NewAgentObjectID("atk_"), Name: in.Name,
		Hint: secret[:store.AgentTokenHintLen], Hash: hash, CreatedAt: now, CreatedBy: sess.Principal(),
	}
	if in.ExpiresInDays > 0 {
		exp := now.Add(time.Duration(in.ExpiresInDays) * 24 * time.Hour)
		t.ExpiresAt = &exp
	}
	if err := s.store.CreateAgentToken(ctx, t); err != nil {
		log.Printf("agents: create token failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "create_failed", "could not create the token")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.CreateAgentToken", KeyID: t.TokenID, Result: "ok", AuditOrigin: s.agentOrigin(r, a)})
	w.Header().Set("Cache-Control", "no-store")
	writeNativeJSON(w, http.StatusCreated, map[string]any{"token": store.FormatAgentToken(a.AgentID, secret), "tokenInfo": agentTokenOut(t, now)})
}

type agentTokenRevokeRequest struct {
	AgentID string `json:"agentId"`
	TokenID string `json:"tokenId"`
}

func (s *Server) handleV1RevokeAgentToken(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var in agentTokenRevokeRequest
	if err := decodeJSONBody(r, &in); err != nil || !agentObjectIDRe.MatchString(in.TokenID) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "agentId and tokenId are required")
		return
	}
	a, ok := s.loadManagedAgent(w, r, ctx, sess, strings.TrimSpace(in.AgentID), auditRevokeAgentToken)
	if !ok {
		return
	}
	err := s.store.RevokeAgentToken(ctx, a.AccountID, a.AgentID, in.TokenID, sess.Principal(), time.Now().UTC().Truncate(time.Second))
	if errors.Is(err, store.ErrAgentTokenNotFound) {
		writeNativeError(w, http.StatusNotFound, "not_found", "token not found")
		return
	}
	if err != nil {
		log.Printf("agents: revoke token failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "revoke_failed", "could not revoke the token")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.RevokeAgentToken", KeyID: in.TokenID, Result: "ok", AuditOrigin: s.agentOrigin(r, a)})
	writeNativeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

// ---- federation bindings ----------------------------------------------------

type agentBindingRequest struct {
	AgentID     string `json:"agentId"`
	Issuer      string `json:"issuer"`
	Subject     string `json:"subject"`
	Audience    string `json:"audience"`
	Description string `json:"description"`
}

// validBindingIssuer checks the issuer is Citadel's workload issuer or an
// IAM OIDC provider registered in the account.
func (s *Server) validBindingIssuer(ctx context.Context, acct, iss string) string {
	u, err := url.Parse(iss)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Scheme != "https" && !(u.Scheme == "http" && s.insecureIdentityURLs())) {
		return "issuer must be an https URL"
	}
	if own := store.NormalizeIssuerURL(s.workloadIssuerURL()); own != "" && iss == own {
		return ""
	}
	if _, err := s.store.GetOIDCProviderByURL(ctx, acct, iss); err != nil {
		return "the issuer must be Citadel's workload identity issuer or an OIDC provider registered under IAM in this account"
	}
	return ""
}

func (s *Server) handleV1CreateAgentBinding(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var in agentBindingRequest
	if err := decodeJSONBody(r, &in); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	iss := store.NormalizeIssuerURL(in.Issuer)
	sub, aud, desc := strings.TrimSpace(in.Subject), strings.TrimSpace(in.Audience), strings.TrimSpace(in.Description)
	switch {
	case !printable(iss, maxAgentFederationField):
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "issuer is required")
		return
	case !printable(sub, maxAgentFederationField):
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "subject is required (the exact sub claim)")
		return
	case !printable(aud, maxAgentFederationField) || strings.ContainsAny(aud, " \t"):
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "audience is required (one exact aud value)")
		return
	case desc != "" && !printable(desc, maxAgentReasonLen):
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "description must be at most 256 printable characters")
		return
	}
	a, ok := s.loadManagedAgent(w, r, ctx, sess, strings.TrimSpace(in.AgentID), auditCreateAgentBinding)
	if !ok {
		return
	}
	if a.Status == store.AgentStatusRevoked {
		writeNativeError(w, http.StatusConflict, "agent_revoked", "a revoked agent can't be changed")
		return
	}
	if msg := s.validBindingIssuer(ctx, a.AccountID, iss); msg != "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", msg)
		return
	}
	if existing, err := s.store.ListAgentBindings(ctx, a.AccountID, a.AgentID); err == nil && len(existing) >= maxAgentBindings {
		writeNativeError(w, http.StatusConflict, "limit_exceeded", "the agent has the maximum of 20 bindings")
		return
	}
	b := store.AgentBinding{
		AccountID: a.AccountID, AgentID: a.AgentID, BindingID: store.NewAgentObjectID("abd_"), Issuer: iss, Subject: sub, Audience: aud,
		Description: desc, CreatedAt: time.Now().UTC().Truncate(time.Second), CreatedBy: sess.Principal(),
	}
	if err := s.store.CreateAgentBinding(ctx, b); err != nil {
		if errors.Is(err, store.ErrAgentBindingExists) {
			writeNativeError(w, http.StatusConflict, "already_exists", "the agent already has that binding")
			return
		}
		log.Printf("agents: create binding failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "create_failed", "could not create the binding")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.CreateAgentBinding", KeyID: b.BindingID, Result: "ok", AuditOrigin: s.agentOrigin(r, a)})
	writeNativeJSON(w, http.StatusCreated, agentBindingOut(b))
}

func (s *Server) handleV1DeleteAgentBinding(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	q := r.URL.Query()
	bindingID := strings.TrimSpace(q.Get("bindingId"))
	if !agentObjectIDRe.MatchString(bindingID) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "agentId and bindingId are required")
		return
	}
	a, ok := s.loadManagedAgent(w, r, ctx, sess, strings.TrimSpace(q.Get("agentId")), auditDeleteAgentBinding)
	if !ok {
		return
	}
	err := s.store.DeleteAgentBinding(ctx, a.AccountID, a.AgentID, bindingID)
	if errors.Is(err, store.ErrAgentBindingNotFound) {
		writeNativeError(w, http.StatusNotFound, "not_found", "binding not found")
		return
	}
	if err != nil {
		log.Printf("agents: delete binding failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "delete_failed", "could not delete the binding")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.DeleteAgentBinding", KeyID: bindingID, Result: "ok", AuditOrigin: s.agentOrigin(r, a)})
	writeNativeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// ---- grants -----------------------------------------------------------------

type agentGrantRequest struct {
	AgentID        string           `json:"agentId"`
	Credential     string           `json:"credential"`
	Actions        []string         `json:"actions"`
	NotBefore      string           `json:"notBefore"`
	NotAfter       string           `json:"notAfter"`
	Window         *agentWindowJSON `json:"window"`
	MaxUsesPerHour int              `json:"maxUsesPerHour"`
	// RequiresApproval and LeaseTTLSeconds (2.3); omitted means not set.
	RequiresApproval *bool `json:"requiresApproval"`
	LeaseTTLSeconds  *int  `json:"leaseTtlSeconds"`

	// Scope narrows minted tokens (2.4).
	Scope *store.AgentGrantScope `json:"scope"`
}

// validateAgentGrant checks in against cred and fills g.
func validateAgentGrant(in agentGrantRequest, cred store.AgentCredential, g *store.AgentGrant) string {
	actions := in.Actions
	if len(actions) == 0 {
		actions = []string{store.AgentActionUse}
	}
	g.Actions = nil
	for _, a := range actions {
		switch a {
		case store.AgentActionUse, store.AgentActionReveal, store.AgentActionTOTP:
		default:
			return "actions must be use, reveal or totp"
		}
		if !slices.Contains(g.Actions, a) {
			g.Actions = append(g.Actions, a)
		}
	}
	sort.Strings(g.Actions)
	if g.HasAction(store.AgentActionTOTP) && cred.Kind != store.AgentCredentialLogin {
		return "totp can only be granted on login credentials"
	}
	if g.HasAction(store.AgentActionUse) && cred.Kind == store.AgentCredentialRaw {
		return "raw credentials can only be revealed; grant reveal instead of use"
	}
	parse := func(v, name string) (*time.Time, string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return nil, ""
		}
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return nil, name + " must be an RFC 3339 timestamp"
		}
		t = t.UTC()
		return &t, ""
	}
	var msg string
	if g.NotBefore, msg = parse(in.NotBefore, "notBefore"); msg != "" {
		return msg
	}
	if g.NotAfter, msg = parse(in.NotAfter, "notAfter"); msg != "" {
		return msg
	}
	if g.NotBefore != nil && g.NotAfter != nil && !g.NotAfter.After(*g.NotBefore) {
		return "notAfter must be after notBefore"
	}
	g.WindowStart, g.WindowEnd, g.WindowDays, g.Timezone = "", "", nil, ""
	if w := in.Window; w != nil {
		start, end := strings.TrimSpace(w.Start), strings.TrimSpace(w.End)
		if (start == "") != (end == "") {
			return "a window needs both start and end (HH:MM)"
		}
		if start != "" {
			if _, ok := parseHHMM(start); !ok {
				return "window start must be HH:MM"
			}
			if _, ok := parseHHMM(end); !ok {
				return "window end must be HH:MM"
			}
		}
		for _, d := range w.Days {
			d = strings.ToLower(strings.TrimSpace(d))
			if !slices.Contains(weekdayNames, d) {
				return "window days must be sun, mon, tue, wed, thu, fri or sat"
			}
			if !slices.Contains(g.WindowDays, d) {
				g.WindowDays = append(g.WindowDays, d)
			}
		}
		tz := strings.TrimSpace(w.Timezone)
		if tz != "" {
			if len(tz) > 64 {
				return "timezone must be an IANA time zone such as Europe/Dublin"
			}
			if _, err := time.LoadLocation(tz); err != nil {
				return "timezone must be an IANA time zone such as Europe/Dublin"
			}
		}
		if start != "" || len(g.WindowDays) > 0 {
			g.WindowStart, g.WindowEnd, g.Timezone = start, end, tz
		}
	}
	if in.MaxUsesPerHour < 0 || in.MaxUsesPerHour > maxAgentGrantUsesPerHr {
		return "maxUsesPerHour must be 0 (unlimited) to 100000"
	}
	g.MaxUsesPerHour = in.MaxUsesPerHour
	g.RequiresApproval, g.LeaseTTLSeconds = nil, nil
	if in.RequiresApproval != nil && *in.RequiresApproval {
		v := true
		g.RequiresApproval = &v
	}
	if in.LeaseTTLSeconds != nil && *in.LeaseTTLSeconds != 0 {
		ttl := *in.LeaseTTLSeconds
		if ttl < minAgentLeaseSeconds || ttl > maxAgentLeaseSeconds {
			return "leaseTtlSeconds must be 0 (not set) or 60 to 86400"
		}
		g.LeaseTTLSeconds = &ttl
	}
	return validateAgentGrantScope(in.Scope, cred, g)
}

func (s *Server) handleV1PutAgentGrant(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var in agentGrantRequest
	if err := decodeJSONBody(r, &in); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	in.Credential = strings.TrimSpace(in.Credential)
	if !agentCredNameRe.MatchString(in.Credential) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "credential is required")
		return
	}
	a, ok := s.loadManagedAgent(w, r, ctx, sess, strings.TrimSpace(in.AgentID), auditPutAgentGrant)
	if !ok {
		return
	}
	if a.Status == store.AgentStatusRevoked {
		writeNativeError(w, http.StatusConflict, "agent_revoked", "a revoked agent can't be granted access")
		return
	}
	cred, err := s.store.GetAgentCredential(ctx, a.AccountID, in.Credential)
	if errors.Is(err, store.ErrAgentCredentialNotFound) {
		writeNativeError(w, http.StatusNotFound, "not_found", "no agent credential with that name; add a usage profile on the secret first")
		return
	}
	if err != nil {
		log.Printf("agents: credential read failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "internal_error", "could not save the grant")
		return
	}
	now := time.Now().UTC().Truncate(time.Second)
	g := store.AgentGrant{AccountID: a.AccountID, GrantID: store.NewAgentObjectID("agr_"), AgentID: a.AgentID, Credential: cred.Name,
		CreatedAt: now, CreatedBy: sess.Principal(), UpdatedAt: now, UpdatedBy: sess.Principal()}
	if msg := validateAgentGrant(in, cred, &g); msg != "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", msg)
		return
	}
	stored, err := s.store.PutAgentGrant(ctx, g)
	if err != nil {
		log.Printf("agents: save grant failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "save_failed", "could not save the grant")
		return
	}
	// The key names the credential and the actions: a grant of reveal stands
	// out in the log.
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.PutAgentGrant", KeyID: stored.Credential + ":" + strings.Join(stored.Actions, ","), Result: "ok", AuditOrigin: s.agentOrigin(r, a)})
	out := agentGrantOut(stored, now)
	out.AgentName = a.Name
	writeNativeJSON(w, http.StatusOK, out)
}

func (s *Server) handleV1DeleteAgentGrant(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	q := r.URL.Query()
	grantID := strings.TrimSpace(q.Get("grantId"))
	if !agentObjectIDRe.MatchString(grantID) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "agentId and grantId are required")
		return
	}
	a, ok := s.loadManagedAgent(w, r, ctx, sess, strings.TrimSpace(q.Get("agentId")), auditDeleteAgentGrant)
	if !ok {
		return
	}
	err := s.store.DeleteAgentGrant(ctx, a.AccountID, a.AgentID, grantID)
	if errors.Is(err, store.ErrAgentGrantNotFound) {
		writeNativeError(w, http.StatusNotFound, "not_found", "grant not found")
		return
	}
	if err != nil {
		log.Printf("agents: delete grant failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "delete_failed", "could not delete the grant")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.DeleteAgentGrant", KeyID: grantID, Result: "ok", AuditOrigin: s.agentOrigin(r, a)})
	writeNativeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// ---- credential usage profiles ----------------------------------------------

type agentCredentialRequest struct {
	Name string `json:"name"`
	// Secret is a backing secret name or ARN; alternatively Project, Env,
	// Path and Key name a secret in the native hierarchy.
	Secret              string   `json:"secret"`
	Project             string   `json:"project"`
	Env                 string   `json:"env"`
	Path                string   `json:"path"`
	Key                 string   `json:"key"`
	Kind                string   `json:"kind"`
	Description         string   `json:"description"`
	AllowedHosts        []string `json:"allowedHosts"`
	AllowedMethods      []string `json:"allowedMethods"`
	AllowedPathPrefixes []string `json:"allowedPathPrefixes"`
	HeaderName          string   `json:"headerName"`
	HeaderPrefix        string   `json:"headerPrefix"`
	QueryParam          string   `json:"queryParam"`
	AllowHTTP           bool     `json:"allowHttp"`
	AllowedCIDRs        []string `json:"allowedCidrs"`

	// The kind-specific settings (2.4): login, awsSts, githubApp, oauth2.
	store.AgentCredentialConfig
}

func isHTTPKind(kind string) bool {
	switch kind {
	case store.AgentCredentialHTTPHeader, store.AgentCredentialHTTPBasic, store.AgentCredentialHTTPQuery:
		return true
	}
	return false
}

// validateAgentCredential checks in and fills c (all but name, secret and
// timestamps).
func validateAgentCredential(in agentCredentialRequest, c *store.AgentCredential) string {
	c.Kind = strings.TrimSpace(in.Kind)
	switch c.Kind {
	case store.AgentCredentialHTTPHeader, store.AgentCredentialHTTPBasic, store.AgentCredentialHTTPQuery, store.AgentCredentialLogin, store.AgentCredentialRaw,
		store.AgentCredentialAWSSTS, store.AgentCredentialGitHubApp, store.AgentCredentialOAuth2:
	default:
		return "kind must be http_header, http_basic, http_query, login, raw, aws_sts, github_app or oauth2_client_credentials"
	}
	c.Description = strings.TrimSpace(in.Description)
	if c.Description != "" && !printable(c.Description, maxAgentDescriptionLen) {
		return "description must be at most 512 printable characters"
	}
	c.AllowedHosts = nil
	if len(in.AllowedHosts) > maxAgentHosts {
		return "at most 20 allowed hosts"
	}
	for _, h := range in.AllowedHosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if !agentHostRe.MatchString(h) || len(h) > 253 {
			return "allowed hosts must be host names such as api.github.com or *.example.com (optionally with :port)"
		}
		if strings.HasPrefix(h, "*.") && !strings.Contains(strings.TrimPrefix(h, "*."), ".") {
			return "a wildcard host needs at least two labels after *. (for example *.example.com)"
		}
		if !slices.Contains(c.AllowedHosts, h) {
			c.AllowedHosts = append(c.AllowedHosts, h)
		}
	}
	if isHTTPKind(c.Kind) && len(c.AllowedHosts) == 0 {
		return "HTTP credentials need at least one allowed host"
	}
	c.AllowedMethods = nil
	for _, m := range in.AllowedMethods {
		m = strings.ToUpper(strings.TrimSpace(m))
		if !slices.Contains(agentHTTPMethods, m) {
			return "allowed methods must be GET, HEAD, POST, PUT, PATCH, DELETE or OPTIONS"
		}
		if !slices.Contains(c.AllowedMethods, m) {
			c.AllowedMethods = append(c.AllowedMethods, m)
		}
	}
	if (isHTTPKind(c.Kind) || store.IsMintedAgentKind(c.Kind)) && len(c.AllowedMethods) == 0 {
		c.AllowedMethods = []string{"GET"}
	}
	c.AllowedPathPrefixes = nil
	if len(in.AllowedPathPrefixes) > maxAgentPathPrefixes {
		return "at most 20 path prefixes"
	}
	for _, p := range in.AllowedPathPrefixes {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") || !printable(p, 256) || strings.ContainsAny(p, " ?#") {
			return "path prefixes must start with / and contain no spaces, ? or #"
		}
		if !slices.Contains(c.AllowedPathPrefixes, p) {
			c.AllowedPathPrefixes = append(c.AllowedPathPrefixes, p)
		}
	}
	c.HeaderName, c.HeaderPrefix, c.QueryParam = "", "", ""
	switch c.Kind {
	case store.AgentCredentialHTTPHeader:
		c.HeaderName = strings.TrimSpace(in.HeaderName)
		if c.HeaderName == "" {
			c.HeaderName = "Authorization"
		}
		lower := strings.ToLower(c.HeaderName)
		if !agentHeaderRe.MatchString(c.HeaderName) || slices.Contains(agentForbiddenHeaders, lower) || strings.HasPrefix(lower, "proxy-") {
			return "headerName must be a header name other than Host, Content-Length, Connection, Proxy-* and similar"
		}
		c.HeaderPrefix = in.HeaderPrefix
		if c.HeaderPrefix != "" && !printable(c.HeaderPrefix, 64) {
			return "headerPrefix must be at most 64 printable characters"
		}
	case store.AgentCredentialHTTPQuery:
		c.QueryParam = strings.TrimSpace(in.QueryParam)
		if !agentQueryRe.MatchString(c.QueryParam) {
			return "queryParam must be 1-64 letters, digits or ._~-"
		}
	}
	c.AllowHTTP = in.AllowHTTP && (isHTTPKind(c.Kind) || store.IsMintedAgentKind(c.Kind))
	c.AllowedCIDRs = nil
	if len(in.AllowedCIDRs) > maxAgentCIDRs {
		return "at most 10 allowed CIDRs"
	}
	for _, raw := range in.AllowedCIDRs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return "allowed CIDRs must be prefixes such as 10.0.0.0/8"
		}
		if v := p.Masked().String(); !slices.Contains(c.AllowedCIDRs, v) {
			c.AllowedCIDRs = append(c.AllowedCIDRs, v)
		}
	}
	return validateAgentCredentialConfig(in.AgentCredentialConfig, c)
}

// resolveCredentialSecret finds the backing secret named by in.
func (s *Server) resolveCredentialSecret(ctx context.Context, in agentCredentialRequest) (string, string) {
	id := strings.TrimSpace(in.Secret)
	if id == "" {
		coord, err := coordFromParts(in.Project, in.Env, in.Path, in.Key)
		if err != nil {
			return "", "name the secret: secret (name or ARN) or project, env and key"
		}
		id = coord.backingName()
	}
	if len(id) > 2048 {
		return "", "secret is too long"
	}
	meta, err := s.store.DescribeSecret(ctx, id)
	if err != nil {
		return "", "the secret doesn't exist in this account"
	}
	if meta.DeletedDate != nil {
		return "", "the secret is scheduled for deletion"
	}
	return meta.Name, ""
}

// attachCredentialGrants fills each credential's grants list.
func (s *Server) attachCredentialGrants(ctx context.Context, acct string, out []agentCredentialJSON) error {
	grants, err := s.store.ListAgentGrants(ctx, acct, "")
	if err != nil {
		return err
	}
	if len(grants) == 0 {
		return nil
	}
	agents, err := s.store.ListAgents(ctx, acct)
	if err != nil {
		return err
	}
	names := map[string]string{}
	for _, a := range agents {
		names[a.AgentID] = a.Name
	}
	idx := map[string]int{}
	for i, c := range out {
		idx[c.Name] = i
	}
	for _, g := range grants {
		if i, ok := idx[g.Credential]; ok {
			out[i].Grants = append(out[i].Grants, agentCredentialGrantRef{GrantID: g.GrantID, AgentID: g.AgentID, AgentName: names[g.AgentID], Actions: g.Actions})
		}
	}
	return nil
}

func (s *Server) handleV1ListAgentCredentials(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	q := r.URL.Query()
	secret := strings.TrimSpace(q.Get("secret"))
	if secret == "" && q.Get("project") != "" {
		coord, err := coordFromQuery(q)
		if err != nil {
			writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		secret = coord.backingName()
	}
	acct := s.agentAccount(ctx, sess)
	creds, err := s.store.ListAgentCredentials(ctx, acct)
	if err != nil {
		log.Printf("agents: list credentials failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "list_failed", "could not list agent credentials")
		return
	}
	out := make([]agentCredentialJSON, 0, len(creds))
	for _, c := range creds {
		if secret == "" || c.SecretName == secret {
			out = append(out, agentCredentialOut(c))
		}
	}
	if err := s.attachCredentialGrants(ctx, acct, out); err != nil {
		log.Printf("agents: list grants failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "list_failed", "could not list agent credentials")
		return
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"credentials": out, "canEdit": uiCanEdit(sess)})
}

func (s *Server) handleV1CreateAgentCredential(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var in agentCredentialRequest
	if err := decodeJSONBody(r, &in); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	name := strings.TrimSpace(in.Name)
	if !agentCredNameRe.MatchString(name) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "name must be 1-63 lowercase letters, digits, dots, dashes or underscores")
		return
	}
	now := time.Now().UTC().Truncate(time.Second)
	c := store.AgentCredential{AccountID: s.agentAccount(ctx, sess), Name: name, CreatedAt: now, CreatedBy: sess.Principal(), UpdatedAt: now, UpdatedBy: sess.Principal()}
	if msg := validateAgentCredential(in, &c); msg != "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", msg)
		return
	}
	secretName, msg := s.resolveCredentialSecret(ctx, in)
	if msg != "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", msg)
		return
	}
	c.SecretName = secretName
	if err := s.store.CreateAgentCredential(ctx, c); err != nil {
		if errors.Is(err, store.ErrAgentCredentialExists) {
			writeNativeError(w, http.StatusConflict, "already_exists", "an agent credential with that name already exists")
			return
		}
		log.Printf("agents: create credential failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "create_failed", "could not create the agent credential")
		return
	}
	o := s.auditOrigin(r)
	o.Resource = c.SecretName
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.CreateAgentCredential", KeyID: c.Name, Result: "ok", AuditOrigin: o})
	writeNativeJSON(w, http.StatusCreated, agentCredentialOut(c))
}

func (s *Server) handleV1UpdateAgentCredential(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var in agentCredentialRequest
	if err := decodeJSONBody(r, &in); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	acct := s.agentAccount(ctx, sess)
	cur, err := s.store.GetAgentCredential(ctx, acct, strings.TrimSpace(in.Name))
	if errors.Is(err, store.ErrAgentCredentialNotFound) {
		writeNativeError(w, http.StatusNotFound, "not_found", "agent credential not found")
		return
	}
	if err != nil {
		log.Printf("agents: credential read failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "update_failed", "could not update the agent credential")
		return
	}
	c := cur
	if msg := validateAgentCredential(in, &c); msg != "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", msg)
		return
	}
	if in.Secret != "" || in.Project != "" {
		name, msg := s.resolveCredentialSecret(ctx, in)
		if msg != "" {
			writeNativeError(w, http.StatusBadRequest, "invalid_request", msg)
			return
		}
		c.SecretName = name
	}
	// Changing the kind can invalidate existing grants' actions, and
	// changing a minted credential's settings their scopes.
	if grants, err := s.store.ListAgentGrants(ctx, acct, ""); err == nil {
		for _, g := range grants {
			if g.Credential != c.Name {
				continue
			}
			if c.Kind != cur.Kind && ((g.HasAction(store.AgentActionTOTP) && c.Kind != store.AgentCredentialLogin) || (g.HasAction(store.AgentActionUse) && c.Kind == store.AgentCredentialRaw)) {
				writeNativeError(w, http.StatusConflict, "grants_conflict", "existing grants use actions this kind doesn't support; change them first")
				return
			}
			scope := g.Scope.Clone()
			if msg := checkAgentGrantScope(&scope, c); msg != "" {
				writeNativeError(w, http.StatusConflict, "grants_conflict", "an existing grant's scope would no longer fit: "+msg)
				return
			}
		}
	}
	c.UpdatedAt, c.UpdatedBy = time.Now().UTC().Truncate(time.Second), sess.Principal()
	if err := s.store.UpdateAgentCredential(ctx, c); err != nil {
		log.Printf("agents: update credential failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "update_failed", "could not update the agent credential")
		return
	}
	o := s.auditOrigin(r)
	o.Resource = c.SecretName
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.UpdateAgentCredential", KeyID: c.Name, Result: "ok", AuditOrigin: o})
	out := []agentCredentialJSON{agentCredentialOut(c)}
	_ = s.attachCredentialGrants(ctx, acct, out)
	writeNativeJSON(w, http.StatusOK, out[0])
}

func (s *Server) handleV1DeleteAgentCredential(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if !agentCredNameRe.MatchString(name) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "name is required")
		return
	}
	err := s.store.DeleteAgentCredential(ctx, s.agentAccount(ctx, sess), name)
	switch {
	case errors.Is(err, store.ErrAgentCredentialNotFound):
		writeNativeError(w, http.StatusNotFound, "not_found", "agent credential not found")
		return
	case errors.Is(err, store.ErrAgentCredentialInUse):
		writeNativeError(w, http.StatusConflict, "in_use", "agents have grants for this credential; remove them first")
		return
	case err != nil:
		log.Printf("agents: delete credential failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "delete_failed", "could not delete the agent credential")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.DeleteAgentCredential", KeyID: name, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// ---- kill switch ------------------------------------------------------------

func (s *Server) handleV1GetAgentSettings(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	st, err := s.store.GetAgentSettings(ctx, s.agentAccount(ctx, sess))
	if err != nil {
		log.Printf("agents: settings read failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "internal_error", "could not load agent settings")
		return
	}
	writeNativeJSON(w, http.StatusOK, agentSettingsOut(st))
}

type agentSettingsRequest struct {
	AgentsSuspended bool   `json:"agentsSuspended"`
	Reason          string `json:"reason"`
}

// handleV1PutAgentSettings turns the account-wide kill switch on or off.
// While on, every agent in the account is refused (agents_suspended); each
// agent's own status is kept, so turning it off restores the previous state.
func (s *Server) handleV1PutAgentSettings(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	var in agentSettingsRequest
	if err := decodeJSONBody(r, &in); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	reason, okReason := validReason(in.Reason)
	if !okReason {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "reason must be at most 256 printable characters")
		return
	}
	acct := s.agentAccount(ctx, sess)
	now := time.Now().UTC().Truncate(time.Second)
	st := store.AgentSettings{AccountID: acct, AgentsSuspended: in.AgentsSuspended, UpdatedAt: now}
	if in.AgentsSuspended {
		st.SuspendedAt, st.SuspendedBy, st.Reason = &now, sess.Principal(), reason
	}
	if err := s.store.PutAgentSettings(ctx, st); err != nil {
		log.Printf("agents: settings save failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "save_failed", "could not save agent settings")
		return
	}
	if in.AgentsSuspended {
		s.recordAudit(ctx, store.AuditEvent{Action: "citadel.SuspendAllAgents", KeyID: acct, Result: "ok", AuditOrigin: s.auditOrigin(r)})
		s.endAccountLeases(ctx, r, acct, sess.Principal())
	} else {
		s.recordAudit(ctx, store.AuditEvent{Action: "citadel.ResumeAllAgents", KeyID: acct, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	}
	writeNativeJSON(w, http.StatusOK, agentSettingsOut(st))
}

// ---- agent-facing -----------------------------------------------------------

func (s *Server) handleV1AgentWhoAmI(w http.ResponseWriter, r *http.Request) {
	p, ctx, ok := s.agentRequest(w, r, auditAgentWhoAmI)
	if !ok {
		return
	}
	out := map[string]any{
		"agentId": p.Agent.AgentID, "name": p.Agent.Name, "owner": p.Agent.Owner, "accountId": p.AccountID,
		"status": p.Agent.Status, "authMethod": p.Method,
	}
	if p.TokenID != "" {
		out["tokenId"] = p.TokenID
	}
	if p.TokenExpiresAt != nil {
		out["tokenExpiresAt"] = fmtTime(*p.TokenExpiresAt)
	}
	if p.BindingID != "" {
		out["bindingId"] = p.BindingID
	}
	if p.TaskID != "" {
		out["taskId"] = p.TaskID
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.AgentWhoAmI", KeyID: p.Agent.AgentID, Result: "ok", AuditOrigin: s.agentAuditOrigin(r, p)})
	writeNativeJSON(w, http.StatusOK, out)
}

type agentUsableCredentialJSON struct {
	Name                string   `json:"name"`
	Kind                string   `json:"kind"`
	Description         string   `json:"description"`
	AllowedHosts        []string `json:"allowedHosts"`
	AllowedMethods      []string `json:"allowedMethods"`
	AllowedPathPrefixes []string `json:"allowedPathPrefixes"`
	Actions             []string `json:"actions"`
	MaxUsesPerHour      int      `json:"maxUsesPerHour"`
	NotAfter            string   `json:"notAfter,omitempty"`
	// RequiresApproval: uses need an approved access request (2.3).
	RequiresApproval bool `json:"requiresApproval"`
	// Usable is false when the grant's dates or window exclude now, or the
	// secret behind the credential is gone; Reason says why.
	Usable bool   `json:"usable"`
	Reason string `json:"reason,omitempty"`
	// URLPatterns are the pages a login may be used on (2.4).
	URLPatterns []string `json:"urlPatterns,omitempty"`
}

// handleV1AgentCredentials lists the credentials the calling agent has
// grants for: names, kinds and where they may be used. Never values.
func (s *Server) handleV1AgentCredentials(w http.ResponseWriter, r *http.Request) {
	p, ctx, ok := s.agentRequest(w, r, auditAgentListCredentials)
	if !ok {
		return
	}
	grants, err := s.store.ListAgentGrants(ctx, p.AccountID, p.Agent.AgentID)
	if err != nil {
		log.Printf("agent credentials: grants read failed: %v", err)
		writeAgentError(w, http.StatusInternalServerError, "list_failed", "", "could not list credentials")
		return
	}
	now := time.Now().UTC()
	out := make([]agentUsableCredentialJSON, 0, len(grants))
	for _, g := range grants {
		c, err := s.store.GetAgentCredential(ctx, p.AccountID, g.Credential)
		if err != nil {
			continue
		}
		j := agentCredentialOut(c)
		item := agentUsableCredentialJSON{
			Name: c.Name, Kind: c.Kind, Description: c.Description, AllowedHosts: j.AllowedHosts, AllowedMethods: j.AllowedMethods,
			AllowedPathPrefixes: j.AllowedPathPrefixes, Actions: g.Actions, MaxUsesPerHour: g.MaxUsesPerHour, NotAfter: fmtTimePtr(g.NotAfter),
			RequiresApproval: g.RequiresApproval != nil && *g.RequiresApproval, URLPatterns: loginURLPatterns(c),
		}
		item.Reason = agentGrantStatus(g, now)
		if item.Reason == "" {
			if _, err := s.agentSecretRef(ctx, p.AccountID, c.SecretName); err != nil {
				item.Reason = agentDenyCredentialUnavailable
			}
		}
		item.Usable = item.Reason == ""
		out = append(out, item)
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.AgentListCredentials", KeyID: p.Agent.AgentID, Result: "ok", AuditOrigin: s.agentAuditOrigin(r, p)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"credentials": out})
}
