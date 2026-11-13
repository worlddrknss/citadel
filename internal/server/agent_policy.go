package server

import (
	"context"
	"errors"
	"log"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // grant time windows name IANA zones; distroless images have no zoneinfo

	"github.com/worlddrknss/citadel/internal/ratelimit"
	"github.com/worlddrknss/citadel/internal/store"
)

// Agent access policy (2.2).
//
// s.evaluateAgentAccess decides whether an agent may perform an action
// (use, reveal, totp) with a named credential right now, and returns the
// grant, the credential's usage profile and a reference to the backing
// secret. The broker, reveal and MCP tools call it on every use; a "use" or
// "reveal" that is allowed counts against the grant's maxUsesPerHour.
//
// Checks, in order: the agent is active and the account's kill switch is
// off; the credential exists and the agent has a grant for it (both report
// no_grant, so an agent cannot discover credentials it was not given); the
// action is granted; notBefore/notAfter; the time-of-day window; leases and
// approvals (agent_access.go: a lease from an approved request can stand in
// for a missing grant or action, and a requiresApproval grant needs one);
// the backing secret exists and is not scheduled for deletion; the rate
// limit; finally the lease is used.

// AgentDecision is the outcome of an access check.
type AgentDecision struct {
	Allowed bool
	// Reason is a stable denial code (one of the agentDeny* constants), ""
	// when allowed.
	Reason string
	// RetryAfter is set for rate_limited.
	RetryAfter time.Duration
	// RequestID is the pending access request for approval_required (2.3);
	// "" when the agent has too many pending requests.
	RequestID string
	// LeaseID and LeaseExpiresAt name the lease an allowed use was made
	// under ("" when none).
	LeaseID        string
	LeaseExpiresAt time.Time
}

// Denial reasons for evaluateAgentAccess. The agent sees them, so none
// reveals anything about credentials the agent was not granted.
const (
	agentDenyAgentSuspended        = agentReasonAgentSuspended
	agentDenyAgentRevoked          = agentReasonAgentRevoked
	agentDenyAgentsSuspended       = agentReasonAgentsSuspended
	agentDenyNoGrant               = "no_grant"
	agentDenyActionNotGranted      = "action_not_granted"
	agentDenyNotYetValid           = "not_yet_valid"
	agentDenyExpired               = "grant_expired"
	agentDenyOutsideWindow         = "outside_window"
	agentDenyRateLimited           = "rate_limited"
	agentDenyCredentialUnavailable = "credential_unavailable"
	agentDenyInvalidAction         = "invalid_action"
	agentDenyInternal              = "internal_error"
)

// agentSecretRef names the secret behind a credential.
type agentSecretRef struct {
	// SecretName is the backing Secrets Manager name.
	SecretName string
	ARN        string
	// Project, Env, Path and Key are set for secrets in the native
	// hierarchy.
	Project, Env, Path, Key string
}

func deny(reason string) AgentDecision { return AgentDecision{Reason: reason} }

// evaluateAgentAccess checks agent's access to credentialName for action at
// now. On allow it consumes one use of the grant's hourly limit (for use and
// reveal).
func (s *Server) evaluateAgentAccess(ctx context.Context, agent store.Agent, credentialName, action string, now time.Time) (store.AgentGrant, store.AgentCredential, agentSecretRef, AgentDecision) {
	var (
		grant store.AgentGrant
		cred  store.AgentCredential
		ref   agentSecretRef
	)
	switch action {
	case store.AgentActionUse, store.AgentActionReveal, store.AgentActionTOTP:
	default:
		return grant, cred, ref, deny(agentDenyInvalidAction)
	}
	// Re-read the agent: a suspension between authentication and use wins.
	cur, err := s.store.GetAgent(ctx, agent.AccountID, agent.AgentID)
	if err != nil {
		if errors.Is(err, store.ErrAgentNotFound) {
			return grant, cred, ref, deny(agentDenyAgentRevoked)
		}
		log.Printf("agent policy: agent read failed: %v", err)
		return grant, cred, ref, deny(agentDenyInternal)
	}
	if err := s.agentActive(ctx, &cur); err != nil {
		var ae *agentAuthError
		if errors.As(err, &ae) && ae.reason != "lookup_failed" {
			return grant, cred, ref, deny(ae.reason)
		}
		return grant, cred, ref, deny(agentDenyInternal)
	}
	grants, err := s.store.ListAgentGrants(ctx, cur.AccountID, cur.AgentID)
	if err != nil {
		log.Printf("agent policy: grants read failed: %v", err)
		return grant, cred, ref, deny(agentDenyInternal)
	}
	found := false
	for _, g := range grants {
		if g.Credential == credentialName {
			grant, found = g, true
			break
		}
	}
	cred, err = s.store.GetAgentCredential(ctx, cur.AccountID, credentialName)
	if err != nil {
		if errors.Is(err, store.ErrAgentCredentialNotFound) {
			return grant, cred, ref, deny(agentDenyNoGrant)
		}
		log.Printf("agent policy: credential read failed: %v", err)
		return grant, cred, ref, deny(agentDenyInternal)
	}
	// Without a grant for the action, only a lease from an approved access
	// request can allow it (2.3).
	grantReason := ""
	switch {
	case !found:
		grantReason = agentDenyNoGrant
	case !grant.HasAction(action):
		grantReason = agentDenyActionNotGranted
	default:
		if reason := agentGrantTimeCheck(grant, now); reason != "" {
			return grant, cred, ref, deny(reason)
		}
	}
	hasGrant := grantReason == ""
	if !hasGrant {
		grant = store.AgentGrant{AccountID: cur.AccountID, AgentID: cur.AgentID, Credential: credentialName}
	}
	decision, useLease := s.agentLeaseGate(ctx, cur, credentialName, grant, hasGrant, grantReason, action, now)
	if !decision.Allowed {
		return grant, cred, ref, decision
	}
	ref, err = s.agentSecretRef(ctx, cur.AccountID, cred.SecretName)
	if err != nil {
		return grant, cred, ref, deny(agentDenyCredentialUnavailable)
	}
	if hasGrant && (action == store.AgentActionUse || action == store.AgentActionReveal) {
		if ok, wait := s.consumeAgentGrantUse(ctx, grant); !ok {
			return grant, cred, ref, AgentDecision{Reason: agentDenyRateLimited, RetryAfter: wait}
		}
	}
	if useLease != nil {
		decision = useLease()
	}
	return grant, cred, ref, decision
}

// agentGrantTimeCheck applies notBefore, notAfter and the time-of-day
// window; "" when the grant is valid at now.
func agentGrantTimeCheck(g store.AgentGrant, now time.Time) string {
	if g.NotBefore != nil && now.Before(*g.NotBefore) {
		return agentDenyNotYetValid
	}
	if g.NotAfter != nil && !now.Before(*g.NotAfter) {
		return agentDenyExpired
	}
	if !inAgentWindow(g, now) {
		return agentDenyOutsideWindow
	}
	return ""
}

var weekdayNames = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}

// parseHHMM returns minutes after midnight for "HH:MM".
func parseHHMM(v string) (int, bool) {
	h, m, ok := strings.Cut(v, ":")
	if !ok || len(h) != 2 || len(m) != 2 {
		return 0, false
	}
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if err1 != nil || err2 != nil || hh < 0 || hh > 23 || mm < 0 || mm > 59 {
		return 0, false
	}
	return hh*60 + mm, true
}

// inAgentWindow reports whether now falls in the grant's days and
// time-of-day window, in its timezone (UTC when unset). A window whose end is
// before its start runs past midnight; its days are the days it starts on.
func inAgentWindow(g store.AgentGrant, now time.Time) bool {
	if g.WindowStart == "" && g.WindowEnd == "" && len(g.WindowDays) == 0 {
		return true
	}
	loc := time.UTC
	if g.Timezone != "" {
		l, err := time.LoadLocation(g.Timezone)
		if err != nil {
			return false // fail closed on a zone this build can't resolve
		}
		loc = l
	}
	local := now.In(loc)
	minute := local.Hour()*60 + local.Minute()
	day := local.Weekday()
	start, end := 0, 24*60
	if g.WindowStart != "" || g.WindowEnd != "" {
		var ok1, ok2 bool
		start, ok1 = parseHHMM(g.WindowStart)
		end, ok2 = parseHHMM(g.WindowEnd)
		if !ok1 || !ok2 {
			return false
		}
	}
	inTime := false
	switch {
	case start == end:
		inTime = true
	case start < end:
		inTime = minute >= start && minute < end
	default: // overnight
		if minute >= start {
			inTime = true
		} else if minute < end {
			inTime = true
			day = (day + 6) % 7 // the window started yesterday
		}
	}
	if !inTime {
		return false
	}
	if len(g.WindowDays) == 0 {
		return true
	}
	for _, d := range g.WindowDays {
		if d == weekdayNames[day] {
			return true
		}
	}
	return false
}

// agentSecretRef resolves a credential's backing secret; an error when it
// no longer exists or is scheduled for deletion.
func (s *Server) agentSecretRef(ctx context.Context, accountID, secretName string) (agentSecretRef, error) {
	ctx = store.WithCallerAccount(ctx, accountID)
	meta, err := s.store.DescribeSecret(ctx, secretName)
	if err != nil {
		return agentSecretRef{}, err
	}
	if meta.DeletedDate != nil {
		return agentSecretRef{}, store.ErrSecretPendingDeletion
	}
	ref := agentSecretRef{SecretName: meta.Name, ARN: meta.ARN}
	if pi, ok := parseSecretName(meta.Name); ok {
		ref.Project, ref.Env, ref.Path, ref.Key = pi.Project, pi.Env, strings.Join(pi.Folder, "/"), pi.Key
	}
	return ref, nil
}

// agentSecretValue reads the current value behind ref. Callers must never
// log, audit or return it except as the credential's usage allows.
func (s *Server) agentSecretValue(ctx context.Context, accountID string, ref agentSecretRef) (string, error) {
	ctx = store.WithCallerAccount(ctx, accountID)
	v, err := s.store.GetSecretValue(ctx, ref.SecretName, "", store.CurrentVersionStage)
	if err != nil {
		return "", err
	}
	if v.SecretString != nil {
		return *v.SecretString, nil
	}
	return v.SecretBinary, nil
}

// consumeAgentGrantUse counts one use against the grant's hourly limit: the
// replica's token bucket first, then the deployment-wide counter.
func (s *Server) consumeAgentGrantUse(ctx context.Context, g store.AgentGrant) (bool, time.Duration) {
	if g.MaxUsesPerHour <= 0 {
		return true, 0
	}
	rt := s.agentRT()
	key := g.GrantID + "|" + strconv.Itoa(g.MaxUsesPerHour)
	rt.mu.Lock()
	l, ok := rt.grants[key]
	if !ok {
		if len(rt.grants) >= agentTokenCacheMax {
			rt.grants = map[string]*ratelimit.Limiter{}
		}
		l = ratelimit.New(time.Hour/time.Duration(g.MaxUsesPerHour), g.MaxUsesPerHour)
		rt.grants[key] = l
	}
	rt.mu.Unlock()
	if ok, wait := l.Reserve(g.GrantID); !ok {
		return false, wait
	}
	limit := sharedLimit{Name: "agent-grant", Limit: int64(g.MaxUsesPerHour), Window: time.Hour}
	return s.sharedAllow(ctx, sharedLimitCheck{limit, g.GrantID})
}

// agentGrantStatus is evaluateAgentAccess without consuming a use and
// without reading the secret, for listings: "" when the grant is usable now,
// otherwise the reason it is not.
func agentGrantStatus(g store.AgentGrant, now time.Time) string {
	return agentGrantTimeCheck(g, now)
}
