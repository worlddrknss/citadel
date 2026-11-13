package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// Just-in-time agent access (2.3): approvals and leases.
//
// evaluateAgentAccess (agent_policy.go) calls agentLeaseGate after the
// grant checks:
//
//   - A grant with requiresApproval needs a lease. Without one the decision
//     is approval_required with the ID of a pending access request, opened
//     (or reused: one per agent, credential, action and task ID) and
//     announced through the agent.approval_requested notification.
//   - A grant with leaseTtl (and no requiresApproval) opens a lease of that
//     length on first use; later uses within it are attributed to it.
//   - Without a grant (or without the action in it) only a lease from an
//     approved request (POST /v1/agent/access-requests, MCP request_access)
//     allows the action.
//
// Leases are used atomically in the store (a single-use lease can't be used
// twice). People approve in the console only: never with an access key, and
// only the agent's owner (an editor) or an account admin; with the
// organization's requireMFA on, a password session confirms with a current
// code. Approvals create a lease scoped once (one use), duration, or task
// (bound to the request's task ID), never longer than 24 hours, the grant's
// leaseTtl or its notAfter.

const (
	agentDenyApprovalRequired = "approval_required"

	minAgentLeaseSeconds     = 60
	maxAgentLeaseSeconds     = 24 * 60 * 60
	defaultAgentLeaseSeconds = 60 * 60
	// agentRequestTTL is how long a pending request waits for a decision.
	agentRequestTTL = time.Hour
	// maxPendingAgentRequests bounds an agent's open requests.
	maxPendingAgentRequests = 20
	maxAgentRequestReason   = 512
	// agentLeasePolicyActor is CreatedBy for leases opened by a leaseTtl.
	agentLeasePolicyActor = "policy"
)

// Audit actions.
const (
	auditAgentRequestAccess    = "citadel.AgentRequestAccess"
	auditAgentGetAccessRequest = "citadel.AgentGetAccessRequest"
	auditAgentListLeases       = "citadel.AgentListLeases"
	auditApproveAgentAccess    = "citadel.ApproveAgentAccess"
	auditDenyAgentAccess       = "citadel.DenyAgentAccess"
	auditRevokeAgentLease      = "citadel.RevokeAgentLease"
)

// agentLeaseGate applies leases and approvals to an access check that
// passed the grant's own checks (or found no grant: hasGrant false, and
// then grantReason is the denial to use when no lease applies). It returns
// the decision so far and, when a lease is needed, a function that uses it
// atomically once the remaining checks (secret, rate limit) pass.
func (s *Server) agentLeaseGate(ctx context.Context, agent store.Agent, credential string, grant store.AgentGrant, hasGrant bool, grantReason, action string, now time.Time) (AgentDecision, func() AgentDecision) {
	taskID := ""
	if p, ok := agentPrincipalFrom(ctx); ok {
		taskID = p.TaskID
	}
	match := store.AgentLeaseMatch{AccountID: agent.AccountID, AgentID: agent.AgentID, Credential: credential, Action: action, TaskID: taskID, Now: now}
	requiresApproval := hasGrant && grant.RequiresApproval != nil && *grant.RequiresApproval
	switch {
	case !hasGrant || requiresApproval:
		if _, ok, err := s.store.FindAgentLease(ctx, match); err != nil {
			log.Printf("agent policy: lease lookup failed: %v", err)
			return deny(agentDenyInternal), nil
		} else if !ok {
			if !hasGrant {
				return deny(grantReason), nil
			}
			return s.agentApprovalRequired(ctx, agent, credential, action, taskID, now), nil
		}
		return AgentDecision{Allowed: true}, func() AgentDecision {
			l, ok, err := s.store.ConsumeAgentLease(ctx, match)
			switch {
			case err != nil:
				log.Printf("agent policy: lease use failed: %v", err)
				return deny(agentDenyInternal)
			case !ok && !hasGrant:
				return deny(grantReason)
			case !ok:
				// Used up by a concurrent request.
				return s.agentApprovalRequired(ctx, agent, credential, action, taskID, now)
			}
			return AgentDecision{Allowed: true, LeaseID: l.LeaseID, LeaseExpiresAt: l.ExpiresAt}
		}
	case grant.LeaseTTLSeconds != nil && *grant.LeaseTTLSeconds > 0:
		return AgentDecision{Allowed: true}, func() AgentDecision {
			l, ok, err := s.store.ConsumeAgentLease(ctx, match)
			if err != nil {
				log.Printf("agent policy: lease use failed: %v", err)
				return deny(agentDenyInternal)
			}
			if !ok {
				if l, err = s.openPolicyLease(ctx, agent, grant, action, now); err != nil {
					log.Printf("agent policy: open lease failed: %v", err)
					return deny(agentDenyInternal)
				}
			}
			return AgentDecision{Allowed: true, LeaseID: l.LeaseID, LeaseExpiresAt: l.ExpiresAt}
		}
	}
	return AgentDecision{Allowed: true}, nil
}

// openPolicyLease opens the lease a leaseTtl grant gives on first use. It
// covers the grant's actions, starts with this use counted, and ends at the
// TTL or the grant's notAfter, whichever is first.
func (s *Server) openPolicyLease(ctx context.Context, agent store.Agent, grant store.AgentGrant, action string, now time.Time) (store.AgentLease, error) {
	exp := now.Add(time.Duration(*grant.LeaseTTLSeconds) * time.Second)
	if grant.NotAfter != nil && grant.NotAfter.Before(exp) {
		exp = *grant.NotAfter
	}
	used := now
	l := store.AgentLease{
		AccountID: agent.AccountID, LeaseID: store.NewAgentLeaseID(), AgentID: agent.AgentID, Credential: grant.Credential,
		Actions: grant.Actions, Scope: store.AgentLeaseDuration, UseCount: 1, LastUsedAt: &used, ExpiresAt: exp.UTC(),
		CreatedAt: now, CreatedBy: agentLeasePolicyActor,
	}
	if err := s.store.CreateAgentLease(ctx, l); err != nil {
		return store.AgentLease{}, err
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.CreateAgentLease", KeyID: l.LeaseID, Result: "ok",
		AuditOrigin: store.AuditOrigin{Resource: "credential=" + l.Credential + " scope=duration by=policy"}})
	return l, nil
}

// agentApprovalRequired opens (or finds) the pending request for a use
// that needs approval and returns the approval_required decision.
func (s *Server) agentApprovalRequired(ctx context.Context, agent store.Agent, credential, action, taskID string, now time.Time) AgentDecision {
	req, _, err := s.openAgentAccessRequest(ctx, agent, store.AgentAccessRequest{
		Credential: credential, Actions: []string{action}, TaskID: taskID, Origin: store.AgentRequestOriginPolicy,
	}, now)
	if err != nil {
		if errors.Is(err, errTooManyAgentRequests) {
			return AgentDecision{Reason: agentDenyApprovalRequired}
		}
		log.Printf("agent policy: open access request failed: %v", err)
		return deny(agentDenyInternal)
	}
	return AgentDecision{Reason: agentDenyApprovalRequired, RequestID: req.RequestID}
}

var errTooManyAgentRequests = errors.New("too many pending access requests")

// openAgentAccessRequest opens r for agent, or returns the pending request
// with the same credential, actions and task ID. A new request is audited
// and announced (agent.approval_requested).
func (s *Server) openAgentAccessRequest(ctx context.Context, agent store.Agent, r store.AgentAccessRequest, now time.Time) (store.AgentAccessRequest, bool, error) {
	r.AccountID, r.AgentID, r.RequestID = agent.AccountID, agent.AgentID, store.NewAgentAccessRequestID()
	r.Status, r.CreatedAt, r.ExpiresAt = store.AgentRequestPending, now, now.Add(agentRequestTTL)
	// Reuse needs no slot; a new request does.
	if n, err := s.store.CountPendingAgentAccessRequests(ctx, agent.AccountID, agent.AgentID, now); err != nil {
		return store.AgentAccessRequest{}, false, err
	} else if n >= maxPendingAgentRequests {
		existing, err := s.store.ListAgentAccessRequests(ctx, agent.AccountID, store.AgentAccessRequestFilter{AgentID: agent.AgentID, Pending: true, Now: now})
		if err != nil {
			return store.AgentAccessRequest{}, false, err
		}
		key := store.AgentActionsKey(r.Actions)
		for _, e := range existing {
			if e.Credential == r.Credential && e.TaskID == r.TaskID && store.AgentActionsKey(e.Actions) == key {
				return e, false, nil
			}
		}
		return store.AgentAccessRequest{}, false, errTooManyAgentRequests
	}
	out, created, err := s.store.OpenAgentAccessRequest(ctx, r, now)
	if err != nil || !created {
		return out, created, err
	}
	s.recordAudit(ctx, store.AuditEvent{Action: auditAgentRequestAccess, KeyID: out.RequestID, Result: "ok",
		AuditOrigin: store.AuditOrigin{Resource: "credential=" + out.Credential + " actions=" + strings.Join(out.Actions, ",") + " origin=" + out.Origin}})
	payload := map[string]any{
		"requestId": out.RequestID, "agentId": agent.AgentID, "agentName": agent.Name, "owner": agent.Owner,
		"credential": out.Credential, "actions": out.Actions, "origin": out.Origin, "expiresAt": fmtTime(out.ExpiresAt),
		"url":     s.agentRequestURL(out.RequestID),
		"summary": agent.Name + " asks to " + strings.Join(out.Actions, "/") + " " + out.Credential,
	}
	if out.TaskID != "" {
		payload["taskId"] = out.TaskID
	}
	if out.Reason != "" {
		payload["reason"] = out.Reason
	}
	if out.DurationSeconds > 0 {
		payload["durationSeconds"] = out.DurationSeconds
	}
	if err := s.notify(context.WithoutCancel(ctx), agent.AccountID, EventAgentApprovalRequested, payload); err != nil {
		log.Printf("agent access: notify failed: %v", err)
	}
	return out, true, nil
}

// agentRequestURL is the console link to a request (relative when no public
// URL is configured).
func (s *Server) agentRequestURL(requestID string) string {
	return s.publicURL() + "/app/approvals?" + url.Values{"type": {"agent_access"}, "id": {requestID}}.Encode()
}

// endAgentAccess ends an agent's leases (suspend, revoke) and, when revoked,
// cancels its pending requests. Failures are logged: the status change has
// already happened and a suspended agent can't use a lease anyway.
func (s *Server) endAgentAccess(ctx context.Context, r *http.Request, a store.Agent, by, reason string, cancelRequests bool) {
	now := time.Now().UTC().Truncate(time.Second)
	n, err := s.store.EndAgentLeases(ctx, a.AccountID, a.AgentID, by, reason, now)
	if err != nil {
		log.Printf("agents: end leases failed: %v", err)
	} else if n > 0 {
		o := s.agentOrigin(r, a)
		o.Resource = "leases=" + strconv.Itoa(n) + " reason=" + reason
		s.recordAudit(ctx, store.AuditEvent{Action: auditRevokeAgentLease, KeyID: a.AgentID, Result: "ok", AuditOrigin: o})
	}
	if cancelRequests {
		if _, err := s.store.CancelAgentAccessRequests(ctx, a.AccountID, a.AgentID, by, reason, now); err != nil {
			log.Printf("agents: cancel requests failed: %v", err)
		}
	}
}

// endAccountLeases ends every lease in the account (the kill switch).
func (s *Server) endAccountLeases(ctx context.Context, r *http.Request, acct, by string) {
	n, err := s.store.EndAgentLeases(ctx, acct, "", by, "kill switch", time.Now().UTC().Truncate(time.Second))
	if err != nil {
		log.Printf("agents: end leases failed: %v", err)
		return
	}
	if n > 0 {
		o := s.auditOrigin(r)
		o.Resource = "leases=" + strconv.Itoa(n) + " reason=kill switch"
		s.recordAudit(ctx, store.AuditEvent{Action: auditRevokeAgentLease, KeyID: acct, Result: "ok", AuditOrigin: o})
	}
}
