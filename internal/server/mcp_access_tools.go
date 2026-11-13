package server

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// MCP tools for just-in-time access (2.3): request_access asks a person for
// access (or returns the pending request), get_lease reports a request's
// decision and the agent's active leases. They share the Agent API's
// validation, audit and notifications (routes_agent_access.go).

const (
	mcpToolRequestAccess = "request_access"
	mcpToolGetLease      = "get_lease"
)

var (
	mcpRequestAccessTool = mcpTool{
		Name:  mcpToolRequestAccess,
		Title: "Request access to a credential",
		Description: "Asks a person to approve access to a credential: one this agent has no grant for, or one whose grant requires approval. " +
			"Returns a request ID; the request waits up to an hour. Check the decision with get_lease, then retry the original call.",
		InputSchema: obj(map[string]any{
			"credential": str("Name of the credential."),
			"actions":    map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": []string{"use", "reveal", "totp"}}, "description": "What you need to do with it (default [use])."},
			"reason":     str("Why you need the access; shown to the approver. Be specific."),
			"duration":   str("How long you need it, such as 15m or 2h (1 minute to 24 hours)."),
			"taskId":     str("Optional task or session ID; a task-scoped approval is bound to it."),
		}, "credential", "reason"),
		Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": false, "openWorldHint": false},
	}
	mcpGetLeaseTool = mcpTool{
		Name:        mcpToolGetLease,
		Title:       "Check an access request or lease",
		Description: "With requestId: the request's status (pending, approved, denied, expired, cancelled), the approver's comment and the lease an approval created. Without it: this agent's active leases (optionally for one credential).",
		InputSchema: obj(map[string]any{
			"requestId":  str("An access request ID from request_access or an approval_required error."),
			"credential": str("Only leases for this credential."),
		}),
		Annotations: map[string]any{"readOnlyHint": true, "openWorldHint": false},
	}
)

// mcpAccessTool handles the 2.3 tools; handled is false for other names.
func (s *Server) mcpAccessTool(ctx context.Context, r *http.Request, c *agentCaller, name string, args json.RawMessage) (*mcpToolResult, bool) {
	switch name {
	case mcpToolRequestAccess:
		var in agentAccessRequestInput
		if err := decodeArgs(args, &in); err != nil {
			return toolFailure(&agentFailure{Reason: "invalid_arguments", Message: err.Error()}), true
		}
		return s.mcpRequestAccess(ctx, r, c, in), true
	case mcpToolGetLease:
		var in struct {
			RequestID  string `json:"requestId"`
			Credential string `json:"credential"`
		}
		if err := decodeArgs(args, &in); err != nil {
			return toolFailure(&agentFailure{Reason: "invalid_arguments", Message: err.Error()}), true
		}
		return s.mcpGetLease(ctx, r, c, strings.TrimSpace(in.RequestID), strings.TrimSpace(in.Credential)), true
	}
	return nil, false
}

// mcpPrincipal is the calling agent as stored, with this call's task ID.
func (s *Server) mcpPrincipal(ctx context.Context, c *agentCaller) (*AgentPrincipal, error) {
	a, err := s.store.GetAgent(ctx, c.AccountID, c.AgentID)
	if err != nil {
		return nil, err
	}
	p := &AgentPrincipal{Agent: a, AccountID: c.AccountID, TaskID: c.TaskID}
	if orig, ok := c.ref.(*AgentPrincipal); ok {
		p.Method, p.TokenID, p.BindingID = orig.Method, orig.TokenID, orig.BindingID
	}
	return p, nil
}

func (s *Server) mcpRequestAccess(ctx context.Context, r *http.Request, c *agentCaller, in agentAccessRequestInput) *mcpToolResult {
	p, err := s.mcpPrincipal(ctx, c)
	if err != nil {
		log.Printf("mcp: load agent failed: %v", err)
		return toolFailure(&agentFailure{Reason: "internal_error", Message: "could not record the access request"})
	}
	if msg := validateAgentAccessInput(&in, c.TaskID); msg != "" {
		return toolFailure(&agentFailure{Reason: "invalid_arguments", Message: msg})
	}
	req, created, err := s.openAgentAccessRequest(ctx, p.Agent, store.AgentAccessRequest{
		Credential: in.Credential, Actions: in.Actions, Reason: in.Reason, TaskID: in.TaskID, DurationSeconds: in.DurationSeconds,
		Origin: store.AgentRequestOriginAgent,
	}, time.Now().UTC().Truncate(time.Second))
	o := s.agentAuditOrigin(r, p)
	o.Resource = "via=mcp"
	if errors.Is(err, errTooManyAgentRequests) {
		s.recordAudit(ctx, store.AuditEvent{Action: auditAgentRequestAccess, KeyID: c.AgentID, Result: store.AuditResultDenied, ErrorType: "too_many_requests", AuditOrigin: o})
		return toolFailure(&agentFailure{Reason: "too_many_requests", Message: "this agent has too many pending access requests; wait for a decision"})
	}
	if err != nil {
		log.Printf("mcp: open access request failed: %v", err)
		return toolFailure(&agentFailure{Reason: "internal_error", Message: "could not record the access request"})
	}
	if !created {
		s.recordAudit(ctx, store.AuditEvent{Action: auditAgentRequestAccess, KeyID: req.RequestID, Result: store.AuditResultSuccess, AuditOrigin: o})
	}
	return toolSuccess(s.agentRequestWithLease(r.WithContext(ctx), p, req, time.Now().UTC()))
}

func (s *Server) mcpGetLease(ctx context.Context, r *http.Request, c *agentCaller, requestID, credential string) *mcpToolResult {
	p, err := s.mcpPrincipal(ctx, c)
	if err != nil {
		log.Printf("mcp: load agent failed: %v", err)
		return toolFailure(&agentFailure{Reason: "internal_error", Message: "could not read leases"})
	}
	o := s.agentAuditOrigin(r, p)
	o.Resource = "via=mcp"
	now := time.Now().UTC()
	if requestID != "" {
		if !store.IsAgentObjectID(requestID, "aar_") {
			return toolFailure(&agentFailure{Reason: "invalid_arguments", Message: "requestId is malformed"})
		}
		req, err := s.store.GetAgentAccessRequest(ctx, c.AccountID, requestID)
		if err == nil && req.AgentID != c.AgentID {
			err = store.ErrAgentAccessRequestNotFound
		}
		if errors.Is(err, store.ErrAgentAccessRequestNotFound) {
			return toolFailure(&agentFailure{Reason: "not_found", Message: "access request not found"})
		}
		if err != nil {
			log.Printf("mcp: read access request failed: %v", err)
			return toolFailure(&agentFailure{Reason: "internal_error", Message: "could not read the access request"})
		}
		s.recordAudit(ctx, store.AuditEvent{Action: auditAgentGetAccessRequest, KeyID: req.RequestID, Result: store.AuditResultSuccess, AuditOrigin: o})
		return toolSuccess(s.agentRequestWithLease(r.WithContext(ctx), p, req, now))
	}
	if credential != "" && !agentCredNameRe.MatchString(credential) {
		return toolFailure(&agentFailure{Reason: "invalid_arguments", Message: "credential must be a credential name"})
	}
	leases, err := s.store.ListAgentLeases(ctx, c.AccountID, c.AgentID, true, now)
	if err != nil {
		log.Printf("mcp: list leases failed: %v", err)
		return toolFailure(&agentFailure{Reason: "internal_error", Message: "could not read leases"})
	}
	out := make([]agentLeaseJSON, 0, len(leases))
	for _, l := range leases {
		if credential == "" || l.Credential == credential {
			out = append(out, agentLeaseOut(l, now))
		}
	}
	s.recordAudit(ctx, store.AuditEvent{Action: auditAgentListLeases, KeyID: c.AgentID, Result: store.AuditResultSuccess, AuditOrigin: o})
	return toolSuccess(map[string]any{"leases": out})
}
