package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/worlddrknss/citadel/internal/agentbroker"
	"github.com/worlddrknss/citadel/internal/store"
)

// MCP tools. They follow the agent's grants: reveal_credential is listed
// only when the agent holds a grant with the reveal action.

type mcpTool struct {
	Name         string         `json:"name"`
	Title        string         `json:"title,omitempty"`
	Description  string         `json:"description"`
	InputSchema  map[string]any `json:"inputSchema"`
	OutputSchema map[string]any `json:"outputSchema,omitempty"`
	Annotations  map[string]any `json:"annotations,omitempty"`
}

type mcpContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type mcpToolResult struct {
	Content           []mcpContent `json:"content"`
	StructuredContent any          `json:"structuredContent,omitempty"`
	IsError           bool         `json:"isError"`
}

const (
	mcpToolListCredentials = "list_credentials"
	mcpToolHTTPRequest     = "http_request"
	mcpToolReveal          = "reveal_credential"
)

func obj(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

var (
	mcpListCredentialsTool = mcpTool{
		Name:        mcpToolListCredentials,
		Title:       "List credentials",
		Description: "Lists the credentials this agent may use: name, kind, description, the hosts each may be sent to, and the granted actions. Never returns secret values.",
		InputSchema: obj(map[string]any{}),
		OutputSchema: obj(map[string]any{
			"credentials": map[string]any{"type": "array", "items": obj(map[string]any{
				"name":                str("Credential name, used as the credential argument of the other tools."),
				"kind":                str("http_header, http_basic, http_query, login, raw, aws_sts, github_app or oauth2_client_credentials."),
				"description":         str("What the credential is for."),
				"allowedHosts":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"allowedMethods":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"allowedPathPrefixes": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"actions":             map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"status":              str("available, or why the grant can't be used right now."),
				"urlPatterns":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Login credentials: the pages the login may be used on (get_login)."},
			}, "name", "kind", "allowedHosts", "actions", "status")},
		}, "credentials"),
		Annotations: map[string]any{"readOnlyHint": true, "openWorldHint": false},
	}
	mcpHTTPRequestTool = mcpTool{
		Name:  mcpToolHTTPRequest,
		Title: "HTTP request with a credential",
		Description: "Performs an HTTP request with a credential injected by Citadel (you never see its value). " +
			"The URL's host must be one of the credential's allowed hosts. Returns the upstream status, headers and body; " +
			"secret values in the response are replaced with [REDACTED].",
		InputSchema: obj(map[string]any{
			"credential":   str("Name of the credential to inject (see list_credentials)."),
			"method":       map[string]any{"type": "string", "enum": []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}, "description": "HTTP method (default GET)."},
			"url":          str("Absolute https URL."),
			"headers":      map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "Extra request headers. Authorization, Cookie and the credential's own header are ignored."},
			"body":         str("Request body."),
			"bodyEncoding": map[string]any{"type": "string", "enum": []string{"text", "base64"}, "description": "Encoding of body (default text)."},
			"taskId":       str("Optional task or session ID recorded in the audit log."),
		}, "credential", "url"),
		OutputSchema: obj(map[string]any{
			"status":       map[string]any{"type": "integer"},
			"headers":      map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
			"body":         map[string]any{"type": "string"},
			"bodyEncoding": map[string]any{"type": "string", "enum": []string{"text", "base64"}},
			"truncated":    map[string]any{"type": "boolean"},
			"redacted":     map[string]any{"type": "boolean"},
		}, "status", "headers", "body", "bodyEncoding", "truncated", "redacted"),
		Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": true, "openWorldHint": true},
	}
	mcpRevealTool = mcpTool{
		Name:        mcpToolReveal,
		Title:       "Reveal a credential",
		Description: "Returns a credential's secret value. Only works for credentials granted with the reveal action; prefer http_request, which never exposes the value.",
		InputSchema: obj(map[string]any{
			"credential": str("Name of the credential to reveal."),
			"taskId":     str("Optional task or session ID recorded in the audit log."),
		}, "credential"),
		OutputSchema: obj(map[string]any{
			"credential": map[string]any{"type": "string"},
			"kind":       map[string]any{"type": "string"},
			"value":      map[string]any{"type": "string"},
			"expiresAt":  map[string]any{"type": "string", "description": "When a minted token stops working (RFC 3339)."},
		}, "credential", "kind", "value"),
		Annotations: map[string]any{"readOnlyHint": true, "openWorldHint": false},
	}
)

type mcpToolsListResult struct {
	Tools []mcpTool `json:"tools"`
}

func hasRevealGrant(creds []agentCredentialInfo) bool {
	for _, c := range creds {
		for _, a := range c.Actions {
			if a == agentActionReveal {
				return true
			}
		}
	}
	return false
}

func (s *Server) mcpToolsList(ctx context.Context, c *agentCaller) (any, *rpcError) {
	creds, err := s.agentAccess().credentials(ctx, c)
	if err != nil {
		log.Printf("mcp: listing credentials failed: %v", err)
		return nil, &rpcError{Code: rpcInternalError, Message: "could not list tools"}
	}
	tools := []mcpTool{mcpListCredentialsTool, mcpHTTPRequestTool}
	if hasRevealGrant(creds) {
		tools = append(tools, mcpRevealTool)
	}
	tools = append(tools, mcpRequestAccessTool, mcpGetLeaseTool)
	tools = append(tools, mcpLoginTools(creds)...)
	return mcpToolsListResult{Tools: tools}, nil
}

type mcpCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// decodeArgs decodes tool arguments strictly (unknown members refused).
func decodeArgs(raw json.RawMessage, target any) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, rpcNullID) {
		raw = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return fmt.Errorf("%w: %v", errMCPArgs, sanitizeJSONError(err))
	}
	return nil
}

func toolSuccess(v any) *mcpToolResult {
	b, _ := json.Marshal(v)
	return &mcpToolResult{Content: []mcpContent{{Type: "text", Text: string(b)}}, StructuredContent: v}
}

func toolFailure(f *agentFailure) *mcpToolResult {
	text := f.Message
	if f.RequestID != "" {
		text = "a person must approve this use (requestId " + f.RequestID + "); check the decision with get_lease, then retry"
	}
	if f.Reason != "" {
		text = f.Reason + ": " + text
	}
	return &mcpToolResult{
		Content: []mcpContent{{Type: "text", Text: text}},
		IsError: true,
	}
}

func (s *Server) mcpToolsCall(ctx context.Context, r *http.Request, c *agentCaller, params json.RawMessage) (any, *rpcError) {
	var p mcpCallParams
	if err := json.Unmarshal(params, &p); err != nil || p.Name == "" {
		return nil, &rpcError{Code: rpcInvalidParams, Message: "tools/call needs a tool name"}
	}
	// Each call works on its own copy: a taskId argument applies to this
	// call only.
	call := *c
	switch p.Name {
	case mcpToolListCredentials:
		var args struct{}
		if err := decodeArgs(p.Arguments, &args); err != nil {
			return toolFailure(&agentFailure{Reason: "invalid_arguments", Message: err.Error()}), nil
		}
		return s.mcpListCredentials(ctx, r, &call), nil
	case mcpToolHTTPRequest:
		var req agentbroker.Request
		if err := decodeArgs(p.Arguments, &req); err != nil {
			return toolFailure(&agentFailure{Reason: "invalid_arguments", Message: err.Error()}), nil
		}
		resp, f := s.brokerHTTP(ctx, r, &call, req, "mcp")
		if f != nil {
			return toolFailure(f), nil
		}
		return toolSuccess(resp), nil
	case mcpToolReveal:
		var req agentRevealRequest
		if err := decodeArgs(p.Arguments, &req); err != nil {
			return toolFailure(&agentFailure{Reason: "invalid_arguments", Message: err.Error()}), nil
		}
		resp, f := s.revealCredential(ctx, r, &call, req, "mcp")
		if f != nil {
			return toolFailure(f), nil
		}
		return toolSuccess(resp), nil
	}
	if res, ok := s.mcpAccessTool(ctx, r, &call, p.Name, p.Arguments); ok {
		return res, nil
	}
	if res, ok := s.mcpLoginTool(ctx, r, &call, p.Name, p.Arguments); ok {
		return res, nil
	}
	return nil, &rpcError{Code: rpcInvalidParams, Message: "unknown tool"}
}

type mcpCredentialsResult struct {
	Credentials []agentCredentialInfo `json:"credentials"`
}

func (s *Server) mcpListCredentials(ctx context.Context, r *http.Request, c *agentCaller) *mcpToolResult {
	acc := s.agentAccess()
	creds, err := acc.credentials(ctx, c)
	o := acc.auditOrigin(r, c)
	o.Resource = "via=mcp"
	if err != nil {
		log.Printf("mcp: listing credentials failed: %v", err)
		s.recordAudit(ctx, store.AuditEvent{Action: actionAgentListCredentials, KeyID: c.AgentID, Result: store.AuditResultError, ErrorType: "internal_error", AuditOrigin: o})
		return toolFailure(&agentFailure{Reason: "internal_error", Message: "could not list credentials"})
	}
	if creds == nil {
		creds = []agentCredentialInfo{}
	}
	s.recordAudit(ctx, store.AuditEvent{Action: actionAgentListCredentials, KeyID: c.AgentID, Result: store.AuditResultSuccess, AuditOrigin: o})
	return toolSuccess(mcpCredentialsResult{Credentials: creds})
}
