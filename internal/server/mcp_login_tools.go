package server

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/worlddrknss/citadel/internal/store"
)

// MCP tools for browser agents (2.4): get_totp_code and get_login. Each is
// listed only when the agent holds a grant it can use: get_totp_code with a
// totp grant, get_login with a reveal grant on a login credential.

const (
	mcpToolGetTOTPCode = "get_totp_code"
	mcpToolGetLogin    = "get_login"
)

var (
	mcpGetTOTPCodeTool = mcpTool{
		Name:  mcpToolGetTOTPCode,
		Title: "Get a TOTP code",
		Description: "Returns the current one-time code (TOTP, RFC 6238) of a login credential, and how many seconds it stays valid. " +
			"Use it for a site's two-factor prompt. Never returns the TOTP seed. Needs a grant with the totp action.",
		InputSchema: obj(map[string]any{
			"credential": str("Name of the login credential (see list_credentials)."),
			"taskId":     str("Optional task or session ID recorded in the audit log."),
		}, "credential"),
		OutputSchema: obj(map[string]any{
			"credential":       map[string]any{"type": "string"},
			"code":             map[string]any{"type": "string"},
			"expiresAt":        map[string]any{"type": "string", "description": "When the code stops being current (RFC 3339)."},
			"secondsRemaining": map[string]any{"type": "integer"},
			"digits":           map[string]any{"type": "integer"},
			"period":           map[string]any{"type": "integer"},
			"algorithm":        map[string]any{"type": "string"},
		}, "credential", "code", "expiresAt", "secondsRemaining"),
		Annotations: map[string]any{"readOnlyHint": true, "openWorldHint": false},
	}
	mcpGetLoginTool = mcpTool{
		Name:  mcpToolGetLogin,
		Title: "Get a login for a page",
		Description: "Returns the username and password of a login credential for the page at url, which must match one of the credential's urlPatterns " +
			"(see list_credentials). Fill them into that page only. Needs a grant with the reveal action.",
		InputSchema: obj(map[string]any{
			"credential": str("Name of the login credential."),
			"url":        str("The absolute https URL of the page the login is for."),
			"taskId":     str("Optional task or session ID recorded in the audit log."),
		}, "credential", "url"),
		OutputSchema: obj(map[string]any{
			"credential": map[string]any{"type": "string"},
			"username":   map[string]any{"type": "string"},
			"password":   map[string]any{"type": "string"},
			"urlPattern": map[string]any{"type": "string"},
		}, "credential", "username", "password", "urlPattern"),
		Annotations: map[string]any{"readOnlyHint": true, "openWorldHint": false},
	}
)

// mcpLoginTools are the login tools the agent's grants allow.
func mcpLoginTools(creds []agentCredentialInfo) []mcpTool {
	var totp, login bool
	for _, c := range creds {
		if c.Kind != store.AgentCredentialLogin {
			continue
		}
		for _, a := range c.Actions {
			totp = totp || a == store.AgentActionTOTP
			login = login || a == store.AgentActionReveal
		}
	}
	var out []mcpTool
	if totp {
		out = append(out, mcpGetTOTPCodeTool)
	}
	if login {
		out = append(out, mcpGetLoginTool)
	}
	return out
}

// mcpLoginTool runs a login tool; ok is false for other tool names.
func (s *Server) mcpLoginTool(ctx context.Context, r *http.Request, c *agentCaller, name string, args json.RawMessage) (*mcpToolResult, bool) {
	switch name {
	case mcpToolGetTOTPCode:
		var req agentTOTPRequest
		if err := decodeArgs(args, &req); err != nil {
			return toolFailure(&agentFailure{Reason: "invalid_arguments", Message: err.Error()}), true
		}
		resp, f := s.agentTOTPCode(ctx, r, c, req, "mcp")
		if f != nil {
			return toolFailure(f), true
		}
		return toolSuccess(resp), true
	case mcpToolGetLogin:
		var req agentLoginRequest
		if err := decodeArgs(args, &req); err != nil {
			return toolFailure(&agentFailure{Reason: "invalid_arguments", Message: err.Error()}), true
		}
		resp, f := s.agentGetLogin(ctx, r, c, req, "mcp")
		if f != nil {
			return toolFailure(f), true
		}
		return toolSuccess(resp), true
	}
	return nil, false
}
