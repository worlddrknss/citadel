package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// MCP server (2.2): the Model Context Protocol over Streamable HTTP at /mcp,
// protocol version 2025-06-18 (2025-03-26 is also accepted).
//
//   - POST carries one JSON-RPC 2.0 message. Requests are answered with an
//     application/json body; notifications and responses get 202 Accepted.
//     Batches (removed in 2025-06-18) are refused.
//   - initialize issues the Mcp-Session-Id; every later request must carry
//     it (400 without, 404 when unknown, expired or ended) and may carry
//     MCP-Protocol-Version (400 when unsupported).
//   - DELETE ends the session; GET (the optional server-to-client stream)
//     is not offered: 405.
//   - Every request needs the agent Bearer credential; cookies, access keys
//     and SigV4 are never accepted. A browser Origin other than Citadel's
//     own is refused (DNS rebinding).
//
// Methods: initialize, ping, tools/list, tools/call and the
// notifications/initialized notification. Tool failures (a denial, a
// refused URL, an unreachable upstream) are tool results with isError, not
// protocol errors, so the model can see and react to them.

const (
	mcpLatestVersion = "2025-06-18"
	mcpSessionHeader = "Mcp-Session-Id"
	mcpVersionHeader = "MCP-Protocol-Version"
	mcpBodyMax       = agentBrokerBodyMax + 64<<10
)

// mcpVersions are the protocol versions this server speaks.
var mcpVersions = []string{"2025-06-18", "2025-03-26"}

func mcpSupportedVersion(v string) bool {
	for _, s := range mcpVersions {
		if s == v {
			return true
		}
	}
	return false
}

// JSON-RPC error codes.
const (
	rpcParseError     = -32700
	rpcInvalidRequest = -32600
	rpcMethodNotFound = -32601
	rpcInvalidParams  = -32602
	rpcInternalError  = -32603
	rpcSessionError   = -32001
)

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

var rpcNullID = json.RawMessage("null")

func writeRPC(w http.ResponseWriter, status int, resp rpcResponse) {
	resp.JSONRPC = "2.0"
	if len(resp.ID) == 0 {
		resp.ID = rpcNullID
	}
	writeNativeJSON(w, status, resp)
}

func writeRPCError(w http.ResponseWriter, status int, id json.RawMessage, code int, msg string) {
	writeRPC(w, status, rpcResponse{ID: id, Error: &rpcError{Code: code, Message: msg}})
}

// validRPCID reports whether id is a JSON-RPC request id MCP allows: a
// string or a number (never null).
func validRPCID(id json.RawMessage) bool {
	id = bytes.TrimSpace(id)
	if len(id) == 0 || len(id) > 256 {
		return false
	}
	switch id[0] {
	case '"':
		var s string
		return json.Unmarshal(id, &s) == nil
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		var n json.Number
		return json.Unmarshal(id, &n) == nil
	}
	return false
}

// mcpMethodLabel bounds a method name for metrics.
func mcpMethodLabel(m string) string {
	switch m {
	case "initialize", "ping", "tools/list", "tools/call", "notifications/initialized", "notifications/cancelled":
		return m
	case "":
		return "none"
	}
	return "other"
}

// handleMCP serves /mcp.
func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && !hostMatches(origin, r.Host) {
		writeAgentBrokerError(w, http.StatusForbidden, "forbidden", "origin_rejected", "cross-origin requests to the MCP endpoint are refused")
		return
	}
	switch r.Method {
	case http.MethodPost:
		s.handleMCPPost(w, r)
	case http.MethodDelete:
		s.handleMCPDelete(w, r)
	default:
		w.Header().Set("Allow", "POST, DELETE")
		writeAgentBrokerError(w, http.StatusMethodNotAllowed, "method_not_allowed", "", "the MCP endpoint accepts POST and DELETE; there is no server-to-client stream")
	}
}

func (s *Server) handleMCPPost(w http.ResponseWriter, r *http.Request) {
	rt := s.agentBrokerMetrics()
	c, ctx, ok := s.agentAccess().authenticate(w, r, "citadel.MCP")
	if !ok {
		rt.mcpReqs.Inc("none", "unauthenticated")
		return
	}
	if v := r.Header.Get(mcpVersionHeader); v != "" && !mcpSupportedVersion(v) {
		rt.mcpReqs.Inc("none", "bad_version")
		writeRPCError(w, http.StatusBadRequest, nil, rpcInvalidRequest, "unsupported MCP-Protocol-Version; this server speaks "+strings.Join(mcpVersions, ", "))
		return
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "application/json") {
		rt.mcpReqs.Inc("none", "bad_content_type")
		writeRPCError(w, http.StatusUnsupportedMediaType, nil, rpcInvalidRequest, "Content-Type must be application/json")
		return
	}
	if accept := r.Header.Get("Accept"); accept != "" && !acceptsJSON(accept) {
		rt.mcpReqs.Inc("none", "not_acceptable")
		writeRPCError(w, http.StatusNotAcceptable, nil, rpcInvalidRequest, "this server answers with application/json")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, mcpBodyMax))
	if err != nil {
		rt.mcpReqs.Inc("none", "too_large")
		writeRPCError(w, http.StatusRequestEntityTooLarge, nil, rpcInvalidRequest, "the message is too large")
		return
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		rt.mcpReqs.Inc("none", "batch")
		writeRPCError(w, http.StatusBadRequest, nil, rpcInvalidRequest, "JSON-RPC batches are not supported; send one message per request")
		return
	}
	var msg rpcMessage
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	if err := dec.Decode(&msg); err != nil || dec.More() {
		rt.mcpReqs.Inc("none", "parse_error")
		writeRPCError(w, http.StatusBadRequest, nil, rpcParseError, "parse error: the body must be one JSON-RPC message")
		return
	}
	if msg.JSONRPC != "2.0" {
		rt.mcpReqs.Inc(mcpMethodLabel(msg.Method), "invalid")
		writeRPCError(w, http.StatusBadRequest, nil, rpcInvalidRequest, `invalid request: jsonrpc must be "2.0"`)
		return
	}
	hasID := len(msg.ID) > 0 && !bytes.Equal(bytes.TrimSpace(msg.ID), rpcNullID)
	if msg.Method == "" {
		// A response or error from the client; this server sends no
		// requests, so there is nothing to match it to.
		if len(msg.Result) == 0 && len(msg.Error) == 0 {
			rt.mcpReqs.Inc("none", "invalid")
			writeRPCError(w, http.StatusBadRequest, nil, rpcInvalidRequest, "invalid request: method is required")
			return
		}
		rt.mcpReqs.Inc("none", "accepted")
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if hasID && !validRPCID(msg.ID) {
		rt.mcpReqs.Inc(mcpMethodLabel(msg.Method), "invalid")
		writeRPCError(w, http.StatusBadRequest, nil, rpcInvalidRequest, "invalid request: id must be a string or a number")
		return
	}
	label := mcpMethodLabel(msg.Method)
	now := time.Now()

	if msg.Method == "initialize" {
		if !hasID {
			rt.mcpReqs.Inc(label, "invalid")
			writeRPCError(w, http.StatusBadRequest, nil, rpcInvalidRequest, "initialize must be a request")
			return
		}
		s.mcpInitialize(ctx, w, r, c, msg, now)
		return
	}

	sid := strings.TrimSpace(r.Header.Get(mcpSessionHeader))
	if sid == "" {
		rt.mcpReqs.Inc(label, "no_session")
		writeRPCError(w, http.StatusBadRequest, msg.ID, rpcInvalidRequest, "Mcp-Session-Id header required; call initialize first")
		return
	}
	session, ok := s.parseMCPSession(sid, c, now)
	if !ok {
		rt.mcpReqs.Inc(label, "unknown_session")
		writeRPCError(w, http.StatusNotFound, msg.ID, rpcSessionError, "the MCP session is unknown, expired or ended; initialize a new one")
		return
	}
	if v := r.Header.Get(mcpVersionHeader); v != "" && v != session.Version {
		rt.mcpReqs.Inc(label, "bad_version")
		writeRPCError(w, http.StatusBadRequest, msg.ID, rpcInvalidRequest, "MCP-Protocol-Version differs from the version negotiated for this session")
		return
	}

	if !hasID {
		// Notifications (initialized, cancelled, ...) need no answer.
		rt.mcpReqs.Inc(label, "accepted")
		w.WriteHeader(http.StatusAccepted)
		return
	}

	var result any
	var rpcErr *rpcError
	switch msg.Method {
	case "ping":
		result = struct{}{}
	case "tools/list":
		result, rpcErr = s.mcpToolsList(ctx, c)
	case "tools/call":
		result, rpcErr = s.mcpToolsCall(ctx, r, c, msg.Params)
	default:
		rpcErr = &rpcError{Code: rpcMethodNotFound, Message: "method not found"}
	}
	if rpcErr != nil {
		rt.mcpReqs.Inc(label, "error")
		writeRPC(w, http.StatusOK, rpcResponse{ID: msg.ID, Error: rpcErr})
		return
	}
	outcome := "ok"
	if tr, isTool := result.(*mcpToolResult); isTool && tr.IsError {
		outcome = "tool_error"
	}
	rt.mcpReqs.Inc(label, outcome)
	writeRPC(w, http.StatusOK, rpcResponse{ID: msg.ID, Result: result})
}

// acceptsJSON reports whether an Accept header admits application/json.
func acceptsJSON(accept string) bool {
	for _, part := range strings.Split(accept, ",") {
		mt, _, _ := strings.Cut(strings.TrimSpace(part), ";")
		switch strings.ToLower(strings.TrimSpace(mt)) {
		case "application/json", "application/*", "*/*":
			return true
		}
	}
	return false
}

type mcpInitializeParams struct {
	ProtocolVersion string `json:"protocolVersion"`
	ClientInfo      struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"clientInfo"`
}

type mcpImplementation struct {
	Name    string `json:"name"`
	Title   string `json:"title,omitempty"`
	Version string `json:"version"`
}

type mcpInitializeResult struct {
	ProtocolVersion string            `json:"protocolVersion"`
	Capabilities    map[string]any    `json:"capabilities"`
	ServerInfo      mcpImplementation `json:"serverInfo"`
	Instructions    string            `json:"instructions,omitempty"`
}

const mcpInstructions = "Citadel holds credentials for you without giving you their values. " +
	"Call list_credentials to see which credentials you may use and the hosts each may be sent to, " +
	"then http_request to make an HTTP request with one injected. Secret values in responses are replaced with [REDACTED]."

func (s *Server) mcpInitialize(ctx context.Context, w http.ResponseWriter, r *http.Request, c *agentCaller, msg rpcMessage, now time.Time) {
	rt := s.agentBrokerMetrics()
	var p mcpInitializeParams
	if len(msg.Params) > 0 {
		if err := json.Unmarshal(msg.Params, &p); err != nil {
			rt.mcpReqs.Inc("initialize", "error")
			writeRPCError(w, http.StatusOK, msg.ID, rpcInvalidParams, "invalid initialize params")
			return
		}
	}
	version := mcpLatestVersion
	if mcpSupportedVersion(p.ProtocolVersion) {
		version = p.ProtocolVersion
	}
	sid, err := s.issueMCPSession(c, version, now)
	if err != nil {
		rt.mcpReqs.Inc("initialize", "error")
		writeRPCError(w, http.StatusInternalServerError, msg.ID, rpcInternalError, "could not start a session")
		return
	}
	client := auditToken(truncateRunes(p.ClientInfo.Name, 64))
	o := s.agentAccess().auditOrigin(r, c)
	o.Resource = "protocol=" + version
	if client != "" {
		o.Resource += " client=" + client
	}
	s.recordAudit(ctx, store.AuditEvent{Action: actionMCPInitialize, KeyID: c.AgentID, Result: store.AuditResultSuccess, AuditOrigin: o})
	if info := auditInfoFrom(ctx); info != nil && info.hasFailed() {
		rt.mcpReqs.Inc("initialize", "error")
		writeRPCError(w, http.StatusInternalServerError, msg.ID, rpcInternalError, "the audit log could not be written")
		return
	}
	rt.mcpSessions.Inc("started")
	rt.mcpReqs.Inc("initialize", "ok")
	w.Header().Set(mcpSessionHeader, sid)
	writeRPC(w, http.StatusOK, rpcResponse{ID: msg.ID, Result: mcpInitializeResult{
		ProtocolVersion: version,
		Capabilities:    map[string]any{"tools": map[string]any{"listChanged": false}},
		ServerInfo:      mcpImplementation{Name: "citadel", Title: AppName, Version: serverVersion()},
		Instructions:    mcpInstructions,
	}})
}

// buildVersion is the release version, set at build time with
// -ldflags "-X github.com/worlddrknss/citadel/internal/server.buildVersion=2.5.1".
var buildVersion string

// serverVersion is the release version of the running build: buildVersion
// when the build set it, else the module version, else "dev".
func serverVersion() string {
	if v := strings.TrimPrefix(strings.TrimSpace(buildVersion), "v"); v != "" {
		return v
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

func truncateRunes(v string, n int) string {
	r := []rune(v)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

func (s *Server) handleMCPDelete(w http.ResponseWriter, r *http.Request) {
	rt := s.agentBrokerMetrics()
	c, ctx, ok := s.agentAccess().authenticate(w, r, actionMCPEndSession)
	if !ok {
		return
	}
	sid := strings.TrimSpace(r.Header.Get(mcpSessionHeader))
	if sid == "" {
		writeAgentBrokerError(w, http.StatusBadRequest, "invalid_request", "", "Mcp-Session-Id header required")
		return
	}
	now := time.Now()
	session, ok := s.parseMCPSession(sid, c, now)
	if !ok {
		writeAgentBrokerError(w, http.StatusNotFound, "not_found", "", "the MCP session is unknown, expired or ended")
		return
	}
	s.endMCPSession(session, now)
	o := s.agentAccess().auditOrigin(r, c)
	o.Resource = "protocol=" + session.Version
	s.recordAudit(ctx, store.AuditEvent{Action: actionMCPEndSession, KeyID: c.AgentID, Result: store.AuditResultSuccess, AuditOrigin: o})
	rt.mcpSessions.Inc("ended")
	w.WriteHeader(http.StatusNoContent)
}

// errMCPArgs is a tools/call arguments error.
var errMCPArgs = errors.New("invalid arguments")
