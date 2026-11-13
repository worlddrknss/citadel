package citadel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"unicode/utf8"
)

// AgentHTTPRequest is a brokered HTTP request: Citadel performs it with the
// named credential injected, so the agent never holds the secret.
type AgentHTTPRequest struct {
	// Credential names the credential to inject (the agent needs a grant
	// with the use action).
	Credential string
	// Method is GET (the default), HEAD, POST, PUT, PATCH, DELETE or
	// OPTIONS, as the credential allows.
	Method string
	// URL is the absolute https URL (http only when the credential allows
	// it); its host must be one of the credential's allowed hosts.
	URL string
	// Header is sent upstream, minus headers that would collide with the
	// credential (Authorization, Cookie, Proxy-*, hop-by-hop headers).
	Header map[string]string
	// Body is the request body, at most 1 MiB. It is sent as text when it
	// is valid UTF-8 and base64 encoded otherwise.
	Body []byte
	// JSON, when non-nil, is marshalled as the body (Body must be empty)
	// and sets Content-Type: application/json unless Header has one.
	JSON any
	// TaskID is the agent's task or session ID, recorded in the audit log.
	TaskID string
}

// AgentHTTPResponse is the upstream's response, filtered and redacted. An
// upstream error status is a successful brokered call: check Status.
type AgentHTTPResponse struct {
	// Status is the upstream's HTTP status.
	Status int
	// Header holds the response headers (multiple values joined with ", "),
	// without Set-Cookie and credential headers.
	Header map[string]string
	// Body is the decoded response body.
	Body []byte
	// Truncated reports that the body was cut at 5 MiB.
	Truncated bool
	// Redacted reports that occurrences of the secret were replaced with
	// [REDACTED].
	Redacted bool
}

// OK reports whether the upstream answered 2xx.
func (r *AgentHTTPResponse) OK() bool { return r.Status >= 200 && r.Status < 300 }

// Text returns the body as a string.
func (r *AgentHTTPResponse) Text() string { return string(r.Body) }

// JSON unmarshals the body into v.
func (r *AgentHTTPResponse) JSON(v any) error { return json.Unmarshal(r.Body, v) }

type agentHTTPWire struct {
	Credential   string            `json:"credential"`
	Method       string            `json:"method,omitempty"`
	URL          string            `json:"url"`
	Headers      map[string]string `json:"headers,omitempty"`
	Body         string            `json:"body,omitempty"`
	BodyEncoding string            `json:"bodyEncoding,omitempty"`
	TaskID       string            `json:"taskId,omitempty"`
}

type agentHTTPWireResponse struct {
	Status       int               `json:"status"`
	Headers      map[string]string `json:"headers"`
	Body         string            `json:"body"`
	BodyEncoding string            `json:"bodyEncoding"`
	Truncated    bool              `json:"truncated"`
	Redacted     bool              `json:"redacted"`
}

// AgentHTTP makes a brokered HTTP request (POST /v1/agent/http). The client
// must be configured with an agent token.
//
// Failures return an *APIError whose Reason says why (no_grant,
// host_not_allowed, destination_blocked, upstream_timeout, ...). A grant
// that requires approval answers approval_required with a pending request:
// see ApprovalRequestID and WaitForAgentAccess.
//
// The call is never retried after a 500, 502, 504 or timeout (the upstream
// may have acted), only after 429 and a busy broker (503 with Retry-After);
// use WithRetryNonIdempotent for requests that are safe to repeat.
func (c *Client) AgentHTTP(ctx context.Context, in AgentHTTPRequest) (*AgentHTTPResponse, error) {
	w := agentHTTPWire{Credential: in.Credential, Method: in.Method, URL: in.URL, Headers: in.Header, TaskID: in.TaskID}
	body := in.Body
	if in.JSON != nil {
		if len(body) > 0 {
			return nil, errors.New("citadel: AgentHTTPRequest: set Body or JSON, not both")
		}
		var err error
		if body, err = json.Marshal(in.JSON); err != nil {
			return nil, fmt.Errorf("citadel: AgentHTTPRequest: encode JSON body: %w", err)
		}
		if !hasHeader(in.Header, "Content-Type") {
			w.Headers = make(map[string]string, len(in.Header)+1)
			for k, v := range in.Header {
				w.Headers[k] = v
			}
			w.Headers["Content-Type"] = "application/json"
		}
	}
	if len(body) > 0 {
		if utf8.Valid(body) {
			w.Body, w.BodyEncoding = string(body), "text"
		} else {
			w.Body, w.BodyEncoding = base64.StdEncoding.EncodeToString(body), "base64"
		}
	}
	var out agentHTTPWireResponse
	if err := c.do(ctx, http.MethodPost, "/v1/agent/http", nil, w, &out); err != nil {
		return nil, err
	}
	resp := &AgentHTTPResponse{Status: out.Status, Header: out.Headers, Truncated: out.Truncated, Redacted: out.Redacted}
	if out.BodyEncoding == "base64" {
		b, err := base64.StdEncoding.DecodeString(out.Body)
		if err != nil {
			return nil, fmt.Errorf("citadel: decode POST /v1/agent/http body: %w", err)
		}
		resp.Body = b
	} else {
		resp.Body = []byte(out.Body)
	}
	return resp, nil
}

func hasHeader(h map[string]string, name string) bool {
	for k := range h {
		if http.CanonicalHeaderKey(k) == http.CanonicalHeaderKey(name) {
			return true
		}
	}
	return false
}
