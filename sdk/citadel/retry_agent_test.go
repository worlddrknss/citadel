package citadel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// scriptedAgent answers every call with statuses in turn, then 200 with a
// brokered response; retryAfter adds a Retry-After header to 503 and 429.
func scriptedAgent(t *testing.T, retryAfter bool, statuses ...int) (*Client, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(calls.Add(1)) - 1
		if r.Header.Get("Authorization") != "Bearer cagt_test" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		status := http.StatusOK
		if n < len(statuses) {
			status = statuses[n]
		}
		w.Header().Set("Content-Type", "application/json")
		if retryAfter && (status == http.StatusServiceUnavailable || status == http.StatusTooManyRequests) {
			w.Header().Set("Retry-After", "1")
		}
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = w.Write([]byte(`{"status":201,"headers":{},"body":"ok","bodyEncoding":"text","truncated":false,"redacted":false}`))
			return
		}
		_, _ = w.Write([]byte(`{"error":"upstream_error","message":"nope","reason":"upstream_timeout"}`))
	}))
	t.Cleanup(srv.Close)
	c, err := New(Config{BaseURL: srv.URL, AgentToken: "cagt_test"})
	if err != nil {
		t.Fatal(err)
	}
	c.sleep = func(ctx context.Context, d time.Duration) error { return ctx.Err() }
	return c, &calls
}

func TestBrokeredCallsAreNotRepeatedAfterAmbiguousFailures(t *testing.T) {
	req := AgentHTTPRequest{Credential: "api", Method: "POST", URL: "https://api.example.com/charge", Body: []byte(`{"amount":1}`)}
	for _, status := range []int{500, 502, 504} {
		c, calls := scriptedAgent(t, true, status, status)
		_, err := c.AgentHTTP(context.Background(), req)
		if statusOf(err) != status || ErrorReason(err) != "upstream_timeout" {
			t.Fatalf("%d: err = %v", status, err)
		}
		if calls.Load() != 1 {
			t.Fatalf("a brokered POST that failed with %d was sent %d times", status, calls.Load())
		}
	}
	// A 503 without Retry-After (from a proxy, say) is just as ambiguous.
	c, calls := scriptedAgent(t, false, 503)
	if _, err := c.AgentReveal(context.Background(), "api"); statusOf(err) != 503 || calls.Load() != 1 {
		t.Fatalf("reveal after a bare 503: err %v, %d calls", err, calls.Load())
	}
	c, calls = scriptedAgent(t, false, 502)
	if _, err := c.AgentRequestAccess(context.Background(), AgentAccessInput{Credential: "api", Reason: "r"}); statusOf(err) != 502 || calls.Load() != 1 {
		t.Fatalf("access request after 502: err %v, %d calls", err, calls.Load())
	}
}

func TestBrokeredCallsRetryWhenTheServerDidNotAct(t *testing.T) {
	// Rate limits (429) and a busy broker (503 with Retry-After) are
	// answered before anything is sent upstream.
	c, calls := scriptedAgent(t, true, 429, 503)
	resp, err := c.AgentHTTP(context.Background(), AgentHTTPRequest{Credential: "api", URL: "https://api.example.com/"})
	if err != nil || resp.Status != 201 || resp.Text() != "ok" {
		t.Fatalf("AgentHTTP = %+v, %v", resp, err)
	}
	if calls.Load() != 3 {
		t.Fatalf("calls = %d, want 3", calls.Load())
	}
}

func TestWithRetryNonIdempotentOptsIn(t *testing.T) {
	c, calls := scriptedAgent(t, false, 502, 504)
	resp, err := c.AgentHTTP(WithRetryNonIdempotent(context.Background()), AgentHTTPRequest{Credential: "api", URL: "https://api.example.com/"})
	if err != nil || resp.Status != 201 || calls.Load() != 3 {
		t.Fatalf("AgentHTTP = %+v, %v after %d calls", resp, err, calls.Load())
	}
}

func TestGetsStillRetryAmbiguousFailures(t *testing.T) {
	c, calls, _ := scripted(t, http.StatusBadGateway, http.StatusGatewayTimeout, http.StatusInternalServerError)
	if _, err := c.ListProjects(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 4 {
		t.Fatalf("calls = %d, want 4", calls.Load())
	}
}

func TestPostTransportFailureIsNotRetried(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("no hijacker")
			return
		}
		conn, _, err := hj.Hijack()
		if err == nil {
			_ = conn.Close() // the request arrived; no response ever does
		}
	}))
	defer srv.Close()
	c, err := New(Config{BaseURL: srv.URL, AgentToken: "cagt_test"})
	if err != nil {
		t.Fatal(err)
	}
	c.sleep = func(ctx context.Context, d time.Duration) error { return ctx.Err() }
	if _, err := c.AgentHTTP(context.Background(), AgentHTTPRequest{Credential: "api", URL: "https://api.example.com/"}); err == nil {
		t.Fatal("expected an error")
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1", calls.Load())
	}
}

func TestAgentErrorFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"approval_required","message":"a person must approve this use","reason":"approval_required","requestId":"areq_123"}`))
	}))
	defer srv.Close()
	c, err := New(Config{BaseURL: srv.URL, AgentToken: "cagt_test"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.AgentReveal(context.Background(), "api")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Reason != "approval_required" || apiErr.RequestID != "areq_123" {
		t.Fatalf("err = %#v", err)
	}
	if id, ok := ApprovalRequestID(err); !ok || id != "areq_123" {
		t.Fatalf("ApprovalRequestID = %q, %v", id, ok)
	}
	if !IsApprovalRequired(err) || ErrorReason(err) != "approval_required" {
		t.Fatalf("helpers disagree for %v", err)
	}
	if _, ok := ApprovalRequestID(errors.New("other")); ok {
		t.Fatal("ApprovalRequestID matched a non-API error")
	}
	if ErrorReason(nil) != "" {
		t.Fatal("ErrorReason(nil)")
	}
}

func TestAgentHTTPBodyEncoding(t *testing.T) {
	var got agentHTTPWire
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = agentHTTPWire{}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":200,"headers":{"Content-Type":"application/octet-stream"},"body":"AP8=","bodyEncoding":"base64","truncated":false,"redacted":true}`))
	}))
	defer srv.Close()
	c, err := New(Config{BaseURL: srv.URL, AgentToken: "cagt_test"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	resp, err := c.AgentHTTP(ctx, AgentHTTPRequest{Credential: "api", Method: "PUT", URL: "https://api.example.com/blob", Body: []byte{0, 0xff}})
	if err != nil || got.BodyEncoding != "base64" || got.Body != "AP8=" || got.Method != "PUT" {
		t.Fatalf("binary body sent as %+v, %v", got, err)
	}
	if !resp.OK() || len(resp.Body) != 2 || resp.Body[1] != 0xff || !resp.Redacted {
		t.Fatalf("response = %+v", resp)
	}

	_, err = c.AgentHTTP(ctx, AgentHTTPRequest{Credential: "api", Method: "POST", URL: "https://api.example.com/", JSON: map[string]int{"n": 1}, TaskID: "t-1"})
	if err != nil || got.BodyEncoding != "text" || got.Body != `{"n":1}` || got.Headers["Content-Type"] != "application/json" || got.TaskID != "t-1" {
		t.Fatalf("JSON body sent as %+v, %v", got, err)
	}
	_, err = c.AgentHTTP(ctx, AgentHTTPRequest{Credential: "api", URL: "https://api.example.com/", JSON: 1, Header: map[string]string{"content-type": "application/vnd.x+json"}})
	if err != nil || got.Headers["content-type"] != "application/vnd.x+json" || len(got.Headers) != 1 {
		t.Fatalf("explicit Content-Type replaced: %+v, %v", got, err)
	}
	if _, err := c.AgentHTTP(ctx, AgentHTTPRequest{Credential: "api", URL: "https://x/", Body: []byte("a"), JSON: 1}); err == nil {
		t.Fatal("Body and JSON together were accepted")
	}
}
