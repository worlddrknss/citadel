package server

import (
	"context"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/worlddrknss/citadel/internal/agentbroker"
	"github.com/worlddrknss/citadel/internal/metrics"
	"github.com/worlddrknss/citadel/internal/providertoken"
	"github.com/worlddrknss/citadel/internal/store"
)

// The agent broker (POST /v1/agent/http), reveal (POST
// /v1/agent/credentials/reveal) and the MCP server (/mcp) act for an
// authenticated agent. They reach the agents core (authentication, grants,
// usage profiles, secret values) only through agentAccess, so the protocol
// handlers stay independent of how agents are stored and can be tested
// with a fake.

// agentCaller is an authenticated agent request.
type agentCaller struct {
	AccountID string
	AgentID   string
	Name      string
	Owner     string
	// TaskID is the agent's own task or session ID ("" when not sent).
	TaskID string
	// ref is the core's own principal, passed back to agentAccess.
	ref any
}

// agentCredentialInfo describes a credential the agent holds a grant for.
// It never carries the value.
type agentCredentialInfo struct {
	Name                string   `json:"name"`
	Kind                string   `json:"kind"`
	Description         string   `json:"description,omitempty"`
	AllowedHosts        []string `json:"allowedHosts"`
	AllowedMethods      []string `json:"allowedMethods,omitempty"`
	AllowedPathPrefixes []string `json:"allowedPathPrefixes,omitempty"`
	Actions             []string `json:"actions"`
	// Status is "available", or why the grant can't be used right now
	// (not_yet_valid, grant_expired, outside_window, ...).
	Status string `json:"status"`
	// URLPatterns are the pages a login credential may be used on (2.4).
	URLPatterns []string `json:"urlPatterns,omitempty"`
}

// agentUse is the outcome of an access check for one action on one
// credential.
type agentUse struct {
	Allowed bool
	// Reason is a stable denial code when not allowed.
	Reason     string
	RetryAfter time.Duration
	// RequestID is the pending access request when Reason is
	// approval_required (2.3).
	RequestID string
	// LeaseID and LeaseExpiresAt name the lease an allowed use was made
	// under ("" when none).
	LeaseID        string
	LeaseExpiresAt time.Time
	Credential     agentCredentialInfo
	Profile        agentbroker.Profile
	// ref is the core's reference to the backing secret.
	ref any
}

// agentAccess is what the broker and the MCP server need from the agents
// core.
type agentAccess interface {
	// authenticate checks the request's agent Bearer credential (never a
	// cookie or SigV4), applies the per-agent request limits and installs
	// the agent as the audit principal. On failure it has written the
	// response and returns ok=false.
	authenticate(w http.ResponseWriter, r *http.Request, action string) (*agentCaller, context.Context, bool)
	// evaluate decides whether the agent may perform action ("use",
	// "reveal") with the named credential now. An allowed use or reveal
	// counts against the grant's rate limit.
	evaluate(ctx context.Context, c *agentCaller, credential, action string) agentUse
	// minter returns what produces the credential's value for an allowed
	// use: providertoken.Static for a stored secret, a provider minter for
	// credentials minted on use (2.4).
	minter(ctx context.Context, c *agentCaller, u agentUse) (providertoken.Minter, error)
	// credentials lists the credentials the agent holds grants for.
	credentials(ctx context.Context, c *agentCaller) ([]agentCredentialInfo, error)
	// auditOrigin is the audit origin of the agent's request: the agent as
	// actor, its owner and task ID.
	auditOrigin(r *http.Request, c *agentCaller) store.AuditOrigin
}

// agentBrokerRuntime is the broker's and MCP server's per-server state.
type agentBrokerRuntime struct {
	// access replaces the agents core (tests).
	access agentAccess
	// client builds the HTTP client for a credential (tests replace it to
	// trust a test CA); nil uses newAgentBrokerHTTPClient.
	client func(allowed []netip.Prefix) *http.Client
	limits agentbroker.Limits

	// Concurrency caps: brokered requests hold up to 30s and a few MiB.
	global chan struct{}
	mu     sync.Mutex
	active map[string]int // agentID -> requests in flight

	sessions mcpSessions

	metricsOnce sync.Once
	reqs        *metrics.CounterVec
	upstream    *metrics.CounterVec
	duration    *metrics.HistogramVec
	reveals     *metrics.CounterVec
	mcpReqs     *metrics.CounterVec
	mcpSessions *metrics.CounterVec
}

const (
	agentBrokerMaxConcurrent         = 32
	agentBrokerMaxConcurrentPerAgent = 4
)

var agentBrokerRuntimes sync.Map // *Server -> *agentBrokerRuntime

func (s *Server) agentBrokerRT() *agentBrokerRuntime {
	if v, ok := agentBrokerRuntimes.Load(s); ok {
		return v.(*agentBrokerRuntime)
	}
	rt := &agentBrokerRuntime{
		global: make(chan struct{}, agentBrokerMaxConcurrent),
		active: map[string]int{},
	}
	v, _ := agentBrokerRuntimes.LoadOrStore(s, rt)
	return v.(*agentBrokerRuntime)
}

// agentAccess returns the agents core the handlers use.
func (s *Server) agentAccess() agentAccess {
	if a := s.agentBrokerRT().access; a != nil {
		return a
	}
	return serverAgentAccess{s}
}

// acquire reserves a broker slot for the agent; release must be called
// when ok.
func (rt *agentBrokerRuntime) acquire(agentID string) (release func(), ok bool) {
	select {
	case rt.global <- struct{}{}:
	default:
		return nil, false
	}
	rt.mu.Lock()
	if rt.active[agentID] >= agentBrokerMaxConcurrentPerAgent {
		rt.mu.Unlock()
		<-rt.global
		return nil, false
	}
	rt.active[agentID]++
	rt.mu.Unlock()
	return func() {
		rt.mu.Lock()
		if rt.active[agentID]--; rt.active[agentID] <= 0 {
			delete(rt.active, agentID)
		}
		rt.mu.Unlock()
		<-rt.global
	}, true
}

func (rt *agentBrokerRuntime) httpClient(allowed []netip.Prefix) *http.Client {
	if rt.client != nil {
		return rt.client(allowed)
	}
	return newAgentBrokerHTTPClient(allowed, agentbroker.DefaultTimeout)
}

// metrics registers the broker's metrics on first use. Labels are bounded
// codes; never credential names, agent IDs, hosts or values.
func (s *Server) agentBrokerMetrics() *agentBrokerRuntime {
	rt := s.agentBrokerRT()
	rt.metricsOnce.Do(func() {
		reg := s.obsRuntime().reg
		rt.reqs = reg.NewCounterVec("citadel_agent_http_requests_total", "Brokered agent HTTP requests by entry point (api, mcp), result and denial or error reason.", "via", "result", "reason")
		rt.upstream = reg.NewCounterVec("citadel_agent_http_upstream_responses_total", "Upstream responses to brokered agent HTTP requests by status class.", "class")
		rt.duration = reg.NewHistogramVec("citadel_agent_http_duration_seconds", "Duration of brokered agent HTTP requests that reached the upstream.", metrics.DefaultBuckets, "via")
		rt.reveals = reg.NewCounterVec("citadel_agent_reveals_total", "Agent credential reveals by entry point, result and reason.", "via", "result", "reason")
		rt.mcpReqs = reg.NewCounterVec("citadel_mcp_requests_total", "MCP JSON-RPC messages by method and outcome.", "method", "outcome")
		rt.mcpSessions = reg.NewCounterVec("citadel_mcp_sessions_total", "MCP sessions started and ended.", "event")
	})
	return rt
}

// metricReason bounds a reason code for use as a label.
func metricReason(reason string) string {
	if reason == "" {
		return "none"
	}
	if len(reason) > 40 {
		return "other"
	}
	for _, c := range reason {
		if !(c >= 'a' && c <= 'z' || c == '_') {
			return "other"
		}
	}
	return reason
}
