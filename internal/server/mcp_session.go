package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
)

// MCP sessions.
//
// A session ID (Mcp-Session-Id) is issued by initialize and is a signed,
// self-contained token: the agent and account it belongs to, the negotiated
// protocol version, a random nonce and an expiry, MACed with a key derived
// from the deployment secret. Any replica can therefore check it without
// shared state. It grants nothing by itself: every request still carries
// the agent's Bearer credential, and the session must belong to that agent.
//
// DELETE /mcp ends a session. The ended nonce is remembered (until the
// session would have expired) by the replica that handled the DELETE; other
// replicas keep accepting the session until it expires. That is acceptable
// because a session is not a credential.

const (
	mcpSessionPrefix   = "mcs1."
	mcpSessionLifetime = 24 * time.Hour
	maxMCPSessionLen   = 512
	// mcpEndedMax bounds the remembered ended sessions per replica.
	mcpEndedMax = 100000
)

type mcpSessionClaims struct {
	Account string `json:"c"`
	Agent   string `json:"a"`
	Version string `json:"v"`
	Nonce   string `json:"n"`
	Expires int64  `json:"e"`
}

type mcpSessions struct {
	once      sync.Once
	ephemeral []byte

	mu    sync.Mutex
	ended map[string]time.Time // nonce -> expiry
}

// mcpSessionKey is the signing key: derived from the deployment secret, or
// a per-process random key when there is none (sessions then only work on
// the replica that issued them).
func (s *Server) mcpSessionKey() []byte {
	if root := s.deploymentSecret(); len(root) > 0 {
		return cryptoutil.DeriveMCPSessionKey(root)
	}
	ss := &s.agentBrokerRT().sessions
	ss.once.Do(func() {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			panic(err)
		}
		ss.ephemeral = b
	})
	return ss.ephemeral
}

func (s *Server) issueMCPSession(c *agentCaller, version string, now time.Time) (string, error) {
	n := make([]byte, 16)
	if _, err := rand.Read(n); err != nil {
		return "", err
	}
	payload, err := json.Marshal(mcpSessionClaims{Account: c.AccountID, Agent: c.AgentID, Version: version, Nonce: hex.EncodeToString(n), Expires: now.Add(mcpSessionLifetime).Unix()})
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, s.mcpSessionKey())
	mac.Write([]byte(mcpSessionPrefix))
	mac.Write(payload)
	return mcpSessionPrefix + b64url.EncodeToString(payload) + "." + b64url.EncodeToString(mac.Sum(nil)), nil
}

// parseMCPSession verifies a session ID for caller c.
func (s *Server) parseMCPSession(id string, c *agentCaller, now time.Time) (mcpSessionClaims, bool) {
	rest, ok := strings.CutPrefix(id, mcpSessionPrefix)
	if !ok || len(id) > maxMCPSessionLen {
		return mcpSessionClaims{}, false
	}
	p, sig, found := strings.Cut(rest, ".")
	if !found {
		return mcpSessionClaims{}, false
	}
	payload, err1 := b64url.DecodeString(p)
	got, err2 := b64url.DecodeString(sig)
	if err1 != nil || err2 != nil {
		return mcpSessionClaims{}, false
	}
	mac := hmac.New(sha256.New, s.mcpSessionKey())
	mac.Write([]byte(mcpSessionPrefix))
	mac.Write(payload)
	if !hmac.Equal(got, mac.Sum(nil)) {
		return mcpSessionClaims{}, false
	}
	var claims mcpSessionClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return mcpSessionClaims{}, false
	}
	if claims.Agent != c.AgentID || claims.Account != c.AccountID || now.Unix() >= claims.Expires || !mcpSupportedVersion(claims.Version) {
		return mcpSessionClaims{}, false
	}
	ss := &s.agentBrokerRT().sessions
	ss.mu.Lock()
	_, isEnded := ss.ended[claims.Nonce]
	ss.mu.Unlock()
	if isEnded {
		return mcpSessionClaims{}, false
	}
	return claims, true
}

// endMCPSession remembers that a session was ended.
func (s *Server) endMCPSession(claims mcpSessionClaims, now time.Time) {
	ss := &s.agentBrokerRT().sessions
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.ended == nil {
		ss.ended = map[string]time.Time{}
	}
	if len(ss.ended) >= mcpEndedMax {
		for k, exp := range ss.ended {
			if !now.Before(exp) {
				delete(ss.ended, k)
			}
		}
		if len(ss.ended) >= mcpEndedMax {
			return // ended sessions still expire on their own
		}
	}
	ss.ended[claims.Nonce] = time.Unix(claims.Expires, 0)
}
