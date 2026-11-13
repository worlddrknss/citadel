package citadel

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// AI agents (Citadel 2.2): management with an access key, and the Agent API
// with an agent token (Config.AgentToken). See docs/agents.md.

// Agent is an AI agent principal.
type Agent struct {
	AgentID          string            `json:"agentId"`
	Name             string            `json:"name"`
	Description      string            `json:"description"`
	Owner            string            `json:"owner"`
	Status           string            `json:"status"` // active, suspended or revoked
	Labels           map[string]string `json:"labels"`
	CreatedAt        time.Time         `json:"createdAt"`
	UpdatedAt        time.Time         `json:"updatedAt"`
	LastUsedAt       *time.Time        `json:"lastUsedAt,omitempty"`
	StatusReason     string            `json:"statusReason,omitempty"`
	GrantCount       int               `json:"grantCount"`
	ActiveTokenCount int               `json:"activeTokenCount"`
	// RequireFederation: agent tokens are refused (2.3).
	RequireFederation bool `json:"requireFederation"`
	CanManage         bool `json:"canManage"`
}

// CreateAgentInput describes a new agent. Owner defaults to the key's owner.
type CreateAgentInput struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Owner       string            `json:"owner,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	// RequireFederation refuses agent tokens: the agent must authenticate
	// with workload identity federation (2.3).
	RequireFederation bool `json:"requireFederation,omitempty"`
}

// ListAgents lists the account's agents.
func (c *Client) ListAgents(ctx context.Context) ([]Agent, error) {
	var out struct {
		Agents []Agent `json:"agents"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/agents", nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Agents, nil
}

// CreateAgent creates an agent.
func (c *Client) CreateAgent(ctx context.Context, in CreateAgentInput) (*Agent, error) {
	var out Agent
	if err := c.do(ctx, http.MethodPost, "/v1/agents", nil, in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SuspendAgent refuses every request of the agent until ResumeAgent.
func (c *Client) SuspendAgent(ctx context.Context, agentID, reason string) (*Agent, error) {
	return c.agentStatus(ctx, "suspend", agentID, reason)
}

// ResumeAgent resumes a suspended agent.
func (c *Client) ResumeAgent(ctx context.Context, agentID string) (*Agent, error) {
	return c.agentStatus(ctx, "resume", agentID, "")
}

// RevokeAgent revokes the agent and all its tokens, permanently.
func (c *Client) RevokeAgent(ctx context.Context, agentID, reason string) (*Agent, error) {
	return c.agentStatus(ctx, "revoke", agentID, reason)
}

func (c *Client) agentStatus(ctx context.Context, verb, agentID, reason string) (*Agent, error) {
	var out Agent
	if err := c.do(ctx, http.MethodPost, "/v1/agents/"+verb, nil, map[string]string{"agentId": agentID, "reason": reason}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteAgent deletes the agent with its tokens, bindings and grants.
func (c *Client) DeleteAgent(ctx context.Context, agentID string) error {
	return c.do(ctx, http.MethodDelete, "/v1/agents", url.Values{"agentId": {agentID}}, nil, nil)
}

// AgentToken is a new agent token. Token is shown only once.
type AgentToken struct {
	Token     string     `json:"token"`
	TokenID   string     `json:"-"`
	ExpiresAt *time.Time `json:"-"`
}

// CreateAgentToken issues a token for the agent. expiresInDays 0 means no
// expiry (at most 365).
func (c *Client) CreateAgentToken(ctx context.Context, agentID, name string, expiresInDays int) (*AgentToken, error) {
	var out struct {
		Token     string `json:"token"`
		TokenInfo struct {
			TokenID   string     `json:"tokenId"`
			ExpiresAt *time.Time `json:"expiresAt,omitempty"`
		} `json:"tokenInfo"`
	}
	body := map[string]any{"agentId": agentID, "name": name, "expiresInDays": expiresInDays}
	if err := c.do(ctx, http.MethodPost, "/v1/agents/tokens", nil, body, &out); err != nil {
		return nil, err
	}
	return &AgentToken{Token: out.Token, TokenID: out.TokenInfo.TokenID, ExpiresAt: out.TokenInfo.ExpiresAt}, nil
}

// RevokeAgentToken revokes one of the agent's tokens.
func (c *Client) RevokeAgentToken(ctx context.Context, agentID, tokenID string) error {
	return c.do(ctx, http.MethodPost, "/v1/agents/tokens/revoke", nil, map[string]string{"agentId": agentID, "tokenId": tokenID}, nil)
}

// AgentCredentialInput makes a secret usable by agents (a usage profile).
// Name the secret with Secret (name or ARN) or Project, Env, Path and Key.
type AgentCredentialInput struct {
	Name    string `json:"name"`
	Secret  string `json:"secret,omitempty"`
	Project string `json:"project,omitempty"`
	Env     string `json:"env,omitempty"`
	Path    string `json:"path,omitempty"`
	Key     string `json:"key,omitempty"`
	// Kind is http_header, http_basic, http_query, login, raw, aws_sts,
	// github_app or oauth2_client_credentials.
	Kind                string   `json:"kind"`
	Description         string   `json:"description,omitempty"`
	AllowedHosts        []string `json:"allowedHosts,omitempty"`
	AllowedMethods      []string `json:"allowedMethods,omitempty"`
	AllowedPathPrefixes []string `json:"allowedPathPrefixes,omitempty"`
	HeaderName          string   `json:"headerName,omitempty"`
	HeaderPrefix        string   `json:"headerPrefix,omitempty"`
	QueryParam          string   `json:"queryParam,omitempty"`
	AllowHTTP           bool     `json:"allowHttp,omitempty"`
	AllowedCIDRs        []string `json:"allowedCidrs,omitempty"`

	// The kind's settings (2.4): set the one matching Kind.
	Login     *AgentLoginConfig     `json:"login,omitempty"`
	AWSSTS    *AgentAWSSTSConfig    `json:"awsSts,omitempty"`
	GitHubApp *AgentGitHubAppConfig `json:"githubApp,omitempty"`
	OAuth2    *AgentOAuth2Config    `json:"oauth2,omitempty"`
}

// CreateAgentCredential stores a usage profile.
func (c *Client) CreateAgentCredential(ctx context.Context, in AgentCredentialInput) error {
	return c.do(ctx, http.MethodPost, "/v1/agents/credentials", nil, in, nil)
}

// AgentGrantWindow limits a grant to a time of day (HH:MM, end before start
// wraps past midnight) in an IANA timezone, optionally on some weekdays.
type AgentGrantWindow struct {
	Start    string   `json:"start"`
	End      string   `json:"end"`
	Days     []string `json:"days,omitempty"`
	Timezone string   `json:"timezone,omitempty"`
}

// AgentGrantInput grants an agent access to a credential.
type AgentGrantInput struct {
	AgentID        string            `json:"agentId"`
	Credential     string            `json:"credential"`
	Actions        []string          `json:"actions,omitempty"` // use (default), reveal, totp
	NotBefore      *time.Time        `json:"notBefore,omitempty"`
	NotAfter       *time.Time        `json:"notAfter,omitempty"`
	Window         *AgentGrantWindow `json:"window,omitempty"`
	MaxUsesPerHour int               `json:"maxUsesPerHour,omitempty"`
	// RequiresApproval makes every use need an approved access request;
	// LeaseTTLSeconds (60-86400) caps approvals or, without
	// RequiresApproval, opens a lease of that length on first use (2.3).
	RequiresApproval bool `json:"requiresApproval,omitempty"`
	LeaseTTLSeconds  int  `json:"leaseTtlSeconds,omitempty"`

	// Scope narrows a minted credential's tokens (2.4).
	Scope *AgentGrantScope `json:"scope,omitempty"`
}

// PutAgentGrant creates or replaces the agent's grant for the credential and
// returns its ID.
func (c *Client) PutAgentGrant(ctx context.Context, in AgentGrantInput) (string, error) {
	var out struct {
		GrantID string `json:"grantId"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/agents/grants", nil, in, &out); err != nil {
		return "", err
	}
	return out.GrantID, nil
}

// SetAgentsSuspended turns the account-wide kill switch on or off (admin).
func (c *Client) SetAgentsSuspended(ctx context.Context, suspended bool, reason string) error {
	return c.do(ctx, http.MethodPost, "/v1/agents/settings", nil, map[string]any{"agentsSuspended": suspended, "reason": reason}, nil)
}

// ---- Agent API (agent token) -------------------------------------------------

// AgentIdentity is the calling agent, from AgentWhoAmI.
type AgentIdentity struct {
	AgentID        string     `json:"agentId"`
	Name           string     `json:"name"`
	Owner          string     `json:"owner"`
	AccountID      string     `json:"accountId"`
	Status         string     `json:"status"`
	AuthMethod     string     `json:"authMethod"`
	TokenID        string     `json:"tokenId,omitempty"`
	TokenExpiresAt *time.Time `json:"tokenExpiresAt,omitempty"`
}

// AgentWhoAmI describes the calling agent. The client must be configured
// with an agent token.
func (c *Client) AgentWhoAmI(ctx context.Context) (*AgentIdentity, error) {
	var out AgentIdentity
	if err := c.do(ctx, http.MethodGet, "/v1/agent/whoami", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UsableCredential is a credential the calling agent may use. It never
// carries the value.
type UsableCredential struct {
	Name           string   `json:"name"`
	Kind           string   `json:"kind"`
	Description    string   `json:"description"`
	AllowedHosts   []string `json:"allowedHosts"`
	AllowedMethods []string `json:"allowedMethods"`
	Actions        []string `json:"actions"`
	// RequiresApproval: uses need an approved access request (2.3).
	RequiresApproval bool   `json:"requiresApproval"`
	Usable           bool   `json:"usable"`
	Reason           string `json:"reason,omitempty"`
	// URLPatterns are the pages a login credential may be used on (2.4).
	URLPatterns []string `json:"urlPatterns,omitempty"`
}

// AgentCredentials lists the credentials the calling agent has grants for.
func (c *Client) AgentCredentials(ctx context.Context) ([]UsableCredential, error) {
	var out struct {
		Credentials []UsableCredential `json:"credentials"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/agent/credentials", nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Credentials, nil
}
