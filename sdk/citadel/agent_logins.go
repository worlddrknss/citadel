package citadel

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// Agent credentials for browser agents and provider-scoped tokens (2.4):
// login credentials (username, password, TOTP), credentials minted on use
// (aws_sts, github_app, oauth2_client_credentials) and anomaly alerts.

// AgentLoginConfig configures a login credential (Kind "login").
type AgentLoginConfig struct {
	// URLPatterns are the pages the login may be used on:
	// "https://host[:port][/path]", the host optionally "*.example.com".
	URLPatterns []string `json:"urlPatterns"`
	// TOTPAlgorithm (SHA256 or SHA512), TOTPDigits and TOTPPeriod apply to
	// a bare base32 TOTP seed; an otpauth:// URI carries its own.
	TOTPAlgorithm string `json:"totpAlgorithm,omitempty"`
	TOTPDigits    int    `json:"totpDigits,omitempty"`
	TOTPPeriod    int    `json:"totpPeriod,omitempty"`
}

// AgentAWSSTSConfig configures an aws_sts credential. The secret holds
// JSON {accessKeyId, secretAccessKey, sessionToken?}.
type AgentAWSSTSConfig struct {
	RoleARN         string `json:"roleArn"`
	Endpoint        string `json:"endpoint,omitempty"`
	Region          string `json:"region,omitempty"`
	ExternalID      string `json:"externalId,omitempty"`
	SessionName     string `json:"sessionName,omitempty"`
	SessionPolicy   string `json:"sessionPolicy,omitempty"`
	DurationSeconds int    `json:"durationSeconds,omitempty"`
	// SigningService (for example "s3") lets the broker SigV4-sign
	// requests; SigningRegion defaults to Region.
	SigningService string `json:"signingService,omitempty"`
	SigningRegion  string `json:"signingRegion,omitempty"`
}

// AgentGitHubAppConfig configures a github_app credential. The secret holds
// the App's PEM private key.
type AgentGitHubAppConfig struct {
	AppID          string            `json:"appId"`
	InstallationID int64             `json:"installationId"`
	BaseURL        string            `json:"baseUrl,omitempty"`
	Repositories   []string          `json:"repositories,omitempty"`
	Permissions    map[string]string `json:"permissions,omitempty"`
}

// AgentOAuth2Config configures an oauth2_client_credentials credential. The
// secret holds the client secret (or JSON {clientId, clientSecret}).
type AgentOAuth2Config struct {
	TokenURL     string   `json:"tokenUrl"`
	ClientID     string   `json:"clientId,omitempty"`
	ClientAuth   string   `json:"clientAuth,omitempty"` // basic (default) or post
	Scopes       []string `json:"scopes,omitempty"`
	Audience     string   `json:"audience,omitempty"`
	Resource     string   `json:"resource,omitempty"`
	HeaderName   string   `json:"headerName,omitempty"`
	HeaderPrefix string   `json:"headerPrefix,omitempty"`
}

// AgentGrantScope narrows a minted credential's tokens for one grant.
type AgentGrantScope struct {
	Repositories  []string          `json:"repositories,omitempty"`  // github_app
	Permissions   map[string]string `json:"permissions,omitempty"`   // github_app
	SessionPolicy string            `json:"sessionPolicy,omitempty"` // aws_sts
	Scopes        []string          `json:"scopes,omitempty"`        // oauth2_client_credentials
}

// ---- Agent API (agent token) -------------------------------------------------

// TOTPCode is a login credential's current one-time code.
type TOTPCode struct {
	Credential       string    `json:"credential"`
	Code             string    `json:"code"`
	ExpiresAt        time.Time `json:"expiresAt"`
	SecondsRemaining int       `json:"secondsRemaining"`
	Digits           int       `json:"digits"`
	Period           int       `json:"period"`
	Algorithm        string    `json:"algorithm"`
}

// AgentTOTPCode returns the current TOTP code of a login credential (needs
// a totp grant). The seed never leaves Citadel.
func (c *Client) AgentTOTPCode(ctx context.Context, credential string) (*TOTPCode, error) {
	var out TOTPCode
	if err := c.do(ctx, http.MethodPost, "/v1/agent/totp", nil, map[string]string{"credential": credential}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AgentLogin is a login's username and password for one page.
type AgentLogin struct {
	Credential string `json:"credential"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	URLPattern string `json:"urlPattern"`
}

// AgentGetLogin returns a login credential's username and password for the
// page at pageURL, which must match the credential's URL patterns (needs a
// reveal grant).
func (c *Client) AgentGetLogin(ctx context.Context, credential, pageURL string) (*AgentLogin, error) {
	var out AgentLogin
	if err := c.do(ctx, http.MethodPost, "/v1/agent/login", nil, map[string]string{"credential": credential, "url": pageURL}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RevealedCredential is a revealed value. For minted credentials it is a
// short-lived token that stops working at ExpiresAt.
type RevealedCredential struct {
	Credential     string     `json:"credential"`
	Kind           string     `json:"kind"`
	Value          string     `json:"value"`
	ExpiresAt      *time.Time `json:"expiresAt,omitempty"`
	LeaseID        string     `json:"leaseId,omitempty"`
	LeaseExpiresAt *time.Time `json:"leaseExpiresAt,omitempty"`
}

// AgentReveal returns a credential's value (needs a reveal grant). Prefer
// brokered use.
func (c *Client) AgentReveal(ctx context.Context, credential string) (*RevealedCredential, error) {
	var out RevealedCredential
	if err := c.do(ctx, http.MethodPost, "/v1/agent/credentials/reveal", nil, map[string]string{"credential": credential}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Management API ------------------------------------------------------------

// AgentLoginInput sets a login credential's fields; nil fields are kept.
type AgentLoginInput struct {
	Name     string  `json:"name"`
	Username *string `json:"username,omitempty"`
	Password *string `json:"password,omitempty"`
	// TOTPSeed is an otpauth://totp/ URI or a base32 seed. SHA-1 seeds are
	// refused (Citadel runs in FIPS 140-3 mode).
	TOTPSeed      *string `json:"totpSeed,omitempty"`
	ClearTOTPSeed bool    `json:"clearTotpSeed,omitempty"`
}

// AgentLoginState is a login's state without its secrets.
type AgentLoginState struct {
	Name        string    `json:"name"`
	Username    string    `json:"username"`
	HasPassword bool      `json:"hasPassword"`
	HasTOTPSeed bool      `json:"hasTotpSeed"`
	TOTPStatus  string    `json:"totpStatus,omitempty"`
	TOTPMessage string    `json:"totpMessage,omitempty"`
	TOTP        *TOTPCode `json:"totp,omitempty"`
}

// SetAgentLogin writes a login credential's username, password and TOTP
// seed as a new version of its secret.
func (c *Client) SetAgentLogin(ctx context.Context, in AgentLoginInput) (*AgentLoginState, error) {
	var out AgentLoginState
	if err := c.do(ctx, http.MethodPost, "/v1/agents/credentials/login", nil, in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetAgentLogin reads a login credential's state; withCode adds the current
// TOTP code.
func (c *Client) GetAgentLogin(ctx context.Context, name string, withCode bool) (*AgentLoginState, error) {
	q := url.Values{"name": {name}}
	if withCode {
		q.Set("code", "true")
	}
	var out AgentLoginState
	if err := c.do(ctx, http.MethodGet, "/v1/agents/credentials/login", q, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Anomaly kinds.
const (
	AnomalyNewHost         = "new_host"
	AnomalyOffHours        = "off_hours"
	AnomalyRateSpike       = "rate_spike"
	AnomalyRepeatedDenials = "repeated_denials"
)

// AgentAnomaly is unusual agent behaviour Citadel detected.
type AgentAnomaly struct {
	AnomalyID  string    `json:"anomalyId"`
	Kind       string    `json:"kind"`
	Detail     string    `json:"detail"`
	DetectedAt time.Time `json:"detectedAt"`
	// Suspended reports that the anomaly suspended the agent.
	Suspended bool `json:"suspended"`
}

// AgentAnomalySettings are an agent's alert settings.
type AgentAnomalySettings struct {
	AlertsEnabled bool `json:"alertsEnabled"`
	AutoSuspend   bool `json:"autoSuspend"`
}

// AgentAnomalies is an agent's anomaly history and settings.
type AgentAnomalies struct {
	Anomalies []AgentAnomaly         `json:"anomalies"`
	Settings  AgentAnomalySettings   `json:"settings"`
	Baseline  map[string]interface{} `json:"baseline"`
}

// ListAgentAnomalies returns an agent's recent anomalies and its settings.
func (c *Client) ListAgentAnomalies(ctx context.Context, agentID string) (*AgentAnomalies, error) {
	var out AgentAnomalies
	if err := c.do(ctx, http.MethodGet, "/v1/agents/anomalies", url.Values{"agentId": {agentID}}, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SetAgentAnomalySettings turns an agent's anomaly alerts and auto-suspend
// on or off.
func (c *Client) SetAgentAnomalySettings(ctx context.Context, agentID string, s AgentAnomalySettings) (*AgentAnomalySettings, error) {
	var out AgentAnomalySettings
	body := map[string]any{"agentId": agentID, "alertsEnabled": s.AlertsEnabled, "autoSuspend": s.AutoSuspend}
	if err := c.do(ctx, http.MethodPost, "/v1/agents/anomaly-settings", nil, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
