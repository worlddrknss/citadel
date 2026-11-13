package store

import (
	"context"
	"errors"
	"maps"
	"slices"
	"time"
)

// Agent credentials for browser agents and provider-scoped tokens (2.4). See
// docs/design/agent-credentials.md.
//
//   - login: the secret is JSON {username, password, totpSeed?}; the profile
//     lists the URL patterns a login may be used on.
//   - aws_sts, github_app, oauth2_client_credentials: the secret holds the
//     long-lived source material (AWS keys, the App private key, the OAuth
//     client secret); the profile holds how to mint a short-lived token from
//     it. Agents only ever receive or use the minted token.
//
// The kind-specific settings live in AgentCredential.Config, the per-grant
// narrowing in AgentGrant.Scope. Both are stored as JSON documents.

// Minted credential kinds (AgentCredential.Kind).
const (
	AgentCredentialAWSSTS    = "aws_sts"
	AgentCredentialGitHubApp = "github_app"
	AgentCredentialOAuth2    = "oauth2_client_credentials"
)

// IsMintedAgentKind reports whether kind is minted on use.
func IsMintedAgentKind(kind string) bool {
	switch kind {
	case AgentCredentialAWSSTS, AgentCredentialGitHubApp, AgentCredentialOAuth2:
		return true
	}
	return false
}

// AgentCredentialConfig holds the kind-specific settings of a usage profile.
// At most one member is set, matching the credential's kind. Nothing in it
// is secret.
type AgentCredentialConfig struct {
	Login     *AgentLoginConfig     `json:"login,omitempty"`
	AWSSTS    *AgentAWSSTSConfig    `json:"awsSts,omitempty"`
	GitHubApp *AgentGitHubAppConfig `json:"githubApp,omitempty"`
	OAuth2    *AgentOAuth2Config    `json:"oauth2,omitempty"`
}

// AgentLoginConfig configures a login credential.
type AgentLoginConfig struct {
	// URLPatterns are the pages the login may be used on:
	// "https://host[:port][/path-prefix]", the host optionally "*.suffix".
	URLPatterns []string `json:"urlPatterns,omitempty"`
	// TOTPAlgorithm, TOTPDigits and TOTPPeriod apply to a bare base32
	// totpSeed (an otpauth:// URI carries its own). Empty algorithm means
	// SHA1, which FIPS 140-3 mode cannot compute.
	TOTPAlgorithm string `json:"totpAlgorithm,omitempty"`
	TOTPDigits    int    `json:"totpDigits,omitempty"`
	TOTPPeriod    int    `json:"totpPeriod,omitempty"`
}

// AgentAWSSTSConfig configures an aws_sts credential: AssumeRole with the
// source keys stored in the secret.
type AgentAWSSTSConfig struct {
	RoleARN string `json:"roleArn"`
	// Endpoint is the STS endpoint (empty: AWS's global endpoint).
	Endpoint string `json:"endpoint,omitempty"`
	// Region signs the AssumeRole call and, unless SigningRegion is set,
	// brokered requests.
	Region          string `json:"region,omitempty"`
	ExternalID      string `json:"externalId,omitempty"`
	SessionName     string `json:"sessionName,omitempty"`
	SessionPolicy   string `json:"sessionPolicy,omitempty"`
	DurationSeconds int    `json:"durationSeconds,omitempty"`
	// SigningService and SigningRegion are used to SigV4-sign brokered
	// requests (for example "s3", "eu-west-1").
	SigningService string `json:"signingService,omitempty"`
	SigningRegion  string `json:"signingRegion,omitempty"`
}

// AgentGitHubAppConfig configures a github_app credential: installation
// tokens minted with the App private key stored in the secret.
type AgentGitHubAppConfig struct {
	AppID          string `json:"appId"`
	InstallationID int64  `json:"installationId"`
	// BaseURL is the REST API base (empty: https://api.github.com).
	BaseURL string `json:"baseUrl,omitempty"`
	// Repositories and Permissions are the default restriction; grants
	// may narrow them.
	Repositories []string          `json:"repositories,omitempty"`
	Permissions  map[string]string `json:"permissions,omitempty"`
}

// AgentOAuth2Config configures an oauth2_client_credentials credential: the
// secret holds the client secret (or JSON {clientId, clientSecret}).
type AgentOAuth2Config struct {
	TokenURL string `json:"tokenUrl"`
	ClientID string `json:"clientId,omitempty"`
	// ClientAuth is "basic" (client_secret_basic, the default) or "post".
	ClientAuth string   `json:"clientAuth,omitempty"`
	Scopes     []string `json:"scopes,omitempty"`
	Audience   string   `json:"audience,omitempty"`
	Resource   string   `json:"resource,omitempty"`
	// HeaderName and HeaderPrefix shape brokered injection (default
	// "Authorization: Bearer <token>").
	HeaderName   string `json:"headerName,omitempty"`
	HeaderPrefix string `json:"headerPrefix,omitempty"`
}

// AgentGrantScope narrows what a grant's minted tokens may do. Empty means
// the credential's defaults.
type AgentGrantScope struct {
	// github_app: a subset of the credential's repositories and
	// permissions (no higher levels).
	Repositories []string          `json:"repositories,omitempty"`
	Permissions  map[string]string `json:"permissions,omitempty"`
	// aws_sts: an inline session policy, only when the credential has none.
	SessionPolicy string `json:"sessionPolicy,omitempty"`
	// oauth2_client_credentials: a subset of the credential's scopes.
	Scopes []string `json:"scopes,omitempty"`
}

// IsZero reports whether the scope narrows nothing.
func (s AgentGrantScope) IsZero() bool {
	return len(s.Repositories) == 0 && len(s.Permissions) == 0 && s.SessionPolicy == "" && len(s.Scopes) == 0
}

// Clone deep-copies the config.
func (c AgentCredentialConfig) Clone() AgentCredentialConfig {
	if c.Login != nil {
		v := *c.Login
		v.URLPatterns = slices.Clone(v.URLPatterns)
		c.Login = &v
	}
	if c.AWSSTS != nil {
		v := *c.AWSSTS
		c.AWSSTS = &v
	}
	if c.GitHubApp != nil {
		v := *c.GitHubApp
		v.Repositories, v.Permissions = slices.Clone(v.Repositories), maps.Clone(v.Permissions)
		c.GitHubApp = &v
	}
	if c.OAuth2 != nil {
		v := *c.OAuth2
		v.Scopes = slices.Clone(v.Scopes)
		c.OAuth2 = &v
	}
	return c
}

// Clone deep-copies the scope.
func (s AgentGrantScope) Clone() AgentGrantScope {
	s.Repositories, s.Permissions, s.Scopes = slices.Clone(s.Repositories), maps.Clone(s.Permissions), slices.Clone(s.Scopes)
	return s
}

// Anomaly kinds (AgentAnomaly.Kind).
const (
	AgentAnomalyNewHost         = "new_host"
	AgentAnomalyOffHours        = "off_hours"
	AgentAnomalyRateSpike       = "rate_spike"
	AgentAnomalyRepeatedDenials = "repeated_denials"
)

// ErrAgentAnomalyDuplicate is returned by RecordAgentAnomaly when the same
// kind was already recorded for the agent in the same hour.
var ErrAgentAnomalyDuplicate = errors.New("anomaly already recorded this hour")

// AgentAnomalySettings are an agent's anomaly alert settings. The zero value
// (no row stored) means alerts on, auto-suspend off.
type AgentAnomalySettings struct {
	AccountID string
	AgentID   string
	// AlertsDisabled turns anomaly notifications off for the agent.
	AlertsDisabled bool
	// AutoSuspend suspends the agent when an anomaly is detected.
	AutoSuspend bool
	UpdatedAt   time.Time
	UpdatedBy   string
}

// AgentAnomaly is a detected anomaly.
type AgentAnomaly struct {
	AccountID string
	AgentID   string
	AnomalyID string
	Kind      string
	// Detail is a short human-readable description (host, counts); never a
	// secret.
	Detail string
	// Hour is the UTC hour the anomaly is de-duplicated in.
	Hour       time.Time
	DetectedAt time.Time
	// Suspended reports whether the agent was suspended automatically.
	Suspended bool
}

// AgentAnomalyStore persists per-agent anomaly settings and detected
// anomalies.
type AgentAnomalyStore interface {
	// GetAgentAnomalySettings returns the agent's settings (zero value
	// with the IDs set when none were stored).
	GetAgentAnomalySettings(ctx context.Context, accountID, agentID string) (AgentAnomalySettings, error)
	PutAgentAnomalySettings(ctx context.Context, s AgentAnomalySettings) error
	// RecordAgentAnomaly stores an anomaly unless one of the same kind was
	// recorded for the agent in the same hour (ErrAgentAnomalyDuplicate),
	// which de-duplicates across replicas.
	RecordAgentAnomaly(ctx context.Context, a AgentAnomaly) error
	// MarkAgentAnomalySuspended records that the anomaly suspended the
	// agent.
	MarkAgentAnomalySuspended(ctx context.Context, accountID, anomalyID string) error
	// ListAgentAnomalies returns the agent's anomalies, newest first, at
	// most limit.
	ListAgentAnomalies(ctx context.Context, accountID, agentID string, limit int) ([]AgentAnomaly, error)
}
