package store

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"strings"
	"time"
)

// Agents (2.2): AI agents as first-class principals that use credentials
// without holding them. See docs/design/agent-credentials.md.
//
//   - Agent: a principal in one account, owned by a console user.
//   - AgentToken: a bearer credential "cagt_<agentId>_<secret>", stored as a
//     PBKDF2 hash with a short non-secret lookup hint.
//   - AgentBinding: workload identity federation; a JWT whose issuer,
//     subject and audience match authenticates as the agent.
//   - AgentCredential: a usage profile that makes a secret usable by agents
//     (how it is injected and where it may be sent).
//   - AgentGrant: the policy binding an agent to a credential.
//   - AgentSettings: the account-wide kill switch.
//
// Every method takes the account explicitly; nothing is read from the
// context, so a missing caller account can never widen a query. The only
// cross-account reads are the authentication lookups (LookupAgent,
// FindAgentTokens, FindAgentBindings), which are keyed by values the caller
// presents.

// Agent statuses.
const (
	AgentStatusActive    = "active"
	AgentStatusSuspended = "suspended"
	// AgentStatusRevoked is permanent.
	AgentStatusRevoked = "revoked"
)

// Credential kinds (AgentCredential.Kind).
const (
	AgentCredentialHTTPHeader = "http_header"
	AgentCredentialHTTPBasic  = "http_basic"
	AgentCredentialHTTPQuery  = "http_query"
	AgentCredentialLogin      = "login"
	AgentCredentialRaw        = "raw"
)

// Grant actions.
const (
	AgentActionUse    = "use"
	AgentActionReveal = "reveal"
	AgentActionTOTP   = "totp"
)

var (
	ErrAgentNotFound           = errors.New("agent not found")
	ErrAgentExists             = errors.New("an agent with that name already exists")
	ErrAgentRevoked            = errors.New("the agent is revoked")
	ErrAgentTokenNotFound      = errors.New("agent token not found")
	ErrAgentBindingNotFound    = errors.New("agent binding not found")
	ErrAgentBindingExists      = errors.New("the agent already has that binding")
	ErrAgentCredentialNotFound = errors.New("agent credential not found")
	ErrAgentCredentialExists   = errors.New("an agent credential with that name already exists")
	ErrAgentCredentialInUse    = errors.New("the agent credential is used by grants")
	ErrAgentGrantNotFound      = errors.New("agent grant not found")
)

// Agent is an AI agent principal.
type Agent struct {
	AccountID   string
	AgentID     string
	Name        string
	Description string
	// Owner is the console username accountable for the agent.
	Owner     string
	Status    string
	Labels    map[string]string
	CreatedAt time.Time
	CreatedBy string
	UpdatedAt time.Time
	// LastUsedAt is updated (throttled) when the agent authenticates.
	LastUsedAt *time.Time
	// StatusChangedAt/By/Reason describe the last suspend, resume or revoke.
	StatusChangedAt *time.Time
	StatusChangedBy string
	StatusReason    string
	// RequireFederation refuses agent tokens: the agent must authenticate
	// with workload identity federation (2.3).
	RequireFederation bool
}

// AgentToken is an agent bearer token. Hash is a PBKDF2 hash of the secret
// part; Hint is the secret's first AgentTokenHintLen characters, kept so a
// presented token can be matched to its row without trying every hash.
type AgentToken struct {
	AccountID  string
	AgentID    string
	TokenID    string
	Name       string
	Hint       string
	Hash       string
	CreatedAt  time.Time
	CreatedBy  string
	ExpiresAt  *time.Time
	RevokedAt  *time.Time
	RevokedBy  string
	LastUsedAt *time.Time
}

// Active reports whether the token is usable at now.
func (t AgentToken) Active(now time.Time) bool {
	return t.RevokedAt == nil && (t.ExpiresAt == nil || now.Before(*t.ExpiresAt))
}

// AgentBinding lets a workload identity token (issuer, subject, audience
// matched exactly) authenticate as the agent.
type AgentBinding struct {
	AccountID   string
	AgentID     string
	BindingID   string
	Issuer      string
	Subject     string
	Audience    string
	Description string
	CreatedAt   time.Time
	CreatedBy   string
}

// AgentCredential is a usage profile: a secret plus how agents may use it.
type AgentCredential struct {
	AccountID string
	// Name is how agents refer to the credential ("github-pat").
	Name string
	// SecretName is the backing Secrets Manager secret name (native items
	// are "project/env/.../key").
	SecretName          string
	Kind                string
	Description         string
	AllowedHosts        []string
	AllowedMethods      []string
	AllowedPathPrefixes []string
	HeaderName          string
	HeaderPrefix        string
	QueryParam          string
	AllowHTTP           bool
	AllowedCIDRs        []string
	CreatedAt           time.Time
	CreatedBy           string
	UpdatedAt           time.Time
	UpdatedBy           string
}

// AgentGrant binds an agent to a credential.
type AgentGrant struct {
	AccountID  string
	GrantID    string
	AgentID    string
	Credential string
	Actions    []string
	NotBefore  *time.Time
	NotAfter   *time.Time
	// WindowStart/WindowEnd are "HH:MM" in Timezone; both empty means any
	// time of day. End before start wraps past midnight. WindowDays limits
	// the window to weekdays ("mon".."sun"); empty means every day.
	WindowStart string
	WindowEnd   string
	WindowDays  []string
	Timezone    string
	// MaxUsesPerHour limits uses of the grant; 0 means unlimited.
	MaxUsesPerHour int
	// RequiresApproval makes every action need a lease from an approved
	// access request (2.3). LeaseTTLSeconds caps how long an approval may
	// last; without RequiresApproval, a use opens a lease of that length
	// automatically. nil means not set.
	RequiresApproval *bool
	LeaseTTLSeconds  *int
	CreatedAt        time.Time
	CreatedBy        string
	UpdatedAt        time.Time
	UpdatedBy        string
}

// HasAction reports whether the grant allows action.
func (g AgentGrant) HasAction(action string) bool {
	for _, a := range g.Actions {
		if a == action {
			return true
		}
	}
	return false
}

// AgentSettings is an account's agent-wide state: the kill switch.
type AgentSettings struct {
	AccountID       string
	AgentsSuspended bool
	SuspendedAt     *time.Time
	SuspendedBy     string
	Reason          string
	UpdatedAt       time.Time
}

// AgentStore persists agents, their tokens, federation bindings, grants,
// credential usage profiles and the account kill switch.
type AgentStore interface {
	// CreateAgent stores a new agent (ErrAgentExists when the name is taken
	// in the account).
	CreateAgent(ctx context.Context, a Agent) error
	GetAgent(ctx context.Context, accountID, agentID string) (Agent, error)
	// LookupAgent finds an agent by ID in any account (authentication).
	LookupAgent(ctx context.Context, agentID string) (Agent, error)
	ListAgents(ctx context.Context, accountID string) ([]Agent, error)
	// UpdateAgent stores name, description, owner, labels and
	// RequireFederation.
	UpdateAgent(ctx context.Context, a Agent) error
	// SetAgentStatus moves the agent to status (ErrAgentRevoked once
	// revoked). Revoking also revokes every active token.
	SetAgentStatus(ctx context.Context, accountID, agentID, status, by, reason string, at time.Time) (Agent, error)
	// DeleteAgent removes the agent with its tokens, bindings and grants.
	DeleteAgent(ctx context.Context, accountID, agentID string) error
	// TouchAgentUsed records a successful authentication (tokenID may be
	// "" for federation).
	TouchAgentUsed(ctx context.Context, accountID, agentID, tokenID string, at time.Time) error

	CreateAgentToken(ctx context.Context, t AgentToken) error
	ListAgentTokens(ctx context.Context, accountID, agentID string) ([]AgentToken, error)
	// FindAgentTokens returns agentID's tokens whose hint is hint, in any
	// account (authentication).
	FindAgentTokens(ctx context.Context, agentID, hint string) ([]AgentToken, error)
	RevokeAgentToken(ctx context.Context, accountID, agentID, tokenID, by string, at time.Time) error

	// CreateAgentBinding stores a binding (ErrAgentBindingExists for a
	// duplicate issuer/subject/audience on the agent).
	CreateAgentBinding(ctx context.Context, b AgentBinding) error
	ListAgentBindings(ctx context.Context, accountID, agentID string) ([]AgentBinding, error)
	// FindAgentBindings returns bindings for issuer and subject in any
	// account (authentication).
	FindAgentBindings(ctx context.Context, issuer, subject string) ([]AgentBinding, error)
	DeleteAgentBinding(ctx context.Context, accountID, agentID, bindingID string) error

	// CreateAgentCredential stores a new usage profile
	// (ErrAgentCredentialExists); UpdateAgentCredential replaces an
	// existing one's fields (not its name or creation).
	CreateAgentCredential(ctx context.Context, c AgentCredential) error
	UpdateAgentCredential(ctx context.Context, c AgentCredential) error
	GetAgentCredential(ctx context.Context, accountID, name string) (AgentCredential, error)
	ListAgentCredentials(ctx context.Context, accountID string) ([]AgentCredential, error)
	// DeleteAgentCredential removes a profile (ErrAgentCredentialInUse while
	// grants reference it).
	DeleteAgentCredential(ctx context.Context, accountID, name string) error

	// PutAgentGrant creates or replaces the grant for (agent, credential);
	// the stored grant (with its ID) is returned.
	PutAgentGrant(ctx context.Context, g AgentGrant) (AgentGrant, error)
	// ListAgentGrants lists an agent's grants, or every grant in the account
	// when agentID is "".
	ListAgentGrants(ctx context.Context, accountID, agentID string) ([]AgentGrant, error)
	DeleteAgentGrant(ctx context.Context, accountID, agentID, grantID string) error

	// GetAgentSettings returns the account's settings (zero value when
	// none were stored).
	GetAgentSettings(ctx context.Context, accountID string) (AgentSettings, error)
	PutAgentSettings(ctx context.Context, s AgentSettings) error
}

// AgentTokenPrefix starts every agent token.
const AgentTokenPrefix = "cagt_"

// AgentTokenHintLen is how many leading characters of a token's secret are
// stored in clear as its lookup hint (40 of 256 bits).
const AgentTokenHintLen = 8

var agentB32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func agentRandom(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return strings.ToLower(agentB32.EncodeToString(b))
}

// NewAgentID returns "agt_" + 20 base32 characters.
func NewAgentID() string { return "agt_" + agentRandom(13)[:20] }

// NewAgentObjectID returns prefix + 16 base32 characters (token, binding and
// grant IDs).
func NewAgentObjectID(prefix string) string { return prefix + agentRandom(10)[:16] }

// NewAgentTokenSecret returns 256 random bits, base32 encoded (52
// characters).
func NewAgentTokenSecret() string { return agentRandom(32) }

// IsAgentID reports whether s has the shape of an agent ID.
func IsAgentID(s string) bool {
	if len(s) != 24 || !strings.HasPrefix(s, "agt_") {
		return false
	}
	for _, c := range s[4:] {
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}

// FormatAgentToken builds the presented token.
func FormatAgentToken(agentID, secret string) string {
	return AgentTokenPrefix + agentID + "_" + secret
}

// ParseAgentToken splits a presented token into its agent ID and secret.
func ParseAgentToken(tok string) (agentID, secret string, ok bool) {
	rest, found := strings.CutPrefix(tok, AgentTokenPrefix)
	if !found || len(rest) < 26 {
		return "", "", false
	}
	agentID, secret = rest[:24], rest[25:]
	if rest[24] != '_' || !IsAgentID(agentID) || len(secret) != 52 {
		return "", "", false
	}
	for _, c := range secret {
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return "", "", false
		}
	}
	return agentID, secret, true
}
