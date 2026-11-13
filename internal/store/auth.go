package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrConsoleSessionNotFound is returned for an unknown, revoked or
	// already-purged console session.
	ErrConsoleSessionNotFound = errors.New("console session not found")
	// ErrAlreadyBootstrapped is returned by Bootstrap once any console user
	// exists.
	ErrAlreadyBootstrapped = errors.New("already bootstrapped")
	// ErrBootstrapTokenInvalid is returned by Bootstrap when
	// BootstrapTokenHash is set and doesn't match an unconsumed, unexpired
	// stored token (another replica consumed it first, or it expired).
	ErrBootstrapTokenInvalid = errors.New("bootstrap token invalid or already used")
)

// Console sign-in methods recorded on a session.
const (
	SessionMethodPassword = "password"
	SessionMethodSSO      = "sso"
)

// ConsoleSession is a signed-in web console session. Only a SHA-256 hash of
// the bearer token (the cookie value) is stored, so a database read does not
// yield usable sessions. ID is a separate public identifier used to list and
// revoke sessions.
type ConsoleSession struct {
	ID         string
	TokenHash  string
	Username   string
	AccountID  string
	Method     string
	IP         string
	UserAgent  string
	CreatedAt  time.Time
	LastSeenAt time.Time
	// ExpiresAt is the absolute expiry (creation + maximum lifetime). The
	// idle timeout is enforced from LastSeenAt.
	ExpiresAt time.Time
}

// OrgSettings are the organization-wide console settings. A deployment is one
// organization; its accounts are the tenants.
type OrgSettings struct {
	OrganizationName     string
	ApprovalEnvironments []string
	ApprovalMinApprovers int
	AllowSelfApproval    bool
	// SessionIdleMinutes and SessionMaxHours override the configured session
	// lifetimes when non-zero.
	SessionIdleMinutes int
	SessionMaxHours    int
	// RequireMFA forces password sign-ins without a second factor through
	// TOTP enrolment before they get a full session (SSO is exempt).
	RequireMFA bool
	UpdatedAt  time.Time // zero when never saved
	UpdatedBy  string
}

// SSOProvider is a console single sign-on (OIDC) provider. The client secret
// is never part of this record.
type SSOProvider struct {
	ID           string
	Name         string
	Issuer       string
	ClientID     string
	Scopes       []string
	GroupClaim   string
	RoleMappings []SSORoleMapping
	DefaultRole  string // none|viewer|editor|admin
	Enabled      bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
	// AccountID is the owning account: the default role is granted there,
	// and account admins of it may manage the provider while its role
	// mappings stay within it (see IdentityStore).
	AccountID string
	// AllowedEmailDomains restricts sign-in to these email domains (empty:
	// any).
	AllowedEmailDomains []string
	// ClientSecretSet reports whether a client secret is stored.
	ClientSecretSet bool
}

// SSORoleMapping grants a role in an account ("*" = every account) to members
// of an IdP group.
type SSORoleMapping struct {
	Group     string `json:"group"`
	AccountID string `json:"accountId"`
	Role      string `json:"role"`
}

// BootstrapRequest describes the first-run setup: the organization, its first
// account and the first (platform) admin.
type BootstrapRequest struct {
	OrganizationName string
	AccountName      string
	Username         string
	DisplayName      string
	PasswordHash     string
	// BootstrapTokenHash, when set, is the SHA-256 (hex) of the generated
	// bootstrap token the caller presented. A backend that stores generated
	// tokens (PostgreSQL) consumes it in the same transaction, so the token
	// works once across every replica.
	BootstrapTokenHash string
}

// AuthStore persists console authentication state: single-user lookups,
// first-run bootstrap, sessions, organization settings and SSO providers.
type AuthStore interface {
	GetUIUser(ctx context.Context, username string) (UIUser, error)
	CountUIUsers(ctx context.Context) (int, error)
	// Bootstrap atomically creates the first account, an admin user flagged
	// platform admin, its admin membership and the organization name. It
	// returns ErrAlreadyBootstrapped when any console user exists; concurrent
	// calls are serialized so exactly one succeeds.
	Bootstrap(ctx context.Context, req BootstrapRequest) (accountID string, err error)

	CreateConsoleSession(ctx context.Context, sess ConsoleSession) error
	GetConsoleSessionByTokenHash(ctx context.Context, tokenHash string) (ConsoleSession, error)
	TouchConsoleSession(ctx context.Context, id string, lastSeen time.Time) error
	SetConsoleSessionAccount(ctx context.Context, id, accountID string) error
	ListConsoleSessions(ctx context.Context, username string) ([]ConsoleSession, error)
	// DeleteConsoleSession revokes one of username's sessions.
	DeleteConsoleSession(ctx context.Context, username, id string) error
	// DeleteUserConsoleSessions revokes all of username's sessions except
	// keepID (which may be empty) and returns how many were revoked.
	DeleteUserConsoleSessions(ctx context.Context, username, keepID string) (int64, error)
	// DeleteExpiredConsoleSessions removes sessions past their absolute
	// expiry or idle since before idleCutoff (zero idleCutoff: absolute only).
	DeleteExpiredConsoleSessions(ctx context.Context, now, idleCutoff time.Time) (int64, error)

	GetOrgSettings(ctx context.Context) (OrgSettings, error)
	PutOrgSettings(ctx context.Context, settings OrgSettings) error

	// ListSSOProviders returns the console SSO providers, optionally only the
	// enabled ones.
	ListSSOProviders(ctx context.Context, enabledOnly bool) ([]SSOProvider, error)
}
