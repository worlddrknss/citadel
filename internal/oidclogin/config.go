// Package oidclogin is the OpenID Connect relying party behind Citadel's
// console sign-in with external providers (Okta, Entra ID, Google, Keycloak
// and any other standards-compliant OIDC provider). SAML is out of scope.
//
// The flow is the authorization code flow with PKCE (S256), state and nonce:
//
//	redirectURL, cookie, err := rp.Start(ctx, "okta", "/secrets")
//	http.SetCookie(w, cookie); http.Redirect(w, r, redirectURL, http.StatusFound)
//
//	// at the provider's RedirectURL:
//	id, err := rp.Callback(ctx, r)
//	http.SetCookie(w, rp.ClearCookie())
//	// map id to Citadel memberships, start a console session, redirect to id.ReturnTo
//
// The per-login state (state, nonce, PKCE verifier, provider, return path)
// lives in a short-lived cookie that is AES-256-GCM encrypted and
// HMAC-SHA256 authenticated with keys HKDF-derived from host-supplied secrets.
// The state value in the callback URL must equal the one sealed in the cookie,
// which binds the flow to the browser that started it, and each state is
// accepted once (ReplayStore).
//
// Everything uses only FIPS 140-3 approved primitives from the standard
// library, so the package works under GODEBUG=fips140=only.
package oidclogin

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/jose"
)

// Token endpoint client authentication methods.
const (
	AuthClientSecretBasic = "client_secret_basic"
	AuthClientSecretPost  = "client_secret_post"
)

// ProviderConfig describes one external OIDC provider.
type ProviderConfig struct {
	// ID is the stable identifier used in URLs and stored identities
	// ("okta", "entra"). Name is the button label.
	ID   string
	Name string
	// Issuer must equal the "issuer" in the provider's discovery document
	// and the "iss" of its ID tokens, byte for byte.
	Issuer       string
	ClientID     string
	ClientSecret string
	// Scopes requested; "openid" is always included. Default: openid email profile.
	Scopes []string
	// RedirectURL is Citadel's callback URL registered with the provider.
	RedirectURL string
	// Claim names; defaults "groups", "email", "preferred_username". A dotted
	// name ("realm_access.roles") walks nested objects when no claim with the
	// literal name exists.
	GroupsClaim   string
	EmailClaim    string
	UsernameClaim string
	// AllowedEmailDomains, when non-empty, restricts sign-in to identities
	// whose (verified) email address is in one of these domains (exact match,
	// case-insensitive; subdomains must be listed explicitly).
	AllowedEmailDomains []string
	// AllowUnverifiedEmail accepts emails without email_verified=true for the
	// domain allowlist. Needed for providers that never send email_verified
	// (Entra ID); only safe if the provider controls the email attribute.
	AllowUnverifiedEmail bool
	// TokenEndpointAuth is AuthClientSecretBasic (default) or AuthClientSecretPost.
	TokenEndpointAuth string
	// UseUserInfo merges claims from the UserInfo endpoint (claims missing
	// from the ID token only; the ID token wins on conflicts).
	UseUserInfo bool
}

// Config configures a RelyingParty.
type Config struct {
	Providers []ProviderConfig
	// CookieKeys are secrets of at least 32 bytes. The first seals new state
	// cookies; all are tried when opening, which allows key rotation.
	CookieKeys [][]byte
	// CookieName defaults to "__Host-citadel-oidc" (or "citadel-oidc" when
	// InsecureCookies is set, since __Host- requires Secure).
	CookieName string
	// InsecureCookies omits the Secure attribute. For tests on plain http only.
	InsecureCookies bool
	// StateTTL bounds how long a sign-in may take (default 10m).
	StateTTL time.Duration
	// HTTPClient is the base client for provider calls (cloned; redirects to
	// non-https URLs are refused).
	HTTPClient *http.Client
	// AllowInsecureHTTP permits http:// issuers and endpoints. Tests only.
	AllowInsecureHTTP bool
	// ClockSkew is the leeway for ID token time claims (default 1m).
	ClockSkew time.Duration
	// DiscoveryTTL is how long discovery documents are cached (default 1h).
	DiscoveryTTL time.Duration
	// HTTPTimeout bounds each provider call (default 10s).
	HTTPTimeout time.Duration
	// ReplayStore makes state single-use. Defaults to an in-memory store,
	// which is only correct with a single Citadel replica.
	ReplayStore ReplayStore
	// Now defaults to time.Now.
	Now func() time.Time
}

var defaultScopes = []string{"openid", "email", "profile"}

func (c *Config) applyDefaults() {
	if c.CookieName == "" {
		c.CookieName = "__Host-citadel-oidc"
		if c.InsecureCookies {
			c.CookieName = "citadel-oidc"
		}
	}
	if c.StateTTL <= 0 {
		c.StateTTL = 10 * time.Minute
	}
	if c.ClockSkew <= 0 {
		c.ClockSkew = time.Minute
	}
	if c.DiscoveryTTL <= 0 {
		c.DiscoveryTTL = time.Hour
	}
	if c.HTTPTimeout <= 0 {
		c.HTTPTimeout = 10 * time.Second
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.ReplayStore == nil {
		c.ReplayStore = NewMemoryReplayStore(c.Now)
	}
}

func (p *ProviderConfig) validate(allowHTTP bool) error {
	if p.ID == "" || strings.ContainsAny(p.ID, "/?#% ") {
		return fmt.Errorf("oidclogin: provider ID %q is empty or contains reserved characters", p.ID)
	}
	if p.ClientID == "" {
		return fmt.Errorf("oidclogin: provider %s: client ID required", p.ID)
	}
	if err := jose.CheckURL(p.Issuer, allowHTTP); err != nil {
		return fmt.Errorf("oidclogin: provider %s issuer: %w", p.ID, err)
	}
	if u, _ := url.Parse(p.Issuer); u.RawQuery != "" {
		return fmt.Errorf("oidclogin: provider %s issuer must not have a query", p.ID)
	}
	if err := jose.CheckURL(p.RedirectURL, allowHTTP); err != nil {
		return fmt.Errorf("oidclogin: provider %s redirect URL: %w", p.ID, err)
	}
	switch p.TokenEndpointAuth {
	case "":
		p.TokenEndpointAuth = AuthClientSecretBasic
	case AuthClientSecretBasic, AuthClientSecretPost:
	default:
		return fmt.Errorf("oidclogin: provider %s: unsupported token endpoint auth %q", p.ID, p.TokenEndpointAuth)
	}
	if p.ClientSecret == "" {
		return fmt.Errorf("oidclogin: provider %s: client secret required", p.ID)
	}
	if len(p.Scopes) == 0 {
		p.Scopes = defaultScopes
	}
	if !contains(p.Scopes, "openid") {
		p.Scopes = append([]string{"openid"}, p.Scopes...)
	}
	if p.GroupsClaim == "" {
		p.GroupsClaim = "groups"
	}
	if p.EmailClaim == "" {
		p.EmailClaim = "email"
	}
	if p.UsernameClaim == "" {
		p.UsernameClaim = "preferred_username"
	}
	for i, d := range p.AllowedEmailDomains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || strings.Contains(d, "@") {
			return fmt.Errorf("oidclogin: provider %s: bad email domain %q", p.ID, p.AllowedEmailDomains[i])
		}
		p.AllowedEmailDomains[i] = d
	}
	return nil
}

// Errors returned by Start and Callback. Callers should show a generic
// message and log the detail.
var (
	ErrUnknownProvider = errors.New("oidclogin: unknown provider")
	ErrInvalidReturnTo = errors.New("oidclogin: invalid return path")
	ErrStateMissing    = errors.New("oidclogin: sign-in state cookie missing")
	ErrStateInvalid    = errors.New("oidclogin: sign-in state invalid or expired")
	ErrStateReplayed   = errors.New("oidclogin: sign-in state already used")
	ErrProvider        = errors.New("oidclogin: provider returned an error")
	ErrDiscovery       = errors.New("oidclogin: discovery failed")
	ErrTokenExchange   = errors.New("oidclogin: token exchange failed")
	ErrIDToken         = errors.New("oidclogin: invalid ID token")
	ErrUserInfo        = errors.New("oidclogin: userinfo failed")
	ErrEmailDomain     = errors.New("oidclogin: email domain not allowed")
)

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
