// Package providertoken mints short-lived, provider-scoped credentials for
// agents (Citadel 2.4): AWS STS AssumeRole, GitHub App installation tokens,
// OAuth 2.0 client-credentials access tokens, and TOTP codes for login
// credentials. Every minter satisfies Minter, so the broker can treat a
// stored static secret and a credential minted on use alike.
//
// The package is a pure library: it has no routes, store or configuration
// dependencies. Rules every minter follows:
//
//   - All outbound HTTP goes through the *http.Client the caller injects (the
//     server passes its SSRF-guarded client). Redirects are never followed,
//     so a token endpoint cannot bounce a request carrying credentials to
//     another host. Endpoints must be https unless AllowInsecureHTTP is set.
//   - Every request runs under a context timeout.
//   - Error messages never contain tokens, keys, secrets, request bodies or
//     endpoint URLs (which may carry credentials); provider errors are
//     reduced to the HTTP status and a validated error code.
//   - Token's String, GoString and LogValue redact the value, so a Token that
//     reaches a log line or a %v format prints no secret.
package providertoken

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

// Kind names the type of credential a Token carries.
type Kind string

const (
	KindStatic       Kind = "static"
	KindAWSSTS       Kind = "aws_sts"
	KindGitHubApp    Kind = "github_app"
	KindOAuth2Client Kind = "oauth2_client_credentials"
	KindTOTP         Kind = "totp"
)

// Token is a credential ready to hand to an agent or inject into a brokered
// request.
type Token struct {
	// Value is the secret: an access token, an installation token, a TOTP
	// code, or for aws_sts a JSON document in the AWS credential_process
	// format (see AWSCredentials.ProcessJSON).
	Value string
	// ExpiresAt is when the credential stops working; zero if unknown or
	// it does not expire.
	ExpiresAt time.Time
	Kind      Kind
	// Metadata holds non-secret details (assumed role ARN, granted
	// repositories and permissions, token type, scopes). It never holds
	// secret material and is safe to audit.
	Metadata map[string]string
}

const redacted = "[REDACTED]"

// String redacts Value.
func (t Token) String() string {
	return fmt.Sprintf("providertoken.Token{Kind:%s, ExpiresAt:%s, Value:%s}", t.Kind, t.ExpiresAt.Format(time.RFC3339), redacted)
}

// GoString redacts Value under %#v.
func (t Token) GoString() string { return t.String() }

// LogValue redacts Value when a Token is passed to log/slog.
func (t Token) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("kind", string(t.Kind)),
		slog.Time("expires_at", t.ExpiresAt),
		slog.String("value", redacted),
	)
}

// Params narrows what a single Mint call asks for, typically from the agent
// grant being exercised. Each minter reads only the fields that apply to it
// and documents which; fields for other kinds are ignored. A zero Params
// means "the minter's configured defaults".
type Params struct {
	// aws_sts
	SessionName   string        // RoleSessionName
	SessionPolicy string        // inline session policy JSON
	Duration      time.Duration // DurationSeconds

	// github_app
	Repositories  []string          // repository names (without owner)
	RepositoryIDs []int64           // repository IDs
	Permissions   map[string]string // e.g. {"contents": "read"}

	// oauth2_client_credentials
	Scopes   []string
	Audience string
	Resource string

	// totp
	At time.Time // the time the code is for; zero means now
}

// Minter produces a credential on demand.
type Minter interface {
	Mint(ctx context.Context, p Params) (Token, error)
}

// Static is a Minter for a stored, non-minted secret, so the broker can hand
// out static and minted credentials through one interface.
type Static struct {
	Value     string
	ExpiresAt time.Time
	Metadata  map[string]string
}

// Mint returns the stored value.
func (s Static) Mint(ctx context.Context, _ Params) (Token, error) {
	if err := ctx.Err(); err != nil {
		return Token{}, err
	}
	if s.Value == "" {
		return Token{}, errors.New("providertoken: static: empty value")
	}
	return Token{Value: s.Value, ExpiresAt: s.ExpiresAt, Kind: KindStatic, Metadata: copyMeta(s.Metadata)}, nil
}

// DefaultTimeout bounds each outbound request when a config leaves Timeout
// zero.
const DefaultTimeout = 15 * time.Second

// maxResponseBytes caps how much of a provider response is read.
const maxResponseBytes = 1 << 20

// ProviderError is a failed provider response. It carries only the HTTP
// status and, when the provider sent one that passes validation, its error
// code (for example "AccessDenied" or "invalid_client"); never the response
// body or message text.
type ProviderError struct {
	Kind   Kind
	Status int
	Code   string
}

func (e *ProviderError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("providertoken: %s: provider returned HTTP %d (%s)", e.Kind, e.Status, e.Code)
	}
	return fmt.Sprintf("providertoken: %s: provider returned HTTP %d", e.Kind, e.Status)
}

var errorCodeRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

// safeCode returns code if it looks like a provider error code, else "".
func safeCode(code string) string {
	if errorCodeRE.MatchString(code) {
		return code
	}
	return ""
}

// checkEndpoint requires an absolute https (or http when allowHTTP) URL with
// a host and no userinfo, query or fragment. The URL is never echoed.
func checkEndpoint(kind Kind, raw string, allowHTTP bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("providertoken: %s: endpoint is not a valid URL", kind)
	}
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return nil, fmt.Errorf("providertoken: %s: endpoint must use https", kind)
	}
	if u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Opaque != "" {
		return nil, fmt.Errorf("providertoken: %s: endpoint must have a host and no userinfo, query or fragment", kind)
	}
	return u, nil
}

// noRedirectClient returns a shallow copy of c that never follows
// redirects (the 3xx response is returned as is and treated as a failure).
func noRedirectClient(kind Kind, c *http.Client) (*http.Client, error) {
	if c == nil {
		return nil, fmt.Errorf("providertoken: %s: an *http.Client is required", kind)
	}
	cp := *c
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cp, nil
}

// do sends req and reads at most maxResponseBytes of the response. Transport
// errors are reduced to a fixed message wrapping the underlying cause
// without the request URL (context errors stay detectable with errors.Is).
func do(kind Kind, c *http.Client, req *http.Request) (*http.Response, []byte, error) {
	resp, err := c.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return nil, nil, fmt.Errorf("providertoken: %s: request failed: %w", kind, err)
		}
		return nil, nil, fmt.Errorf("providertoken: %s: request failed: %w", kind, sanitizedError{err})
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("providertoken: %s: reading response failed", kind)
	}
	if len(body) > maxResponseBytes {
		return nil, nil, fmt.Errorf("providertoken: %s: response too large", kind)
	}
	return resp, body, nil
}

// sanitizedError keeps the error chain (errors.Is/As still work) while
// printing only a fixed description, since net errors can quote the
// destination address.
type sanitizedError struct{ err error }

func (e sanitizedError) Error() string { return "transport error" }
func (e sanitizedError) Unwrap() error { return e.err }

func withTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		d = DefaultTimeout
	}
	return context.WithTimeout(ctx, d)
}

func copyMeta(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
