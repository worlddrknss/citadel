package workloadid

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/worlddrknss/citadel/internal/jose"
)

// Config configures an Issuer.
type Config struct {
	// IssuerURL is the iss claim and the base of the discovery, JWKS and
	// token URLs, e.g. "https://citadel.example.com/workload". It must be
	// https, with no query, fragment or trailing slash.
	IssuerURL string
	Signers   SignerSet
	Clients   ClientStore
	// Authenticator authenticates token requests. Use a MethodRouter to
	// combine an AuthenticatorFunc (access_key) and a KubernetesAuthenticator.
	Authenticator Authenticator
	// Clock defaults to time.Now.
	Clock func() time.Time
	// MaxTTL caps every token lifetime (default 1h).
	MaxTTL time.Duration
	// DefaultTTL applies to clients without a TTL (default 15m, capped by MaxTTL).
	DefaultTTL time.Duration
	// MinTTL is the floor for requested lifetimes (default 60s).
	MinTTL time.Duration
	// ClaimsNamespace is the key of the custom claims object (default
	// "citadel").
	ClaimsNamespace string
	// OnIssue, if set, is called after every token is minted (audit log).
	OnIssue func(ctx context.Context, w Workload, c Client, jti, aud string, exp time.Time)
	// AllowInsecureIssuer permits an http:// IssuerURL. Tests only.
	AllowInsecureIssuer bool
}

// Issuer is a workload identity OIDC issuer.
type Issuer struct {
	cfg      Config
	basePath string
}

// New validates cfg and returns an Issuer.
func New(cfg Config) (*Issuer, error) {
	if err := jose.CheckURL(cfg.IssuerURL, cfg.AllowInsecureIssuer); err != nil {
		return nil, fmt.Errorf("workloadid: issuer URL: %w", err)
	}
	u, _ := url.Parse(cfg.IssuerURL)
	if u.RawQuery != "" || strings.HasSuffix(cfg.IssuerURL, "/") {
		return nil, errors.New("workloadid: issuer URL must not have a query or trailing slash")
	}
	if cfg.Signers == nil || cfg.Clients == nil || cfg.Authenticator == nil {
		return nil, errors.New("workloadid: Signers, Clients and Authenticator are required")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = time.Hour
	}
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = 15 * time.Minute
	}
	if cfg.MinTTL <= 0 {
		cfg.MinTTL = time.Minute
	}
	if cfg.DefaultTTL > cfg.MaxTTL {
		cfg.DefaultTTL = cfg.MaxTTL
	}
	if cfg.MinTTL > cfg.MaxTTL {
		cfg.MinTTL = cfg.MaxTTL
	}
	if cfg.ClaimsNamespace == "" {
		cfg.ClaimsNamespace = "citadel"
	}
	switch cfg.ClaimsNamespace {
	case "iss", "sub", "aud", "iat", "nbf", "exp", "jti":
		return nil, errors.New("workloadid: claims namespace collides with a registered claim")
	}
	return &Issuer{cfg: cfg, basePath: strings.TrimSuffix(u.EscapedPath(), "/")}, nil
}

// Paths relative to the issuer URL.
const (
	DiscoveryPath = "/.well-known/openid-configuration"
	JWKSPath      = "/jwks.json"
	TokenPath     = "/token"
)

// TokenRequest asks for a token.
type TokenRequest struct {
	ClientID   string
	Audience   string
	TTL        time.Duration // 0 means the client's TTL
	Credential string
	HTTP       *http.Request
}

// Token is the token endpoint's success response:
//
//	{"token": "<JWT>", "expires_at": "2026-11-12T10:15:00Z", "expires_in": 900}
//
// token is a compact JWS (typ JWT) signed by the issuer's current key; it is
// an OIDC ID token for the workload, to be presented to the relying party
// (for example as the web identity token for AWS
// AssumeRoleWithWebIdentity or the subject token for GCP STS).
type Token struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	ExpiresIn int64     `json:"expires_in"`
}

// Error is a token endpoint error, serialised as
// {"error": Code, "error_description": Description} with HTTP Status.
// Codes follow OAuth 2.0: invalid_request, invalid_client, access_denied,
// invalid_target, server_error.
type Error struct {
	Status      int    `json:"-"`
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	// Err is the internal cause; it is never sent to the caller.
	Err error `json:"-"`
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("workloadid: %s: %s: %v", e.Code, e.Description, e.Err)
	}
	return fmt.Sprintf("workloadid: %s: %s", e.Code, e.Description)
}

func (e *Error) Unwrap() error { return e.Err }

func errorf(status int, code string, cause error, format string, args ...any) *Error {
	return &Error{Status: status, Code: code, Description: fmt.Sprintf(format, args...), Err: cause}
}

// Issue authenticates req and mints a token. Errors are *Error.
func (i *Issuer) Issue(ctx context.Context, req TokenRequest) (*Token, error) {
	if req.ClientID == "" || req.Audience == "" {
		return nil, errorf(400, "invalid_request", nil, "client_id and audience are required")
	}
	if req.TTL < 0 {
		return nil, errorf(400, "invalid_request", nil, "ttl must be positive")
	}
	client, err := i.cfg.Clients.Get(ctx, req.ClientID)
	if errors.Is(err, ErrClientNotFound) {
		return nil, errorf(401, "invalid_client", err, "unknown client")
	}
	if err != nil {
		return nil, errorf(500, "server_error", err, "client lookup failed")
	}
	w, err := i.cfg.Authenticator.Authenticate(ctx, &AuthRequest{Client: client, Credential: req.Credential, HTTP: req.HTTP})
	switch {
	case errors.Is(err, ErrForbidden):
		return nil, errorf(403, "access_denied", err, "workload is not allowed to use this client")
	case err != nil:
		return nil, errorf(401, "invalid_client", err, "workload authentication failed")
	}
	if w.AccountRef != client.AccountRef || w.ClientID != client.ID {
		return nil, errorf(403, "access_denied", nil, "authenticated workload does not belong to this client")
	}
	if !contains(client.AllowedAudiences, req.Audience) {
		return nil, errorf(400, "invalid_target", nil, "audience is not allowed for this client")
	}
	ttl := i.effectiveTTL(client, req.TTL)
	sub, err := renderSubject(client, w)
	if err != nil {
		return nil, errorf(403, "access_denied", err, "subject template cannot be rendered for this workload")
	}
	signer, err := i.cfg.Signers.Current(ctx)
	if err != nil {
		return nil, errorf(500, "server_error", err, "signing key unavailable")
	}
	jti, err := newJTI()
	if err != nil {
		return nil, errorf(500, "server_error", err, "randomness unavailable")
	}
	now := i.cfg.Clock().Truncate(time.Second)
	exp := now.Add(ttl)
	attrs := make(map[string]string, len(w.Attributes))
	for k, v := range w.Attributes {
		attrs[k] = v
	}
	custom := map[string]any{
		"account":     client.AccountRef,
		"client_id":   client.ID,
		"auth_method": string(client.AuthMethod),
	}
	if w.Subject != "" {
		custom["workload"] = w.Subject
	}
	if len(attrs) > 0 {
		custom["attributes"] = attrs
	}
	claims := map[string]any{
		"iss":                 i.cfg.IssuerURL,
		"sub":                 sub,
		"aud":                 req.Audience,
		"iat":                 now.Unix(),
		"nbf":                 now.Unix(),
		"exp":                 exp.Unix(),
		"jti":                 jti,
		i.cfg.ClaimsNamespace: custom,
	}
	tok, err := jose.SignJWT(ctx, signer, claims)
	if err != nil {
		return nil, errorf(500, "server_error", err, "signing failed")
	}
	if i.cfg.OnIssue != nil {
		i.cfg.OnIssue(ctx, w, client, jti, req.Audience, exp)
	}
	return &Token{Token: tok, ExpiresAt: exp.UTC(), ExpiresIn: int64(ttl / time.Second)}, nil
}

// effectiveTTL: requested (or client default) <= client TTL <= MaxTTL, and
// at least MinTTL.
func (i *Issuer) effectiveTTL(c Client, requested time.Duration) time.Duration {
	limit := c.TTL
	if limit <= 0 {
		limit = i.cfg.DefaultTTL
	}
	if limit > i.cfg.MaxTTL {
		limit = i.cfg.MaxTTL
	}
	ttl := requested
	if ttl <= 0 || ttl > limit {
		ttl = limit
	}
	if ttl < i.cfg.MinTTL {
		ttl = i.cfg.MinTTL
	}
	return ttl.Truncate(time.Second)
}

func renderSubject(c Client, w Workload) (string, error) {
	tmpl := c.SubjectTemplate
	if tmpl == "" {
		tmpl = DefaultSubjectTemplate
	}
	var missing []string
	out := placeholderPattern.ReplaceAllStringFunc(tmpl, func(m string) string {
		name := m[1 : len(m)-1]
		switch name {
		case "account":
			return c.AccountRef
		case "client":
			return c.ID
		}
		v, ok := w.Attributes[name]
		if !ok || v == "" {
			missing = append(missing, name)
		}
		return v
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("missing workload attributes %q", missing)
	}
	if out == "" || len(out) > 255 || !utf8.ValidString(out) || strings.ContainsFunc(out, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", errors.New("rendered subject is empty, too long or contains control characters")
	}
	return out, nil
}

func newJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// DiscoveryDocument is served at /.well-known/openid-configuration.
type DiscoveryDocument struct {
	Issuer                           string   `json:"issuer"`
	JWKSURI                          string   `json:"jwks_uri"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
}

// Discovery returns the discovery document.
func (i *Issuer) Discovery(ctx context.Context) (*DiscoveryDocument, error) {
	signers, err := i.cfg.Signers.Published(ctx)
	if err != nil {
		return nil, err
	}
	var algs []string
	for _, s := range signers {
		if !contains(algs, s.Alg()) {
			algs = append(algs, s.Alg())
		}
	}
	return &DiscoveryDocument{
		Issuer:                           i.cfg.IssuerURL,
		JWKSURI:                          i.cfg.IssuerURL + JWKSPath,
		TokenEndpoint:                    i.cfg.IssuerURL + TokenPath,
		ResponseTypesSupported:           []string{"id_token"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: algs,
		ClaimsSupported:                  []string{"iss", "sub", "aud", "iat", "nbf", "exp", "jti", i.cfg.ClaimsNamespace},
		ScopesSupported:                  []string{"openid"},
	}, nil
}

// JWKS returns the published key set.
func (i *Issuer) JWKS(ctx context.Context) (*jose.JWKSet, error) {
	signers, err := i.cfg.Signers.Published(ctx)
	if err != nil {
		return nil, err
	}
	set := &jose.JWKSet{Keys: make([]jose.JWK, 0, len(signers))}
	for _, s := range signers {
		set.Keys = append(set.Keys, jose.NewJWK(s))
	}
	return set, nil
}

// Handler serves the discovery document, JWKS and token endpoint under the
// issuer URL's path. Mount it at that path prefix (or at "/" when the issuer
// URL has no path); requests for other paths get 404.
func (i *Issuer) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel, ok := strings.CutPrefix(r.URL.EscapedPath(), i.basePath)
		if !ok {
			http.NotFound(w, r)
			return
		}
		switch rel {
		case DiscoveryPath:
			if !methodIs(w, r, http.MethodGet, http.MethodHead) {
				return
			}
			doc, err := i.Discovery(r.Context())
			if err != nil {
				writeError(w, errorf(500, "server_error", err, "keys unavailable"))
				return
			}
			writeJSON(w, http.StatusOK, "public, max-age=3600", doc)
		case JWKSPath:
			if !methodIs(w, r, http.MethodGet, http.MethodHead) {
				return
			}
			set, err := i.JWKS(r.Context())
			if err != nil {
				writeError(w, errorf(500, "server_error", err, "keys unavailable"))
				return
			}
			writeJSON(w, http.StatusOK, "public, max-age=300", set)
		case TokenPath:
			if !methodIs(w, r, http.MethodPost) {
				return
			}
			i.serveToken(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

const maxTokenRequestBytes = 64 << 10

// tokenRequestBody is the token endpoint request, as JSON or form fields:
//
//	{"client_id": "...", "audience": "sts.amazonaws.com", "ttl_seconds": 900, "credential": "<SA token>"}
//
// credential may instead be sent as "Authorization: Bearer <token>".
type tokenRequestBody struct {
	ClientID   string `json:"client_id"`
	Audience   string `json:"audience"`
	TTLSeconds int64  `json:"ttl_seconds"`
	Credential string `json:"credential"`
}

func (i *Issuer) serveToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenRequestBytes)
	var body tokenRequestBody
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch mt {
	case "application/json":
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			writeError(w, errorf(400, "invalid_request", err, "malformed JSON body"))
			return
		}
	case "application/x-www-form-urlencoded":
		if err := r.ParseForm(); err != nil {
			writeError(w, errorf(400, "invalid_request", err, "malformed form body"))
			return
		}
		body.ClientID = r.PostForm.Get("client_id")
		body.Audience = r.PostForm.Get("audience")
		body.Credential = r.PostForm.Get("credential")
		if v := r.PostForm.Get("ttl_seconds"); v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				writeError(w, errorf(400, "invalid_request", err, "ttl_seconds must be an integer"))
				return
			}
			body.TTLSeconds = n
		}
	default:
		writeError(w, errorf(415, "invalid_request", nil, "content type must be application/json or application/x-www-form-urlencoded"))
		return
	}
	if body.Credential == "" {
		if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
			body.Credential = strings.TrimSpace(h[7:])
		}
	}
	if body.TTLSeconds < 0 || body.TTLSeconds > int64(24*time.Hour/time.Second) {
		writeError(w, errorf(400, "invalid_request", nil, "ttl_seconds out of range"))
		return
	}
	tok, err := i.Issue(r.Context(), TokenRequest{
		ClientID:   body.ClientID,
		Audience:   body.Audience,
		TTL:        time.Duration(body.TTLSeconds) * time.Second,
		Credential: body.Credential,
		HTTP:       r,
	})
	if err != nil {
		var e *Error
		if !errors.As(err, &e) {
			e = errorf(500, "server_error", err, "internal error")
		}
		writeError(w, e)
		return
	}
	writeJSON(w, http.StatusOK, "no-store", tok)
}

func methodIs(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	for _, m := range methods {
		if r.Method == m {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(methods, ", "))
	writeError(w, errorf(http.StatusMethodNotAllowed, "invalid_request", nil, "method not allowed"))
	return false
}

func writeJSON(w http.ResponseWriter, status int, cacheControl string, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", cacheControl)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, e *Error) {
	if e.Status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="citadel-workload-identity"`)
	}
	writeJSON(w, e.Status, "no-store", e)
}
