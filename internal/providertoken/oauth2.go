package providertoken

import (
	"context"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AuthStyle is how the client authenticates to the token endpoint.
type AuthStyle int

const (
	// AuthStyleBasic sends client_id and client_secret in an HTTP Basic
	// Authorization header (client_secret_basic, RFC 6749 §2.3.1).
	AuthStyleBasic AuthStyle = iota
	// AuthStylePost sends them as form parameters (client_secret_post).
	AuthStylePost
)

// DefaultRefreshBefore is how long before expiry a cached token is
// replaced.
const DefaultRefreshBefore = time.Minute

// OAuth2Config configures an OAuth 2.0 client-credentials minter.
type OAuth2Config struct {
	TokenURL     string
	ClientID     string
	ClientSecret string
	AuthStyle    AuthStyle
	// Scopes, Audience and Resource are the defaults when a Mint call names
	// none. Audience is the non-standard "audience" parameter (Auth0 and
	// others); Resource is RFC 8707's "resource".
	Scopes   []string
	Audience string
	Resource string
	// RefreshBefore replaces a cached token this long before it expires;
	// zero means DefaultRefreshBefore.
	RefreshBefore time.Duration
	// Timeout bounds the HTTP call; zero means DefaultTimeout.
	Timeout time.Duration
	// AllowInsecureHTTP permits an http:// token URL (development only).
	AllowInsecureHTTP bool
	// Now overrides the clock (tests).
	Now func() time.Time
}

// OAuth2ClientCredentials fetches access tokens with the client-credentials
// grant and caches each (scopes, audience, resource) combination until
// RefreshBefore ahead of its expires_in. Concurrent Mint calls for the same
// combination share one request. A response without expires_in is returned
// but not cached. It reads Params.Scopes, Params.Audience and
// Params.Resource.
type OAuth2ClientCredentials struct {
	cfg      OAuth2Config
	tokenURL string
	client   *http.Client

	mu       sync.Mutex
	cache    map[string]Token
	inflight map[string]*oauthCall
}

type oauthCall struct {
	done chan struct{}
	tok  Token
	err  error
}

// NewOAuth2ClientCredentials validates cfg and returns a minter that calls
// the token endpoint through client.
func NewOAuth2ClientCredentials(cfg OAuth2Config, client *http.Client) (*OAuth2ClientCredentials, error) {
	c, err := noRedirectClient(KindOAuth2Client, client)
	if err != nil {
		return nil, err
	}
	if _, err := checkEndpoint(KindOAuth2Client, cfg.TokenURL, cfg.AllowInsecureHTTP); err != nil {
		return nil, err
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("providertoken: oauth2_client_credentials: client ID and secret are required")
	}
	if cfg.AuthStyle != AuthStyleBasic && cfg.AuthStyle != AuthStylePost {
		return nil, errors.New("providertoken: oauth2_client_credentials: unknown auth style")
	}
	if err := checkScopes(cfg.Scopes); err != nil {
		return nil, err
	}
	if cfg.RefreshBefore <= 0 {
		cfg.RefreshBefore = DefaultRefreshBefore
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &OAuth2ClientCredentials{
		cfg: cfg, tokenURL: cfg.TokenURL, client: c,
		cache: map[string]Token{}, inflight: map[string]*oauthCall{},
	}, nil
}

// checkScopes enforces RFC 6749 §3.3 scope-token syntax.
func checkScopes(scopes []string) error {
	for _, s := range scopes {
		if s == "" {
			return errors.New("providertoken: oauth2_client_credentials: empty scope")
		}
		for i := 0; i < len(s); i++ {
			c := s[i]
			if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
				return errors.New("providertoken: oauth2_client_credentials: invalid scope")
			}
		}
	}
	return nil
}

type oauthRequest struct {
	scopes   []string
	audience string
	resource string
}

func (r oauthRequest) key() string {
	s := append([]string(nil), r.scopes...)
	sort.Strings(s)
	return strings.Join(s, " ") + "\x00" + r.audience + "\x00" + r.resource
}

// Mint returns a cached token or fetches a new one.
func (o *OAuth2ClientCredentials) Mint(ctx context.Context, p Params) (Token, error) {
	r := oauthRequest{scopes: o.cfg.Scopes, audience: o.cfg.Audience, resource: o.cfg.Resource}
	if len(p.Scopes) > 0 {
		if err := checkScopes(p.Scopes); err != nil {
			return Token{}, err
		}
		r.scopes = p.Scopes
	}
	if p.Audience != "" {
		r.audience = p.Audience
	}
	if p.Resource != "" {
		if _, err := checkEndpoint(KindOAuth2Client, p.Resource, true); err != nil {
			return Token{}, errors.New("providertoken: oauth2_client_credentials: resource must be an absolute URI")
		}
		r.resource = p.Resource
	}
	key := r.key()

	o.mu.Lock()
	if t, ok := o.cache[key]; ok {
		if o.cfg.Now().Add(o.cfg.RefreshBefore).Before(t.ExpiresAt) {
			o.mu.Unlock()
			return withMeta(t), nil
		}
		delete(o.cache, key)
	}
	call, ok := o.inflight[key]
	if !ok {
		call = &oauthCall{done: make(chan struct{})}
		o.inflight[key] = call
		// The fetch is detached from the first caller's cancellation so
		// that one caller giving up does not fail the others sharing it;
		// it is still bounded by the configured timeout.
		go o.fetch(context.WithoutCancel(ctx), key, r, call)
	}
	o.mu.Unlock()

	select {
	case <-call.done:
		if call.err != nil {
			return Token{}, call.err
		}
		return withMeta(call.tok), nil
	case <-ctx.Done():
		return Token{}, ctx.Err()
	}
}

// Invalidate drops every cached token (for example after the provider
// rejected one, or the client secret was rotated).
func (o *OAuth2ClientCredentials) Invalidate() {
	o.mu.Lock()
	o.cache = map[string]Token{}
	o.mu.Unlock()
}

func withMeta(t Token) Token {
	t.Metadata = copyMeta(t.Metadata)
	return t
}

func (o *OAuth2ClientCredentials) fetch(ctx context.Context, key string, r oauthRequest, call *oauthCall) {
	tok, err := o.request(ctx, r)
	o.mu.Lock()
	call.tok, call.err = tok, err
	if err == nil && !tok.ExpiresAt.IsZero() {
		o.cache[key] = tok
	}
	delete(o.inflight, key)
	o.mu.Unlock()
	close(call.done)
}

func (o *OAuth2ClientCredentials) request(ctx context.Context, r oauthRequest) (Token, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	if len(r.scopes) > 0 {
		form.Set("scope", strings.Join(r.scopes, " "))
	}
	if r.audience != "" {
		form.Set("audience", r.audience)
	}
	if r.resource != "" {
		form.Set("resource", r.resource)
	}
	if o.cfg.AuthStyle == AuthStylePost {
		form.Set("client_id", o.cfg.ClientID)
		form.Set("client_secret", o.cfg.ClientSecret)
	}

	ctx, cancel := withTimeout(ctx, o.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return Token{}, errors.New("providertoken: oauth2_client_credentials: building request failed")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if o.cfg.AuthStyle == AuthStyleBasic {
		// RFC 6749 §2.3.1: form-encode both parts before Basic encoding.
		req.SetBasicAuth(url.QueryEscape(o.cfg.ClientID), url.QueryEscape(o.cfg.ClientSecret))
	}
	issued := o.cfg.Now()
	resp, body, err := do(KindOAuth2Client, o.client, req)
	if err != nil {
		return Token{}, err
	}

	var out struct {
		AccessToken string          `json:"access_token"`
		TokenType   string          `json:"token_type"`
		ExpiresIn   json.RawMessage `json:"expires_in"`
		Scope       string          `json:"scope"`
		Error       string          `json:"error"`
	}
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if mt == "application/x-www-form-urlencoded" || mt == "text/plain" {
		v, perr := url.ParseQuery(string(body))
		if perr == nil {
			out.AccessToken, out.TokenType, out.Scope, out.Error = v.Get("access_token"), v.Get("token_type"), v.Get("scope"), v.Get("error")
			if e := v.Get("expires_in"); e != "" {
				out.ExpiresIn = json.RawMessage(strconv.Quote(e))
			}
		}
	} else {
		_ = json.Unmarshal(body, &out)
	}
	if resp.StatusCode != http.StatusOK {
		return Token{}, &ProviderError{Kind: KindOAuth2Client, Status: resp.StatusCode, Code: safeCode(out.Error)}
	}
	if out.AccessToken == "" {
		return Token{}, errors.New("providertoken: oauth2_client_credentials: response has no access_token")
	}
	meta := map[string]string{}
	if tt := strings.ToLower(out.TokenType); tt != "" && safeCode(tt) != "" {
		meta["tokenType"] = tt
	}
	if out.Scope != "" && checkScopes(strings.Fields(out.Scope)) == nil {
		meta["scope"] = out.Scope
	}
	tok := Token{Value: out.AccessToken, Kind: KindOAuth2Client, Metadata: meta}
	if secs, ok := parseExpiresIn(out.ExpiresIn); ok {
		tok.ExpiresAt = issued.Add(time.Duration(secs) * time.Second).UTC()
	} else if len(out.ExpiresIn) > 0 && string(out.ExpiresIn) != "null" {
		return Token{}, errors.New("providertoken: oauth2_client_credentials: invalid expires_in")
	}
	return tok, nil
}

// parseExpiresIn accepts a JSON number or a numeric string (some providers
// send one), between 1 second and 1 year.
func parseExpiresIn(raw json.RawMessage) (int64, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, false
	}
	s := string(raw)
	if unq, err := strconv.Unquote(s); err == nil {
		s = unq
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || f < 1 || f > 365*24*3600 {
		return 0, false
	}
	return int64(f), true
}
