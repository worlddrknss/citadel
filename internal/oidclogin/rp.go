package oidclogin

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/jose"
)

const maxTokenResponseBytes = 1 << 20

// RelyingParty drives console sign-in against the configured providers. It
// is safe for concurrent use.
type RelyingParty struct {
	cfg       Config
	client    *http.Client
	sealer    *sealer
	providers map[string]*providerState
	order     []string
}

// ProviderInfo is what the login screen needs to render a button.
type ProviderInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// New validates cfg and returns a RelyingParty. No network I/O happens here;
// discovery runs lazily on the first Start for each provider.
func New(cfg Config) (*RelyingParty, error) {
	cfg.applyDefaults()
	s, err := newSealer(cfg.CookieKeys, cfg.CookieName)
	if err != nil {
		return nil, err
	}
	rp := &RelyingParty{
		cfg:       cfg,
		client:    jose.SecureHTTPClient(cfg.HTTPClient, cfg.AllowInsecureHTTP),
		sealer:    s,
		providers: map[string]*providerState{},
	}
	for _, p := range cfg.Providers {
		p.Scopes = append([]string(nil), p.Scopes...)
		p.AllowedEmailDomains = append([]string(nil), p.AllowedEmailDomains...)
		if err := p.validate(cfg.AllowInsecureHTTP); err != nil {
			return nil, err
		}
		if _, dup := rp.providers[p.ID]; dup {
			return nil, fmt.Errorf("oidclogin: duplicate provider ID %q", p.ID)
		}
		if p.Name == "" {
			p.Name = p.ID
		}
		rp.providers[p.ID] = &providerState{cfg: p}
		rp.order = append(rp.order, p.ID)
	}
	return rp, nil
}

// Providers lists the configured providers in configuration order.
func (rp *RelyingParty) Providers() []ProviderInfo {
	out := make([]ProviderInfo, 0, len(rp.order))
	for _, id := range rp.order {
		out = append(out, ProviderInfo{ID: id, Name: rp.providers[id].cfg.Name})
	}
	return out
}

func (rp *RelyingParty) cookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     rp.cfg.CookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   !rp.cfg.InsecureCookies,
		// Lax: the callback is a top-level cross-site GET from the provider.
		SameSite: http.SameSiteLaxMode,
	}
}

// ClearCookie returns a cookie that deletes the state cookie; set it on the
// callback response whatever the outcome.
func (rp *RelyingParty) ClearCookie() *http.Cookie { return rp.cookie("", -1) }

// Start begins a sign-in with providerID. The host must set the returned
// cookie and redirect the browser (302/303) to redirectURL. returnTo must be
// a same-origin relative path ("" means "/").
//
// Only one sign-in per browser can be in flight: starting another replaces
// the cookie and invalidates the first.
func (rp *RelyingParty) Start(ctx context.Context, providerID, returnTo string) (string, *http.Cookie, error) {
	p, ok := rp.providers[providerID]
	if !ok {
		return "", nil, fmt.Errorf("%w: %q", ErrUnknownProvider, providerID)
	}
	ret, err := ValidateReturnTo(returnTo)
	if err != nil {
		return "", nil, err
	}
	doc, _, _, err := rp.discover(ctx, p)
	if err != nil {
		return "", nil, err
	}
	st := flowState{Provider: providerID, ReturnTo: ret, Expires: rp.cfg.Now().Add(rp.cfg.StateTTL).Unix()}
	for _, f := range []*string{&st.State, &st.Nonce, &st.Verifier} {
		if *f, err = randomToken(32); err != nil {
			return "", nil, err
		}
	}
	value, err := rp.sealer.seal(st)
	if err != nil {
		return "", nil, err
	}
	authURL, err := url.Parse(doc.AuthorizationEndpoint)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrDiscovery, err)
	}
	challenge := sha256.Sum256([]byte(st.Verifier))
	q := authURL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", p.cfg.RedirectURL)
	q.Set("scope", strings.Join(p.cfg.Scopes, " "))
	q.Set("state", st.State)
	q.Set("nonce", st.Nonce)
	q.Set("code_challenge", b64.EncodeToString(challenge[:]))
	q.Set("code_challenge_method", "S256")
	authURL.RawQuery = q.Encode()
	return authURL.String(), rp.cookie(value, int(rp.cfg.StateTTL/time.Second)), nil
}

// Callback completes a sign-in at the redirect URL. It validates the state
// cookie against the state parameter, consumes the state, exchanges the code
// (with the PKCE verifier), verifies the ID token and builds the Identity.
// The host should always clear the cookie (ClearCookie) afterwards.
func (rp *RelyingParty) Callback(ctx context.Context, r *http.Request) (Identity, error) {
	var id Identity
	c, err := r.Cookie(rp.cfg.CookieName)
	if err != nil || c.Value == "" {
		return id, ErrStateMissing
	}
	st, err := rp.sealer.open(c.Value)
	if err != nil {
		return id, err
	}
	now := rp.cfg.Now()
	expires := time.Unix(st.Expires, 0)
	if !now.Before(expires) {
		return id, fmt.Errorf("%w: expired", ErrStateInvalid)
	}
	q := r.URL.Query()
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(st.State)) != 1 {
		return id, fmt.Errorf("%w: state mismatch", ErrStateInvalid)
	}
	p, ok := rp.providers[st.Provider]
	if !ok {
		return id, fmt.Errorf("%w: %q", ErrUnknownProvider, st.Provider)
	}
	fresh, err := rp.cfg.ReplayStore.Consume(ctx, stateID(st.State), expires)
	if err != nil {
		return id, fmt.Errorf("%w: %v", ErrStateInvalid, err)
	}
	if !fresh {
		return id, ErrStateReplayed
	}
	// RFC 9207 mix-up defence when the provider sends iss.
	if iss := q.Get("iss"); iss != "" && iss != p.cfg.Issuer {
		return id, fmt.Errorf("%w: iss parameter %q does not match provider", ErrProvider, iss)
	}
	if e := q.Get("error"); e != "" {
		return id, fmt.Errorf("%w: %s", ErrProvider, sanitize(e))
	}
	code := q.Get("code")
	if code == "" {
		return id, fmt.Errorf("%w: missing code", ErrProvider)
	}
	doc, algs, jwks, err := rp.discover(ctx, p)
	if err != nil {
		return id, err
	}
	tok, err := rp.exchange(ctx, p.cfg, doc, code, st.Verifier)
	if err != nil {
		return id, err
	}
	claims, err := rp.verifyIDToken(ctx, p.cfg, algs, jwks, tok, st.Nonce)
	if err != nil {
		return id, err
	}
	if p.cfg.UseUserInfo && doc.UserInfoEndpoint != "" && tok.AccessToken != "" {
		if err := rp.mergeUserInfo(ctx, doc.UserInfoEndpoint, tok.AccessToken, claims); err != nil {
			return id, err
		}
	}
	id = buildIdentity(p.cfg, claims)
	id.ReturnTo = st.ReturnTo
	if len(p.cfg.AllowedEmailDomains) > 0 {
		if id.Email == "" || (!id.EmailVerified && !p.cfg.AllowUnverifiedEmail) || !EmailDomainAllowed(id.Email, p.cfg.AllowedEmailDomains) {
			return Identity{}, fmt.Errorf("%w: %q (verified=%v)", ErrEmailDomain, id.Email, id.EmailVerified)
		}
	}
	return id, nil
}

type tokenResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

func (rp *RelyingParty) exchange(ctx context.Context, p ProviderConfig, doc *Discovery, code, verifier string) (*tokenResponse, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.RedirectURL},
		"code_verifier": {verifier},
	}
	if p.TokenEndpointAuth == AuthClientSecretPost {
		form.Set("client_id", p.ClientID)
		form.Set("client_secret", p.ClientSecret)
	}
	ctx, cancel := context.WithTimeout(ctx, rp.cfg.HTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, doc.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenExchange, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if p.TokenEndpointAuth == AuthClientSecretBasic {
		// RFC 6749 section 2.3.1: form-encode before Basic.
		req.SetBasicAuth(url.QueryEscape(p.ClientID), url.QueryEscape(p.ClientSecret))
	}
	resp, err := rp.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenExchange, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes+1))
	if err != nil || len(body) > maxTokenResponseBytes {
		return nil, fmt.Errorf("%w: response unreadable or too large", ErrTokenExchange)
	}
	var tr tokenResponse
	jerr := json.Unmarshal(body, &tr)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d %s", ErrTokenExchange, resp.StatusCode, sanitize(tr.Error))
	}
	if jerr != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenExchange, jerr)
	}
	if tr.IDToken == "" {
		return nil, fmt.Errorf("%w: no id_token in response", ErrTokenExchange)
	}
	return &tr, nil
}

func (rp *RelyingParty) verifyIDToken(ctx context.Context, p ProviderConfig, algs []string, keys jose.KeySource, tok *tokenResponse, nonce string) (jose.Claims, error) {
	j, err := jose.Verify(ctx, tok.IDToken, keys, algs...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIDToken, err)
	}
	claims, err := jose.ParseClaims(j.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIDToken, err)
	}
	v := jose.Validator{
		Issuer:          p.Issuer,
		Audience:        p.ClientID,
		Leeway:          rp.cfg.ClockSkew,
		Now:             rp.cfg.Now,
		Required:        []string{"sub"},
		RequireIssuedAt: true,
		MaxAge:          rp.cfg.StateTTL,
	}
	if err := v.Validate(claims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIDToken, err)
	}
	aud, _ := claims.Audience()
	azp, err := claims.String("azp")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIDToken, err)
	}
	if (len(aud) > 1 || azp != "") && azp != p.ClientID {
		return nil, fmt.Errorf("%w: azp %q is not the client ID", ErrIDToken, azp)
	}
	got, err := claims.String("nonce")
	if err != nil || got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(nonce)) != 1 {
		return nil, fmt.Errorf("%w: nonce mismatch", ErrIDToken)
	}
	if sub, err := claims.String("sub"); err != nil || sub == "" {
		return nil, fmt.Errorf("%w: sub must be a non-empty string", ErrIDToken)
	}
	if atHash, _ := claims.String("at_hash"); atHash != "" && tok.AccessToken != "" {
		if !checkAtHash(j.Header.Alg, tok.AccessToken, atHash) {
			return nil, fmt.Errorf("%w: at_hash mismatch", ErrIDToken)
		}
	}
	return claims, nil
}

func checkAtHash(alg, accessToken, atHash string) bool {
	var sum []byte
	switch alg {
	case jose.ES384:
		s := sha512.Sum384([]byte(accessToken))
		sum = s[:]
	default:
		s := sha256.Sum256([]byte(accessToken))
		sum = s[:]
	}
	want := b64.EncodeToString(sum[:len(sum)/2])
	return subtle.ConstantTimeCompare([]byte(want), []byte(atHash)) == 1
}

// registered claims that UserInfo must never override or introduce.
var protectedClaims = map[string]bool{"iss": true, "aud": true, "exp": true, "iat": true, "nbf": true, "nonce": true, "azp": true, "sub": true, "auth_time": true, "at_hash": true, "c_hash": true}

func (rp *RelyingParty) mergeUserInfo(ctx context.Context, endpoint, accessToken string, claims jose.Claims) error {
	ctx, cancel := context.WithTimeout(ctx, rp.cfg.HTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUserInfo, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := rp.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUserInfo, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: HTTP %d", ErrUserInfo, resp.StatusCode)
	}
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != "application/json" {
		return fmt.Errorf("%w: unsupported content type %q (signed UserInfo is not supported)", ErrUserInfo, mt)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes+1))
	if err != nil || len(body) > maxTokenResponseBytes {
		return fmt.Errorf("%w: response unreadable or too large", ErrUserInfo)
	}
	info, err := jose.ParseClaims(body)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUserInfo, err)
	}
	sub, _ := info.String("sub")
	idSub, _ := claims.String("sub")
	if sub != idSub {
		return fmt.Errorf("%w: sub mismatch", ErrUserInfo)
	}
	for k, v := range info {
		if _, exists := claims[k]; !exists && !protectedClaims[k] {
			claims[k] = v
		}
	}
	return nil
}

// lookupClaim finds name in claims, walking dotted paths when the literal
// name is absent.
func lookupClaim(claims map[string]any, name string) (any, bool) {
	if v, ok := claims[name]; ok {
		return v, true
	}
	cur := any(claims)
	for _, part := range strings.Split(name, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[part]; !ok {
			return nil, false
		}
	}
	return cur, true
}

func claimString(claims map[string]any, name string) string {
	v, _ := lookupClaim(claims, name)
	s, _ := v.(string)
	return s
}

func buildIdentity(p ProviderConfig, claims jose.Claims) Identity {
	id := Identity{
		Provider:  p.ID,
		Subject:   claimString(claims, "sub"),
		Email:     claimString(claims, p.EmailClaim),
		Name:      claimString(claims, "name"),
		Username:  claimString(claims, p.UsernameClaim),
		RawClaims: map[string]any(claims),
	}
	switch v := claims["email_verified"].(type) {
	case bool:
		id.EmailVerified = v
	case string:
		id.EmailVerified = strings.EqualFold(v, "true")
	}
	if v, ok := lookupClaim(claims, p.GroupsClaim); ok {
		switch g := v.(type) {
		case string:
			if g != "" {
				id.Groups = []string{g}
			}
		case []any:
			for _, e := range g {
				if s, ok := e.(string); ok && s != "" {
					id.Groups = append(id.Groups, s)
				}
			}
		}
	}
	sort.Strings(id.Groups)
	return id
}

// sanitize keeps provider-supplied error codes printable and short.
func sanitize(s string) string {
	if len(s) > 64 {
		s = s[:64]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return '?'
		}
		return r
	}, s)
}
