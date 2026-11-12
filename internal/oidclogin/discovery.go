package oidclogin

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/worlddrknss/citadel/internal/jose"
)

// Discovery is the subset of an OpenID Provider Metadata document
// (OpenID Connect Discovery 1.0) that the relying party uses.
type Discovery struct {
	Issuer                   string   `json:"issuer"`
	AuthorizationEndpoint    string   `json:"authorization_endpoint"`
	TokenEndpoint            string   `json:"token_endpoint"`
	UserInfoEndpoint         string   `json:"userinfo_endpoint"`
	JWKSURI                  string   `json:"jwks_uri"`
	IDTokenSigningAlgs       []string `json:"id_token_signing_alg_values_supported"`
	CodeChallengeMethods     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
}

type providerState struct {
	cfg ProviderConfig

	mu      sync.Mutex
	doc     *Discovery
	algs    []string
	jwks    *jose.Fetcher
	expires time.Time
}

const maxDiscoveryBytes = 256 << 10

// discover returns the cached discovery document, refreshing it after
// DiscoveryTTL. If a refresh fails, the previous document is used for up to
// one more DiscoveryTTL.
func (rp *RelyingParty) discover(ctx context.Context, p *providerState) (*Discovery, []string, *jose.Fetcher, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := rp.cfg.Now()
	if p.doc != nil && now.Before(p.expires) {
		return p.doc, p.algs, p.jwks, nil
	}
	doc, algs, err := rp.fetchDiscovery(ctx, p.cfg)
	if err != nil {
		if p.doc != nil && now.Before(p.expires.Add(rp.cfg.DiscoveryTTL)) {
			return p.doc, p.algs, p.jwks, nil
		}
		return nil, nil, nil, err
	}
	if p.jwks == nil || p.doc == nil || p.doc.JWKSURI != doc.JWKSURI {
		f, err := jose.NewFetcher(jose.FetcherConfig{
			URL:               doc.JWKSURI,
			Client:            rp.cfg.HTTPClient,
			AllowInsecureHTTP: rp.cfg.AllowInsecureHTTP,
			Timeout:           rp.cfg.HTTPTimeout,
			Now:               rp.cfg.Now,
		})
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%w: %v", ErrDiscovery, err)
		}
		p.jwks = f
	}
	p.doc, p.algs, p.expires = doc, algs, now.Add(rp.cfg.DiscoveryTTL)
	return p.doc, p.algs, p.jwks, nil
}

func (rp *RelyingParty) fetchDiscovery(ctx context.Context, cfg ProviderConfig) (*Discovery, []string, error) {
	u := strings.TrimSuffix(cfg.Issuer, "/") + "/.well-known/openid-configuration"
	body, _, err := jose.GetLimited(ctx, rp.client, u, maxDiscoveryBytes, rp.cfg.HTTPTimeout, "application/json")
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s: %v", ErrDiscovery, cfg.ID, err)
	}
	var doc Discovery
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, nil, fmt.Errorf("%w: %s: %v", ErrDiscovery, cfg.ID, err)
	}
	if doc.Issuer != cfg.Issuer {
		return nil, nil, fmt.Errorf("%w: %s: discovery issuer %q does not match configured issuer %q", ErrDiscovery, cfg.ID, doc.Issuer, cfg.Issuer)
	}
	for name, v := range map[string]string{"authorization_endpoint": doc.AuthorizationEndpoint, "token_endpoint": doc.TokenEndpoint, "jwks_uri": doc.JWKSURI} {
		if err := jose.CheckURL(v, rp.cfg.AllowInsecureHTTP); err != nil {
			return nil, nil, fmt.Errorf("%w: %s: %s: %v", ErrDiscovery, cfg.ID, name, err)
		}
	}
	if doc.UserInfoEndpoint != "" {
		if err := jose.CheckURL(doc.UserInfoEndpoint, rp.cfg.AllowInsecureHTTP); err != nil {
			return nil, nil, fmt.Errorf("%w: %s: userinfo_endpoint: %v", ErrDiscovery, cfg.ID, err)
		}
	}
	if len(doc.CodeChallengeMethods) > 0 && !contains(doc.CodeChallengeMethods, "S256") {
		return nil, nil, fmt.Errorf("%w: %s: provider does not support PKCE S256", ErrDiscovery, cfg.ID)
	}
	advertised := doc.IDTokenSigningAlgs
	if len(advertised) == 0 {
		advertised = []string{jose.RS256} // OIDC default
	}
	var algs []string
	for _, a := range advertised {
		if jose.IsSupported(a) {
			algs = append(algs, a)
		}
	}
	if len(algs) == 0 {
		return nil, nil, fmt.Errorf("%w: %s: no FIPS-approved ID token algorithm among %q", ErrDiscovery, cfg.ID, advertised)
	}
	return &doc, algs, nil
}
