package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/worlddrknss/citadel/internal/agentbroker"
	"github.com/worlddrknss/citadel/internal/providertoken"
	"github.com/worlddrknss/citadel/internal/store"
)

// Minted credentials (2.4): aws_sts, github_app and
// oauth2_client_credentials. The secret behind the usage profile holds the
// long-lived source material; on use, Citadel mints a short-lived token with
// internal/providertoken and caches it per credential and grant scope until
// shortly before it expires. Agents only ever get (reveal) or use (broker)
// the minted token, never the source material. Outbound calls to STS,
// GitHub and token endpoints go through the same SSRF-guarded client as
// brokered requests, with the credential's allowedCidrs.

const (
	// agentMintRefreshBefore replaces a cached token this long before it
	// expires.
	agentMintRefreshBefore = time.Minute
	agentMintCacheMax      = 2048
)

type agentMintCall struct {
	done chan struct{}
	tok  providertoken.Token
	err  error
}

type agentMintRuntime struct {
	mu       sync.Mutex
	cache    map[string]providertoken.Token
	inflight map[string]*agentMintCall
	now      func() time.Time
}

var agentMintRuntimes sync.Map // *Server -> *agentMintRuntime

func (s *Server) agentMintRT() *agentMintRuntime {
	if v, ok := agentMintRuntimes.Load(s); ok {
		return v.(*agentMintRuntime)
	}
	v, _ := agentMintRuntimes.LoadOrStore(s, &agentMintRuntime{cache: map[string]providertoken.Token{}, inflight: map[string]*agentMintCall{}, now: time.Now})
	return v.(*agentMintRuntime)
}

// agentGrantMinter mints the token for one allowed use of a minted
// credential.
type agentGrantMinter struct {
	s       *Server
	account string
	use     agentCoreUse
}

func (m agentGrantMinter) Mint(ctx context.Context, _ providertoken.Params) (providertoken.Token, error) {
	return m.s.agentMintedToken(ctx, m.account, m.use.cred, m.use.grant, m.use.ref)
}

// errAgentScope is a grant scope that no longer fits its credential.
type errAgentScope struct{ msg string }

func (e errAgentScope) Error() string { return "agent grant scope: " + e.msg }

// agentMintedToken returns a cached token for (credential, scope) or mints a
// new one. Concurrent requests for the same key share one mint.
func (s *Server) agentMintedToken(ctx context.Context, accountID string, cred store.AgentCredential, grant store.AgentGrant, ref agentSecretRef) (providertoken.Token, error) {
	params, msg := agentMintParams(cred, grant)
	if msg != "" {
		return providertoken.Token{}, errAgentScope{msg}
	}
	rt := s.agentMintRT()
	key := strings.Join([]string{accountID, cred.Name, cred.Kind, strconv.FormatInt(cred.UpdatedAt.UnixNano(), 10), ref.SecretName, ref.VersionID, agentMintParamsKey(params)}, "\x00")
	rt.mu.Lock()
	if tok, ok := rt.cache[key]; ok && rt.now().Before(tok.ExpiresAt.Add(-agentMintRefreshBefore)) {
		rt.mu.Unlock()
		return tok, nil
	}
	if call, ok := rt.inflight[key]; ok {
		rt.mu.Unlock()
		select {
		case <-call.done:
			return call.tok, call.err
		case <-ctx.Done():
			return providertoken.Token{}, ctx.Err()
		}
	}
	call := &agentMintCall{done: make(chan struct{})}
	rt.inflight[key] = call
	rt.mu.Unlock()

	// The mint outlives a cancelled waiter: others may share it.
	mctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), providertoken.DefaultTimeout+5*time.Second)
	call.tok, call.err = s.mintAgentToken(mctx, accountID, cred, ref, params)
	cancel()

	rt.mu.Lock()
	delete(rt.inflight, key)
	if call.err == nil && !call.tok.ExpiresAt.IsZero() && rt.now().Before(call.tok.ExpiresAt.Add(-agentMintRefreshBefore)) {
		if len(rt.cache) >= agentMintCacheMax {
			now := rt.now()
			for k, t := range rt.cache {
				if !now.Before(t.ExpiresAt.Add(-agentMintRefreshBefore)) {
					delete(rt.cache, k)
				}
			}
			if len(rt.cache) >= agentMintCacheMax {
				rt.cache = map[string]providertoken.Token{}
			}
		}
		rt.cache[key] = call.tok
	}
	rt.mu.Unlock()
	close(call.done)
	return call.tok, call.err
}

// mintAgentToken builds the provider minter from the secret and the
// profile, and mints one token.
func (s *Server) mintAgentToken(ctx context.Context, accountID string, cred store.AgentCredential, ref agentSecretRef, params providertoken.Params) (providertoken.Token, error) {
	value, err := s.agentSecretValue(ctx, accountID, ref)
	if err != nil {
		return providertoken.Token{}, err
	}
	m, err := s.agentProviderMinter(cred, value)
	if err != nil {
		return providertoken.Token{}, errAgentMint{err}
	}
	tok, err := m.Mint(ctx, params)
	if err != nil {
		return providertoken.Token{}, errAgentMint{err}
	}
	return tok, nil
}

// errAgentMint wraps a failure to mint a token (as opposed to a missing
// source secret).
type errAgentMint struct{ err error }

func (e errAgentMint) Error() string { return "minting failed: " + e.err.Error() }
func (e errAgentMint) Unwrap() error { return e.err }

// agentMintFailure maps a failure to produce a credential's value onto the
// agent's response.
func agentMintFailure(err error) *agentFailure {
	var scope errAgentScope
	if errors.As(err, &scope) {
		return &agentFailure{Status: http.StatusForbidden, Code: "forbidden", Reason: "scope_invalid", Message: "the grant's scope no longer fits the credential: " + scope.msg}
	}
	var mint errAgentMint
	if errors.As(err, &mint) {
		return mintFailure(mint.err)
	}
	return &agentFailure{Status: http.StatusForbidden, Code: "forbidden", Reason: agentDenyCredentialUnavailable, Message: "the credential's secret is not available"}
}

// mintedBrokerProfile adapts p for a minted credential: bearer tokens are
// injected as a header, AWS credentials sign the request with SigV4.
func mintedBrokerProfile(c store.AgentCredential, p *agentbroker.Profile) {
	switch c.Kind {
	case store.AgentCredentialGitHubApp:
		p.Kind, p.HeaderName, p.HeaderPrefix = agentbroker.KindHTTPHeader, "Authorization", "Bearer "
	case store.AgentCredentialOAuth2:
		p.Kind, p.HeaderName, p.HeaderPrefix = agentbroker.KindHTTPHeader, "Authorization", "Bearer "
		if cfg := c.Config.OAuth2; cfg != nil && cfg.HeaderName != "" && !strings.EqualFold(cfg.HeaderName, "Authorization") {
			p.HeaderName, p.HeaderPrefix = cfg.HeaderName, cfg.HeaderPrefix
		} else if cfg != nil && cfg.HeaderPrefix != "" {
			p.HeaderPrefix = cfg.HeaderPrefix
		}
	case store.AgentCredentialAWSSTS:
		cfg := c.Config.AWSSTS
		if cfg == nil || cfg.SigningService == "" {
			return // reveal only: the broker refuses kind aws_sts
		}
		region := cfg.SigningRegion
		if region == "" {
			region = cfg.Region
		}
		if region == "" {
			region = "us-east-1"
		}
		p.Kind, p.SigV4Service, p.SigV4Region = agentbroker.KindAWSSigV4, cfg.SigningService, region
	}
}

// agentProviderMinter builds the minter for a minted credential from its
// source material.
func (s *Server) agentProviderMinter(cred store.AgentCredential, source string) (providertoken.Minter, error) {
	client := s.agentBrokerRT().httpClient(brokerProfile(cred).AllowedCIDRs)
	switch cred.Kind {
	case store.AgentCredentialAWSSTS:
		cfg := cred.Config.AWSSTS
		if cfg == nil {
			return nil, errors.New("aws_sts credential has no configuration")
		}
		var src struct {
			AccessKeyID     string `json:"accessKeyId"`
			SecretAccessKey string `json:"secretAccessKey"`
			SessionToken    string `json:"sessionToken"`
		}
		if err := json.Unmarshal([]byte(source), &src); err != nil || src.AccessKeyID == "" || src.SecretAccessKey == "" {
			return nil, errors.New("aws_sts source secret must be JSON {accessKeyId, secretAccessKey}")
		}
		return providertoken.NewAWSSTS(providertoken.AWSSTSConfig{
			Endpoint: cfg.Endpoint, Region: cfg.Region, RoleARN: cfg.RoleARN, ExternalID: cfg.ExternalID,
			SessionName: cfg.SessionName, SessionPolicy: cfg.SessionPolicy, Duration: time.Duration(cfg.DurationSeconds) * time.Second,
			Source:            providertoken.AWSCredentials{AccessKeyID: src.AccessKeyID, SecretAccessKey: src.SecretAccessKey, SessionToken: src.SessionToken},
			AllowInsecureHTTP: cred.AllowHTTP,
		}, client)
	case store.AgentCredentialGitHubApp:
		cfg := cred.Config.GitHubApp
		if cfg == nil {
			return nil, errors.New("github_app credential has no configuration")
		}
		key := strings.TrimSpace(source)
		if strings.HasPrefix(key, "{") {
			var doc struct {
				PrivateKey string `json:"privateKey"`
			}
			if err := json.Unmarshal([]byte(key), &doc); err != nil {
				return nil, errors.New("github_app source secret must be the App's PEM private key")
			}
			key = doc.PrivateKey
		}
		return providertoken.NewGitHubApp(providertoken.GitHubAppConfig{
			BaseURL: cfg.BaseURL, AppID: cfg.AppID, InstallationID: cfg.InstallationID, PrivateKeyPEM: []byte(key),
			Repositories: cfg.Repositories, Permissions: cfg.Permissions, AllowInsecureHTTP: cred.AllowHTTP,
		}, client)
	case store.AgentCredentialOAuth2:
		cfg := cred.Config.OAuth2
		if cfg == nil {
			return nil, errors.New("oauth2_client_credentials credential has no configuration")
		}
		clientID, secret := cfg.ClientID, source
		if t := strings.TrimSpace(source); strings.HasPrefix(t, "{") {
			var doc struct {
				ClientID     string `json:"clientId"`
				ClientSecret string `json:"clientSecret"`
			}
			if err := json.Unmarshal([]byte(t), &doc); err != nil {
				return nil, errors.New("oauth2 source secret must be the client secret or JSON {clientId, clientSecret}")
			}
			if doc.ClientID != "" {
				clientID = doc.ClientID
			}
			secret = doc.ClientSecret
		}
		style := providertoken.AuthStyleBasic
		if cfg.ClientAuth == "post" {
			style = providertoken.AuthStylePost
		}
		// One-shot minter: Citadel caches the token itself (per scope).
		return providertoken.NewOAuth2ClientCredentials(providertoken.OAuth2Config{
			TokenURL: cfg.TokenURL, ClientID: clientID, ClientSecret: secret, AuthStyle: style,
			Scopes: cfg.Scopes, Audience: cfg.Audience, Resource: cfg.Resource, AllowInsecureHTTP: cred.AllowHTTP,
		}, client)
	}
	return nil, errors.New("not a minted credential kind")
}
