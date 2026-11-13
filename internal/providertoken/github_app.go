package providertoken

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DefaultGitHubAPI is github.com's REST API base URL. GitHub Enterprise
// Server uses https://HOST/api/v3.
const DefaultGitHubAPI = "https://api.github.com"

// GitHub App JWT timing: iat is backdated for clock skew and exp is kept
// within GitHub's 10-minute ceiling (measured from GitHub's clock, so the
// lifetime counted from the backdated iat stays at 10 minutes).
const (
	githubJWTSkew     = 60 * time.Second
	githubJWTLifetime = 9 * time.Minute
)

// RSA modulus bounds for App private keys.
const (
	minGitHubRSABits = 2048
	maxGitHubRSABits = 16384
)

// GitHubAppConfig configures a GitHub App installation-token minter.
type GitHubAppConfig struct {
	// BaseURL is the REST API base; empty means DefaultGitHubAPI.
	BaseURL string
	// AppID is the JWT issuer: the App ID or the App's client ID.
	AppID string
	// InstallationID is the installation tokens are minted for.
	InstallationID int64
	// PrivateKeyPEM is the App private key ("RSA PRIVATE KEY" as GitHub
	// issues it, or PKCS #8 "PRIVATE KEY"); RSA, at least 2048 bits.
	PrivateKeyPEM []byte
	// Repositories, RepositoryIDs and Permissions are the default
	// restriction when a Mint call names none.
	Repositories  []string
	RepositoryIDs []int64
	Permissions   map[string]string
	// Timeout bounds the HTTP call; zero means DefaultTimeout.
	Timeout time.Duration
	// AllowInsecureHTTP permits an http:// base URL (development only).
	AllowInsecureHTTP bool
	// Now overrides the clock (tests).
	Now func() time.Time
}

// GitHubApp mints GitHub App installation access tokens. It reads
// Params.Repositories, Params.RepositoryIDs and Params.Permissions; when
// none is set the configured defaults apply, and when those are empty too
// the token has the installation's full access.
type GitHubApp struct {
	cfg    GitHubAppConfig
	key    *rsa.PrivateKey
	base   string
	client *http.Client
}

var (
	githubAppIDRE  = regexp.MustCompile(`^[A-Za-z0-9.]{1,64}$`)
	githubRepoRE   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	githubPermRE   = regexp.MustCompile(`^[a-z_]{1,64}$`)
	githubLevels   = map[string]bool{"read": true, "write": true, "admin": true}
	maxGitHubRepos = 500
)

// NewGitHubApp validates cfg, parses the private key and returns a minter
// that calls GitHub through client.
func NewGitHubApp(cfg GitHubAppConfig, client *http.Client) (*GitHubApp, error) {
	c, err := noRedirectClient(KindGitHubApp, client)
	if err != nil {
		return nil, err
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultGitHubAPI
	}
	if _, err := checkEndpoint(KindGitHubApp, cfg.BaseURL, cfg.AllowInsecureHTTP); err != nil {
		return nil, err
	}
	if !githubAppIDRE.MatchString(cfg.AppID) {
		return nil, errors.New("providertoken: github_app: invalid App ID")
	}
	if cfg.InstallationID <= 0 {
		return nil, errors.New("providertoken: github_app: invalid installation ID")
	}
	key, err := ParseGitHubAppKey(cfg.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	if err := checkGitHubRestriction(cfg.Repositories, cfg.RepositoryIDs, cfg.Permissions); err != nil {
		return nil, err
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &GitHubApp{cfg: cfg, key: key, base: strings.TrimRight(cfg.BaseURL, "/"), client: c}, nil
}

// ParseGitHubAppKey parses an RSA private key from PEM (PKCS #1 or PKCS #8)
// and requires a 2048–16384-bit modulus. Errors never include key material.
func ParseGitHubAppKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("providertoken: github_app: private key is not PEM")
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("providertoken: github_app: invalid RSA private key")
		}
		key = k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("providertoken: github_app: invalid PKCS #8 private key")
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("providertoken: github_app: private key is not RSA")
		}
		key = rk
	default:
		return nil, errors.New("providertoken: github_app: unsupported PEM block type")
	}
	if b := key.N.BitLen(); b < minGitHubRSABits || b > maxGitHubRSABits {
		return nil, errors.New("providertoken: github_app: RSA key must be 2048 to 16384 bits")
	}
	return key, nil
}

func checkGitHubRestriction(repos []string, ids []int64, perms map[string]string) error {
	if len(repos)+len(ids) > maxGitHubRepos {
		return errors.New("providertoken: github_app: too many repositories")
	}
	for _, r := range repos {
		if !githubRepoRE.MatchString(r) {
			return errors.New("providertoken: github_app: invalid repository name (use the name without the owner)")
		}
	}
	for _, id := range ids {
		if id <= 0 {
			return errors.New("providertoken: github_app: invalid repository ID")
		}
	}
	for k, v := range perms {
		if !githubPermRE.MatchString(k) || !githubLevels[v] {
			return errors.New("providertoken: github_app: invalid permission")
		}
	}
	return nil
}

// AppJWT returns the RS256 App JWT GitHub expects as the Bearer credential
// for App-level endpoints: iat 60 s in the past, exp 9 minutes ahead.
func (g *GitHubApp) AppJWT() (string, error) {
	now := g.cfg.Now()
	return signAppJWT(g.key, g.cfg.AppID, now)
}

func signAppJWT(key *rsa.PrivateKey, iss string, now time.Time) (string, error) {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, err := json.Marshal(struct {
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
		Iss string `json:"iss"`
	}{now.Add(-githubJWTSkew).Unix(), now.Add(githubJWTLifetime).Unix(), iss})
	if err != nil {
		return "", errors.New("providertoken: github_app: encoding JWT failed")
	}
	input := header + "." + enc.EncodeToString(claims)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", errors.New("providertoken: github_app: signing JWT failed")
	}
	return input + "." + enc.EncodeToString(sig), nil
}

// Mint exchanges an App JWT for an installation access token
// (POST /app/installations/{id}/access_tokens). Metadata carries the
// installation ID, granted permissions (JSON), repository selection and
// repository names; none of it is secret.
func (g *GitHubApp) Mint(ctx context.Context, p Params) (Token, error) {
	repos, ids, perms := p.Repositories, p.RepositoryIDs, p.Permissions
	if len(repos) == 0 && len(ids) == 0 && len(perms) == 0 {
		repos, ids, perms = g.cfg.Repositories, g.cfg.RepositoryIDs, g.cfg.Permissions
	}
	if err := checkGitHubRestriction(repos, ids, perms); err != nil {
		return Token{}, err
	}
	jwt, err := g.AppJWT()
	if err != nil {
		return Token{}, err
	}
	reqBody := struct {
		Repositories  []string          `json:"repositories,omitempty"`
		RepositoryIDs []int64           `json:"repository_ids,omitempty"`
		Permissions   map[string]string `json:"permissions,omitempty"`
	}{repos, ids, perms}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return Token{}, errors.New("providertoken: github_app: encoding request failed")
	}

	ctx, cancel := withTimeout(ctx, g.cfg.Timeout)
	defer cancel()
	endpoint := g.base + "/app/installations/" + url.PathEscape(strconv.FormatInt(g.cfg.InstallationID, 10)) + "/access_tokens"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Token{}, errors.New("providertoken: github_app: building request failed")
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, respBody, err := do(KindGitHubApp, g.client, req)
	if err != nil {
		return Token{}, err
	}
	if resp.StatusCode != http.StatusCreated {
		return Token{}, &ProviderError{Kind: KindGitHubApp, Status: resp.StatusCode}
	}
	var out struct {
		Token               string            `json:"token"`
		ExpiresAt           time.Time         `json:"expires_at"`
		Permissions         map[string]string `json:"permissions"`
		RepositorySelection string            `json:"repository_selection"`
		Repositories        []struct {
			Name     string `json:"name"`
			FullName string `json:"full_name"`
		} `json:"repositories"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil || out.Token == "" || out.ExpiresAt.IsZero() {
		return Token{}, errors.New("providertoken: github_app: malformed access token response")
	}
	meta := map[string]string{
		"installationId": strconv.FormatInt(g.cfg.InstallationID, 10),
	}
	if out.RepositorySelection == "all" || out.RepositorySelection == "selected" {
		meta["repositorySelection"] = out.RepositorySelection
	}
	if len(out.Permissions) > 0 {
		clean := map[string]string{}
		for k, v := range out.Permissions {
			if githubPermRE.MatchString(k) && githubLevels[v] {
				clean[k] = v
			}
		}
		if b, err := json.Marshal(clean); err == nil {
			meta["permissions"] = string(b)
		}
	}
	if len(out.Repositories) > 0 {
		names := make([]string, 0, len(out.Repositories))
		for _, r := range out.Repositories {
			if githubRepoRE.MatchString(r.Name) {
				names = append(names, r.Name)
			}
		}
		sort.Strings(names)
		meta["repositories"] = strings.Join(names, ",")
	}
	return Token{Value: out.Token, ExpiresAt: out.ExpiresAt.UTC(), Kind: KindGitHubApp, Metadata: meta}, nil
}
