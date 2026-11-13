package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/providertoken"
	"github.com/worlddrknss/citadel/internal/store"
)

// Usage profile settings for login and minted credentials (2.4), and the
// grant scopes that narrow minted tokens. See docs/agents.md.
//
// A profile's kind-specific settings arrive as one member of
// store.AgentCredentialConfig (login, awsSts, githubApp, oauth2), embedded
// in the credential request and response; a grant's narrowing as its scope.

const (
	maxAgentURLPatterns = 20
	maxAgentGitHubRepos = 100
	maxAgentGitHubPerms = 40
	maxAgentOAuthScopes = 50
)

var (
	agentRoleARNRe   = regexp.MustCompile(`^arn:[a-z0-9-]+:iam::[0-9]{12}:role/[\w+=,.@/-]{1,512}$`)
	agentAWSScopeRe  = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	agentAWSNameRe   = regexp.MustCompile(`^[\w+=,.@-]{2,64}$`)
	agentExternalRe  = regexp.MustCompile(`^[\w+=,.@:/-]{2,1224}$`)
	agentGHAppIDRe   = regexp.MustCompile(`^[A-Za-z0-9.]{1,64}$`)
	agentGHRepoRe    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	agentGHPermRe    = regexp.MustCompile(`^[a-z_]{1,64}$`)
	agentGHLevelRank = map[string]int{"read": 1, "write": 2, "admin": 3}
)

// agentFIPSSHA1Message explains why SHA-1 TOTP seeds are refused.
const agentFIPSSHA1Message = "this TOTP seed uses HMAC-SHA-1, which Citadel cannot compute: it runs in FIPS 140-3 mode, where SHA-1 HMAC is not an approved algorithm. Re-enrol the site's authenticator with SHA-256 or SHA-512 if it offers that"

// validEndpointURL checks an https URL (http only when allowHTTP) with a
// host and no userinfo, query or fragment.
func validEndpointURL(raw string, allowHTTP bool) bool {
	if len(raw) > 2048 {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	return u.Scheme == "https" || (allowHTTP && u.Scheme == "http")
}

// validateAgentCredentialConfig checks the kind-specific settings in in and
// stores the matching member in c.Config (others are dropped).
func validateAgentCredentialConfig(in store.AgentCredentialConfig, c *store.AgentCredential) string {
	c.Config = store.AgentCredentialConfig{}
	switch c.Kind {
	case store.AgentCredentialLogin:
		return validateLoginConfig(in.Login, c)
	case store.AgentCredentialAWSSTS:
		return validateAWSSTSConfig(in.AWSSTS, c)
	case store.AgentCredentialGitHubApp:
		return validateGitHubAppConfig(in.GitHubApp, c)
	case store.AgentCredentialOAuth2:
		return validateOAuth2Config(in.OAuth2, c)
	}
	return ""
}

func validateLoginConfig(in *store.AgentLoginConfig, c *store.AgentCredential) string {
	if in == nil {
		return "login credentials need login.urlPatterns (the pages the login may be used on)"
	}
	out := &store.AgentLoginConfig{}
	if len(in.URLPatterns) > maxAgentURLPatterns {
		return "at most 20 URL patterns"
	}
	for _, raw := range in.URLPatterns {
		p, ok := normalizeLoginPattern(raw)
		if !ok {
			return "URL patterns must be https://host[:port][/path], the host optionally *.example.com, with no query or fragment"
		}
		if !slices.Contains(out.URLPatterns, p) {
			out.URLPatterns = append(out.URLPatterns, p)
		}
	}
	if len(out.URLPatterns) == 0 {
		return "login credentials need at least one URL pattern"
	}
	switch alg := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(in.TOTPAlgorithm), "-", "")); alg {
	case "":
	case "SHA256", "SHA512":
		out.TOTPAlgorithm = alg
	case "SHA1":
		return "totpAlgorithm SHA1: " + agentFIPSSHA1Message
	default:
		return "totpAlgorithm must be SHA256 or SHA512"
	}
	if in.TOTPDigits != 0 && (in.TOTPDigits < 6 || in.TOTPDigits > 8) {
		return "totpDigits must be 6 to 8"
	}
	if in.TOTPPeriod != 0 && (in.TOTPPeriod < 10 || in.TOTPPeriod > 300) {
		return "totpPeriod must be 10 to 300 seconds"
	}
	out.TOTPDigits, out.TOTPPeriod = in.TOTPDigits, in.TOTPPeriod
	c.Config.Login = out
	return ""
}

// normalizeLoginPattern lowercases the scheme and host of a URL pattern and
// checks its shape.
func normalizeLoginPattern(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 512 {
		return "", false
	}
	if len(raw) < 9 || !strings.EqualFold(raw[:8], "https://") {
		return "", false
	}
	rest := raw[8:]
	if strings.ContainsAny(rest, "?#@\\ ") {
		return "", false
	}
	host, path, _ := strings.Cut(rest, "/")
	host = strings.ToLower(host)
	if !agentHostRe.MatchString(host) || len(host) > 253 {
		return "", false
	}
	if strings.HasPrefix(host, "*.") && !strings.Contains(strings.TrimPrefix(host, "*."), ".") {
		return "", false
	}
	path = "/" + path
	if !printable(path, 256) || strings.Contains(path, "/../") || strings.HasSuffix(path, "/..") {
		return "", false
	}
	return "https://" + host + path, true
}

func validateAWSSTSConfig(in *store.AgentAWSSTSConfig, c *store.AgentCredential) string {
	if in == nil {
		return "aws_sts credentials need awsSts.roleArn"
	}
	out := *in
	out.RoleARN = strings.TrimSpace(out.RoleARN)
	if !agentRoleARNRe.MatchString(out.RoleARN) {
		return "awsSts.roleArn must be an IAM role ARN (arn:aws:iam::123456789012:role/name)"
	}
	out.Endpoint = strings.TrimSpace(out.Endpoint)
	if out.Endpoint != "" && !validEndpointURL(out.Endpoint, c.AllowHTTP) {
		return "awsSts.endpoint must be an https URL with no query (empty: AWS's global STS endpoint)"
	}
	for _, f := range []struct{ v *string }{{&out.Region}, {&out.SigningService}, {&out.SigningRegion}} {
		*f.v = strings.TrimSpace(*f.v)
		if *f.v != "" && !agentAWSScopeRe.MatchString(*f.v) {
			return "awsSts.region, signingService and signingRegion must be lowercase AWS names such as eu-west-1 or s3"
		}
	}
	out.ExternalID = strings.TrimSpace(out.ExternalID)
	if out.ExternalID != "" && !agentExternalRe.MatchString(out.ExternalID) {
		return "awsSts.externalId must be 2-1224 letters, digits or +=,.@:/-_"
	}
	out.SessionName = strings.TrimSpace(out.SessionName)
	if out.SessionName != "" && !agentAWSNameRe.MatchString(out.SessionName) {
		return "awsSts.sessionName must be 2-64 letters, digits or +=,.@-_"
	}
	if msg := validSessionPolicy(out.SessionPolicy); msg != "" {
		return "awsSts.sessionPolicy " + msg
	}
	if out.DurationSeconds != 0 && (out.DurationSeconds < 900 || out.DurationSeconds > 43200) {
		return "awsSts.durationSeconds must be 900 to 43200"
	}
	c.Config.AWSSTS = &out
	return ""
}

func validSessionPolicy(p string) string {
	if p == "" {
		return ""
	}
	if len(p) > 2048 {
		return "must be at most 2048 bytes"
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(p), &doc); err != nil {
		return "must be a JSON policy document"
	}
	return ""
}

func validateGitHubAppConfig(in *store.AgentGitHubAppConfig, c *store.AgentCredential) string {
	if in == nil {
		return "github_app credentials need githubApp.appId and githubApp.installationId"
	}
	out := store.AgentGitHubAppConfig{AppID: strings.TrimSpace(in.AppID), InstallationID: in.InstallationID, BaseURL: strings.TrimRight(strings.TrimSpace(in.BaseURL), "/")}
	if !agentGHAppIDRe.MatchString(out.AppID) {
		return "githubApp.appId must be the App ID or client ID"
	}
	if out.InstallationID <= 0 {
		return "githubApp.installationId must be a positive number"
	}
	if out.BaseURL != "" && !validEndpointURL(out.BaseURL, c.AllowHTTP) {
		return "githubApp.baseUrl must be an https URL (GitHub Enterprise Server: https://HOST/api/v3)"
	}
	var msg string
	if out.Repositories, msg = githubRepos(in.Repositories); msg != "" {
		return "githubApp." + msg
	}
	if out.Permissions, msg = githubPerms(in.Permissions); msg != "" {
		return "githubApp." + msg
	}
	c.Config.GitHubApp = &out
	return ""
}

func githubRepos(in []string) ([]string, string) {
	if len(in) > maxAgentGitHubRepos {
		return nil, "repositories: at most 100"
	}
	var out []string
	for _, r := range in {
		r = strings.TrimSpace(r)
		if !agentGHRepoRe.MatchString(r) {
			return nil, "repositories must be repository names without the owner"
		}
		if !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out, ""
}

func githubPerms(in map[string]string) (map[string]string, string) {
	if len(in) == 0 {
		return nil, ""
	}
	if len(in) > maxAgentGitHubPerms {
		return nil, "permissions: at most 40"
	}
	out := map[string]string{}
	for k, v := range in {
		k, v = strings.TrimSpace(k), strings.ToLower(strings.TrimSpace(v))
		if !agentGHPermRe.MatchString(k) || agentGHLevelRank[v] == 0 {
			return nil, "permissions must map GitHub permission names (contents, issues, ...) to read, write or admin"
		}
		out[k] = v
	}
	return out, ""
}

func validateOAuth2Config(in *store.AgentOAuth2Config, c *store.AgentCredential) string {
	if in == nil {
		return "oauth2_client_credentials credentials need oauth2.tokenUrl"
	}
	out := store.AgentOAuth2Config{
		TokenURL: strings.TrimSpace(in.TokenURL), ClientID: strings.TrimSpace(in.ClientID), ClientAuth: strings.ToLower(strings.TrimSpace(in.ClientAuth)),
		Audience: strings.TrimSpace(in.Audience), Resource: strings.TrimSpace(in.Resource),
		HeaderName: strings.TrimSpace(in.HeaderName), HeaderPrefix: in.HeaderPrefix,
	}
	if !validEndpointURL(out.TokenURL, c.AllowHTTP) {
		return "oauth2.tokenUrl must be an https URL with no query or fragment"
	}
	if out.ClientID != "" && !printable(out.ClientID, 256) {
		return "oauth2.clientId must be at most 256 printable characters"
	}
	switch out.ClientAuth {
	case "", "basic", "post":
	default:
		return "oauth2.clientAuth must be basic or post"
	}
	var msg string
	if out.Scopes, msg = oauthScopes(in.Scopes); msg != "" {
		return "oauth2." + msg
	}
	if out.Audience != "" && !printable(out.Audience, 512) {
		return "oauth2.audience must be at most 512 printable characters"
	}
	if out.Resource != "" {
		if u, err := url.Parse(out.Resource); err != nil || !u.IsAbs() || u.Fragment != "" || !printable(out.Resource, 512) {
			return "oauth2.resource must be an absolute URI without a fragment"
		}
	}
	if out.HeaderName != "" {
		lower := strings.ToLower(out.HeaderName)
		if !agentHeaderRe.MatchString(out.HeaderName) || slices.Contains(agentForbiddenHeaders, lower) || strings.HasPrefix(lower, "proxy-") {
			return "oauth2.headerName must be a header name other than Host, Content-Length, Connection, Proxy-* and similar"
		}
	}
	if out.HeaderPrefix != "" && !printable(out.HeaderPrefix, 64) {
		return "oauth2.headerPrefix must be at most 64 printable characters"
	}
	c.Config.OAuth2 = &out
	return ""
}

func oauthScopes(in []string) ([]string, string) {
	if len(in) > maxAgentOAuthScopes {
		return nil, "scopes: at most 50"
	}
	var out []string
	for _, sc := range in {
		sc = strings.TrimSpace(sc)
		if sc == "" || len(sc) > 256 {
			return nil, "scopes must be non-empty scope tokens"
		}
		for i := 0; i < len(sc); i++ {
			if ch := sc[i]; ch < 0x21 || ch > 0x7e || ch == '"' || ch == '\\' {
				return nil, "scopes must be scope tokens (printable ASCII, no spaces, quotes or backslashes)"
			}
		}
		if !slices.Contains(out, sc) {
			out = append(out, sc)
		}
	}
	return out, ""
}

// validateAgentGrantScope checks a grant's scope against its credential and
// stores it in g.Scope. It also enforces that a github_app grant ends up
// restricted to some repositories or permissions.
func validateAgentGrantScope(in *store.AgentGrantScope, cred store.AgentCredential, g *store.AgentGrant) string {
	g.Scope = store.AgentGrantScope{}
	if in != nil {
		g.Scope = in.Clone()
	}
	return checkAgentGrantScope(&g.Scope, cred)
}

// checkAgentGrantScope normalizes scope in place and reports why it doesn't
// fit cred ("" when it does).
func checkAgentGrantScope(scope *store.AgentGrantScope, cred store.AgentCredential) string {
	cfg := cred.Config
	switch cred.Kind {
	case store.AgentCredentialGitHubApp:
		if scope.SessionPolicy != "" || len(scope.Scopes) > 0 {
			return "a github_app grant's scope may only set repositories and permissions"
		}
		var def store.AgentGitHubAppConfig
		if cfg.GitHubApp != nil {
			def = *cfg.GitHubApp
		}
		var msg string
		if scope.Repositories, msg = githubRepos(scope.Repositories); msg != "" {
			return "scope." + msg
		}
		if scope.Permissions, msg = githubPerms(scope.Permissions); msg != "" {
			return "scope." + msg
		}
		if len(def.Repositories) > 0 {
			for _, r := range scope.Repositories {
				if !slices.Contains(def.Repositories, r) {
					return "scope.repositories must be a subset of the credential's repositories (" + strings.Join(def.Repositories, ", ") + ")"
				}
			}
		}
		if len(def.Permissions) > 0 {
			for k, v := range scope.Permissions {
				max, ok := def.Permissions[k]
				if !ok || agentGHLevelRank[v] > agentGHLevelRank[max] {
					return "scope.permissions may only name the credential's permissions, at the same or a lower level"
				}
			}
		}
		if len(def.Repositories) == 0 && len(def.Permissions) == 0 && len(scope.Repositories) == 0 && len(scope.Permissions) == 0 {
			return "this github_app credential has no default repositories or permissions, so the grant must restrict them (scope.repositories or scope.permissions); Citadel never issues installation-wide tokens"
		}
	case store.AgentCredentialAWSSTS:
		if len(scope.Repositories) > 0 || len(scope.Permissions) > 0 || len(scope.Scopes) > 0 {
			return "an aws_sts grant's scope may only set sessionPolicy"
		}
		if scope.SessionPolicy != "" {
			if cfg.AWSSTS != nil && cfg.AWSSTS.SessionPolicy != "" {
				return "the credential already has a session policy; a grant can add one only when the credential has none"
			}
			if msg := validSessionPolicy(scope.SessionPolicy); msg != "" {
				return "scope.sessionPolicy " + msg
			}
		}
	case store.AgentCredentialOAuth2:
		if len(scope.Repositories) > 0 || len(scope.Permissions) > 0 || scope.SessionPolicy != "" {
			return "an oauth2_client_credentials grant's scope may only set scopes"
		}
		var msg string
		if scope.Scopes, msg = oauthScopes(scope.Scopes); msg != "" {
			return "scope." + msg
		}
		if cfg.OAuth2 != nil && len(cfg.OAuth2.Scopes) > 0 {
			for _, sc := range scope.Scopes {
				if !slices.Contains(cfg.OAuth2.Scopes, sc) {
					return "scope.scopes must be a subset of the credential's scopes (" + strings.Join(cfg.OAuth2.Scopes, " ") + ")"
				}
			}
		}
	default:
		if !scope.IsZero() {
			return "a scope applies only to aws_sts, github_app and oauth2_client_credentials credentials"
		}
	}
	return ""
}

// agentMintParams is what one Mint call for grant asks for: the grant's
// scope over the credential's defaults.
func agentMintParams(cred store.AgentCredential, grant store.AgentGrant) (providertoken.Params, string) {
	scope := grant.Scope.Clone()
	if msg := checkAgentGrantScope(&scope, cred); msg != "" {
		return providertoken.Params{}, msg
	}
	var p providertoken.Params
	switch cred.Kind {
	case store.AgentCredentialGitHubApp:
		def := cred.Config.GitHubApp
		p.Repositories, p.Permissions = scope.Repositories, scope.Permissions
		if len(p.Repositories) == 0 && def != nil {
			p.Repositories = def.Repositories
		}
		if len(p.Permissions) == 0 && def != nil {
			p.Permissions = def.Permissions
		}
	case store.AgentCredentialAWSSTS:
		p.SessionPolicy = scope.SessionPolicy
	case store.AgentCredentialOAuth2:
		p.Scopes = scope.Scopes
	}
	return p, ""
}

// agentMintParamsKey is a stable cache key for p.
func agentMintParamsKey(p providertoken.Params) string {
	var b strings.Builder
	repos := slices.Clone(p.Repositories)
	sort.Strings(repos)
	b.WriteString(strings.Join(repos, ","))
	b.WriteByte(0)
	keys := make([]string, 0, len(p.Permissions))
	for k := range p.Permissions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString(k + "=" + p.Permissions[k] + ",")
	}
	b.WriteByte(0)
	b.WriteString(p.SessionPolicy)
	b.WriteByte(0)
	scopes := slices.Clone(p.Scopes)
	sort.Strings(scopes)
	b.WriteString(strings.Join(scopes, " "))
	b.WriteByte(0)
	b.WriteString(strconv.FormatInt(int64(p.Duration/time.Second), 10))
	return b.String()
}

// mintFailure maps a minting error onto an agent failure. Provider errors
// carry only an HTTP status and a validated error code, so both may be shown.
func mintFailure(err error) *agentFailure {
	var pe *providertoken.ProviderError
	msg := "the credential's provider did not issue a token"
	if errors.As(err, &pe) {
		msg += " (HTTP " + strconv.Itoa(pe.Status)
		if pe.Code != "" {
			msg += ", " + pe.Code
		}
		msg += ")"
	}
	return &agentFailure{Status: http.StatusBadGateway, Code: "upstream_error", Reason: agentReasonTokenUnavailable, Message: msg}
}

const agentReasonTokenUnavailable = "token_unavailable"
