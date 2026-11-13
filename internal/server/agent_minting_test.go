package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// echoUpstream records the Authorization header (and X-Amz-Security-Token)
// of each request and echoes the Authorization back.
type echoUpstream struct {
	mu   sync.Mutex
	auth []string
	tok  []string
	srv  *httptest.Server
}

func newEchoUpstream(t *testing.T) *echoUpstream {
	u := &echoUpstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.auth = append(u.auth, r.Header.Get("Authorization"))
		u.tok = append(u.tok, r.Header.Get("X-Amz-Security-Token"))
		u.mu.Unlock()
		_, _ = w.Write([]byte("auth=" + r.Header.Get("Authorization")))
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *echoUpstream) host() string { return strings.TrimPrefix(u.srv.URL, "http://") }
func (u *echoUpstream) last() (string, string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.auth[len(u.auth)-1], u.tok[len(u.tok)-1]
}

func TestAgentMintedOAuth2(t *testing.T) {
	const clientSecret = "oauth-client-secret-never-leaks"
	var calls atomic.Int32
	var gotScope atomic.Value
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		user, pass, ok := r.BasicAuth()
		_ = r.ParseForm()
		if !ok || user != "citadel-client" || pass != clientSecret || r.PostForm.Get("grant_type") != "client_credentials" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			return
		}
		gotScope.Store(r.PostForm.Get("scope"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"minted-access-token-1","token_type":"Bearer","expires_in":3600}`))
	}))
	defer tokenSrv.Close()
	up := newEchoUpstream(t)

	e := newAuthEnv(t)
	bob := e.session("bob", e.acctA)
	e.createSecret(e.acctA, "app/prod/OAUTH_CLIENT", clientSecret)
	cred := map[string]any{
		"name": "partner-api", "project": "app", "env": "prod", "key": "OAUTH_CLIENT", "kind": "oauth2_client_credentials",
		"allowedHosts": []string{up.host()}, "allowHttp": true, "allowedCidrs": []string{"127.0.0.1/32"},
		"oauth2": map[string]any{"tokenUrl": tokenSrv.URL + "/token", "clientId": "citadel-client", "scopes": []string{"read", "write"}},
	}
	rec := e.do(http.MethodPost, "/v1/agents/credentials", cred, bob)
	wantStatus(t, rec, http.StatusCreated)
	if decode(t, rec)["oauth2"].(map[string]any)["tokenUrl"] != tokenSrv.URL+"/token" {
		t.Fatalf("config not returned: %s", rec.Body)
	}
	id := e.agentCreate(bob, "partner")
	tok := e.agentToken(bob, id, 1)
	// A grant's scopes must be a subset of the credential's.
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/grants", map[string]any{"agentId": id, "credential": "partner-api", "actions": []string{"use", "reveal"},
		"scope": map[string]any{"scopes": []string{"admin"}}}, bob), http.StatusBadRequest)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/grants", map[string]any{"agentId": id, "credential": "partner-api", "actions": []string{"use", "reveal"},
		"scope": map[string]any{"repositories": []string{"x"}}}, bob), http.StatusBadRequest)
	rec = e.do(http.MethodPost, "/v1/agents/grants", map[string]any{"agentId": id, "credential": "partner-api", "actions": []string{"use", "reveal"},
		"scope": map[string]any{"scopes": []string{"read"}}}, bob)
	wantStatus(t, rec, http.StatusOK)
	if decode(t, rec)["scope"].(map[string]any)["scopes"].([]any)[0] != "read" {
		t.Fatalf("grant scope: %s", rec.Body)
	}

	for i := 0; i < 3; i++ {
		rec = e.do(http.MethodPost, "/v1/agent/http", map[string]any{"credential": "partner-api", "url": up.srv.URL + "/v1/x"}, nil, bearer(tok))
		wantStatus(t, rec, http.StatusOK)
		if body := decode(t, rec)["body"]; body != "auth=Bearer [REDACTED]" {
			t.Fatalf("brokered body %v", body)
		}
	}
	if a, _ := up.last(); a != "Bearer minted-access-token-1" {
		t.Fatalf("upstream saw %q", a)
	}
	if calls.Load() != 1 || gotScope.Load() != "read" {
		t.Fatalf("token endpoint calls=%d scope=%v (want 1 cached call with the grant's scope)", calls.Load(), gotScope.Load())
	}
	// Reveal returns the short-lived token with its expiry, never the client secret.
	rec = e.do(http.MethodPost, "/v1/agent/credentials/reveal", map[string]any{"credential": "partner-api"}, nil, bearer(tok))
	wantStatus(t, rec, http.StatusOK)
	out := decode(t, rec)
	if out["value"] != "minted-access-token-1" || out["kind"] != "oauth2_client_credentials" || out["expiresAt"] == nil || strings.Contains(rec.Body.String(), clientSecret) {
		t.Fatalf("reveal = %s", rec.Body)
	}
	// A new client secret takes effect at once (cache keyed by version); a
	// rejected one is a token_unavailable error with the provider's code.
	if _, err := e.st.PutSecretValue(store.WithCallerAccount(t.Context(), e.acctA), store.PutSecretValueRequest{SecretID: "app/prod/OAUTH_CLIENT", SecretString: "wrong-secret"}); err != nil {
		t.Fatal(err)
	}
	rec = e.do(http.MethodPost, "/v1/agent/http", map[string]any{"credential": "partner-api", "url": up.srv.URL + "/v1/x"}, nil, bearer(tok))
	wantStatus(t, rec, http.StatusBadGateway)
	if got := decode(t, rec); got["reason"] != "token_unavailable" || !strings.Contains(got["message"].(string), "HTTP 401") {
		t.Fatalf("bad client secret: %v", got)
	}
	for _, ev := range e.agentEvents(e.acctA, id) {
		if strings.Contains(ev.Resource+ev.KeyID+ev.ErrorType, "minted-access-token") || strings.Contains(ev.Resource, clientSecret) {
			t.Fatalf("audit leaks a token: %+v", ev)
		}
	}
}

func testRSAKeyPEM(t *testing.T) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
}

func TestAgentMintedGitHubApp(t *testing.T) {
	var mu sync.Mutex
	var reqBody map[string]any
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/app/installations/77/access_tokens" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ey") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		reqBody = nil
		_ = json.Unmarshal(b, &reqBody)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		_, _ = w.Write([]byte(`{"token":"ghs_installationtoken123","expires_at":"` + exp + `","permissions":{"contents":"read"},"repository_selection":"selected"}`))
	}))
	defer gh.Close()
	up := newEchoUpstream(t)

	e := newAuthEnv(t)
	bob := e.session("bob", e.acctA)
	e.createSecret(e.acctA, "app/prod/GH_APP_KEY", testRSAKeyPEM(t))
	cred := map[string]any{
		"name": "gh", "project": "app", "env": "prod", "key": "GH_APP_KEY", "kind": "github_app",
		"allowedHosts": []string{up.host()}, "allowHttp": true, "allowedCidrs": []string{"127.0.0.1/32"},
		"githubApp": map[string]any{"appId": "12345", "installationId": 77, "baseUrl": gh.URL},
	}
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/credentials", cred, bob), http.StatusCreated)
	id := e.agentCreate(bob, "gh-bot")
	tok := e.agentToken(bob, id, 1)
	// No default restriction on the credential: the grant must restrict.
	rec := e.do(http.MethodPost, "/v1/agents/grants", map[string]any{"agentId": id, "credential": "gh", "actions": []string{"use", "reveal"}}, bob)
	wantStatus(t, rec, http.StatusBadRequest)
	if !strings.Contains(rec.Body.String(), "installation-wide") {
		t.Fatalf("unrestricted grant: %s", rec.Body)
	}
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/grants", map[string]any{"agentId": id, "credential": "gh", "actions": []string{"use", "reveal"},
		"scope": map[string]any{"repositories": []string{"api"}, "permissions": map[string]string{"contents": "read"}}}, bob), http.StatusOK)

	rec = e.do(http.MethodPost, "/v1/agent/http", map[string]any{"credential": "gh", "url": up.srv.URL + "/repos/acme/api"}, nil, bearer(tok))
	wantStatus(t, rec, http.StatusOK)
	if a, _ := up.last(); a != "Bearer ghs_installationtoken123" {
		t.Fatalf("upstream saw %q", a)
	}
	mu.Lock()
	if repos, _ := reqBody["repositories"].([]any); len(repos) != 1 || repos[0] != "api" || reqBody["permissions"].(map[string]any)["contents"] != "read" {
		t.Fatalf("GitHub request body %v", reqBody)
	}
	mu.Unlock()
	rec = e.do(http.MethodPost, "/v1/agent/credentials/reveal", map[string]any{"credential": "gh"}, nil, bearer(tok))
	wantStatus(t, rec, http.StatusOK)
	if out := decode(t, rec); out["value"] != "ghs_installationtoken123" || out["expiresAt"] == nil || strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Fatalf("reveal = %s", rec.Body)
	}

	// Credential defaults bound what grants may ask for, also on update.
	cred["githubApp"] = map[string]any{"appId": "12345", "installationId": 77, "baseUrl": gh.URL, "repositories": []string{"web"}}
	rec = e.do(http.MethodPost, "/v1/agents/credentials/update", cred, bob)
	wantStatus(t, rec, http.StatusConflict)
	cred["githubApp"] = map[string]any{"appId": "12345", "installationId": 77, "baseUrl": gh.URL, "repositories": []string{"api", "web"}, "permissions": map[string]string{"contents": "write"}}
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/credentials/update", cred, bob), http.StatusOK)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/grants", map[string]any{"agentId": id, "credential": "gh", "actions": []string{"use"},
		"scope": map[string]any{"permissions": map[string]string{"contents": "admin"}}}, bob), http.StatusBadRequest)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/grants", map[string]any{"agentId": id, "credential": "gh", "actions": []string{"use"},
		"scope": map[string]any{"repositories": []string{"other"}}}, bob), http.StatusBadRequest)
	// With defaults on the credential, an unscoped grant is fine and uses them.
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/grants", map[string]any{"agentId": id, "credential": "gh", "actions": []string{"use"}}, bob), http.StatusOK)
	wantStatus(t, e.do(http.MethodPost, "/v1/agent/http", map[string]any{"credential": "gh", "url": up.srv.URL + "/x"}, nil, bearer(tok)), http.StatusOK)
	mu.Lock()
	if repos, _ := reqBody["repositories"].([]any); len(repos) != 2 || reqBody["permissions"].(map[string]any)["contents"] != "write" {
		t.Fatalf("defaults not applied: %v", reqBody)
	}
	mu.Unlock()
}

func TestAgentMintedAWSSTS(t *testing.T) {
	const sourceSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYSOURCEKEY"
	var stsCalls atomic.Int32
	var policy atomic.Value
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stsCalls.Add(1)
		_ = r.ParseForm()
		if r.PostForm.Get("Action") != "AssumeRole" || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIASOURCE/") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>`))
			return
		}
		policy.Store(r.PostForm.Get("Policy"))
		exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		_, _ = w.Write([]byte(`<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIATEMPKEY</AccessKeyId>` +
			`<SecretAccessKey>tempSecretKeyValue0123456789abcdefghij</SecretAccessKey><SessionToken>temp-session-token-xyz</SessionToken>` +
			`<Expiration>` + exp + `</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/agent/citadel-agent</Arn>` +
			`<AssumedRoleId>AROA:citadel-agent</AssumedRoleId></AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>`))
	}))
	defer sts.Close()
	up := newEchoUpstream(t)

	e := newAuthEnv(t)
	bob := e.session("bob", e.acctA)
	src, _ := json.Marshal(map[string]string{"accessKeyId": "AKIASOURCE", "secretAccessKey": sourceSecret})
	e.createSecret(e.acctA, "app/prod/AWS_SOURCE", string(src))
	cred := map[string]any{
		"name": "aws-deploy", "project": "app", "env": "prod", "key": "AWS_SOURCE", "kind": "aws_sts",
		"allowedHosts": []string{up.host()}, "allowedMethods": []string{"GET", "POST"}, "allowHttp": true, "allowedCidrs": []string{"127.0.0.1/32"},
		"awsSts": map[string]any{"roleArn": "arn:aws:iam::123456789012:role/agent", "endpoint": sts.URL, "region": "eu-west-1", "signingService": "s3", "durationSeconds": 900},
	}
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/credentials", map[string]any{"name": "bad", "project": "app", "env": "prod", "key": "AWS_SOURCE", "kind": "aws_sts",
		"awsSts": map[string]any{"roleArn": "not-an-arn"}}, bob), http.StatusBadRequest)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/credentials", cred, bob), http.StatusCreated)
	id := e.agentCreate(bob, "deployer")
	tok := e.agentToken(bob, id, 1)
	pol := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/grants", map[string]any{"agentId": id, "credential": "aws-deploy", "actions": []string{"use", "reveal"},
		"scope": map[string]any{"sessionPolicy": pol}}, bob), http.StatusOK)

	rec := e.do(http.MethodPost, "/v1/agent/http", map[string]any{"credential": "aws-deploy", "method": "POST", "url": up.srv.URL + "/bucket/key", "body": "hello",
		"headers": map[string]string{"X-Amz-Security-Token": "agent-forged", "X-Amz-Target": "S3.Put"}}, nil, bearer(tok))
	wantStatus(t, rec, http.StatusOK)
	auth, sessTok := up.last()
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=ASIATEMPKEY/") || !strings.Contains(auth, "/eu-west-1/s3/aws4_request") || sessTok != "temp-session-token-xyz" {
		t.Fatalf("upstream auth %q token %q", auth, sessTok)
	}
	if strings.Contains(rec.Body.String(), "tempSecretKeyValue") || strings.Contains(rec.Body.String(), "temp-session-token") {
		t.Fatalf("response leaks credentials: %s", rec.Body)
	}
	if policy.Load() != pol {
		t.Fatalf("session policy sent: %v", policy.Load())
	}
	rec = e.do(http.MethodPost, "/v1/agent/credentials/reveal", map[string]any{"credential": "aws-deploy"}, nil, bearer(tok))
	wantStatus(t, rec, http.StatusOK)
	out := decode(t, rec)
	var doc map[string]any
	if err := json.Unmarshal([]byte(out["value"].(string)), &doc); err != nil || doc["AccessKeyId"] != "ASIATEMPKEY" || doc["Version"] != float64(1) || out["expiresAt"] == nil {
		t.Fatalf("reveal = %s", rec.Body)
	}
	if strings.Contains(rec.Body.String(), sourceSecret) || stsCalls.Load() != 1 {
		t.Fatalf("source leaked or not cached (sts calls %d)", stsCalls.Load())
	}
	// The credential's own session policy forbids a grant's.
	cred["awsSts"] = map[string]any{"roleArn": "arn:aws:iam::123456789012:role/agent", "endpoint": sts.URL, "signingService": "s3", "sessionPolicy": pol}
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/credentials/update", cred, bob), http.StatusConflict)

	// The minters' outbound calls go through the SSRF guard: without the
	// loopback CIDR the STS endpoint is refused.
	cred["name"], cred["allowedCidrs"] = "aws-guarded", []string{}
	cred["awsSts"] = map[string]any{"roleArn": "arn:aws:iam::123456789012:role/agent", "endpoint": sts.URL, "signingService": "s3"}
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/credentials", cred, bob), http.StatusCreated)
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/grants", map[string]any{"agentId": id, "credential": "aws-guarded", "actions": []string{"reveal"}}, bob), http.StatusOK)
	before := stsCalls.Load()
	rec = e.do(http.MethodPost, "/v1/agent/credentials/reveal", map[string]any{"credential": "aws-guarded"}, nil, bearer(tok))
	wantStatus(t, rec, http.StatusBadGateway)
	if stsCalls.Load() != before {
		t.Fatal("the STS call bypassed the SSRF guard")
	}
}
