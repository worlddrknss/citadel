package providertoken

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	testRSAOnce sync.Once
	testRSAKey  *rsa.PrivateKey
)

func githubTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testRSAOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		testRSAKey = k
	})
	return testRSAKey
}

func pkcs1PEM(k *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
}

const testInstallToken = "ghs_installationTokenExample0123456789"

type fakeGitHub struct {
	pub     *rsa.PublicKey
	mu      sync.Mutex
	path    string
	headers http.Header
	body    map[string]any
	claims  map[string]any
	jwtErr  error
	status  int
}

func (f *fakeGitHub) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.path, f.headers = r.URL.Path, r.Header.Clone()
	b, _ := io.ReadAll(r.Body)
	f.body = nil
	_ = json.Unmarshal(b, &f.body)
	f.claims, f.jwtErr = verifyRS256(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), f.pub)
	if f.status != 0 {
		w.WriteHeader(f.status)
		io.WriteString(w, `{"message":"Bad credentials `+testInstallToken+`"}`)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	io.WriteString(w, `{"token":"`+testInstallToken+`","expires_at":"2026-11-13T13:00:00Z",
		"permissions":{"contents":"read","issues":"write"},"repository_selection":"selected",
		"repositories":[{"name":"web","full_name":"acme/web"},{"name":"api","full_name":"acme/api"}]}`)
}

func verifyRS256(tok string, pub *rsa.PublicKey) (map[string]any, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a JWT")
	}
	hdr, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var h map[string]any
	if err := json.Unmarshal(hdr, &h); err != nil || h["alg"] != "RS256" || h["typ"] != "JWT" || len(h) != 2 {
		return nil, errors.New("bad header")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return nil, err
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c map[string]any
	return c, json.Unmarshal(payload, &c)
}

func newTestGitHub(t *testing.T, f *fakeGitHub, mod func(*GitHubAppConfig)) *GitHubApp {
	t.Helper()
	key := githubTestKey(t)
	f.pub = &key.PublicKey
	srv, client := newTLS(t, f.handler)
	cfg := GitHubAppConfig{BaseURL: srv.URL + "/api/v3/", AppID: "123456", InstallationID: 987, PrivateKeyPEM: pkcs1PEM(key)}
	if mod != nil {
		mod(&cfg)
	}
	g, err := NewGitHubApp(cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestGitHubAppMint(t *testing.T) {
	f := &fakeGitHub{}
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	g := newTestGitHub(t, f, func(c *GitHubAppConfig) { c.Now = func() time.Time { return now } })
	tok, err := g.Mint(context.Background(), Params{Repositories: []string{"web", "api"}, Permissions: map[string]string{"contents": "read", "issues": "write"}})
	if err != nil {
		t.Fatal(err)
	}
	if f.jwtErr != nil {
		t.Fatalf("App JWT did not verify: %v", f.jwtErr)
	}
	// Enterprise base URL path is kept.
	if f.path != "/api/v3/app/installations/987/access_tokens" {
		t.Fatalf("path = %s", f.path)
	}
	if f.headers.Get("Accept") != "application/vnd.github+json" || f.headers.Get("X-GitHub-Api-Version") != "2022-11-28" {
		t.Fatalf("headers = %v", f.headers)
	}
	iat, exp := int64(f.claims["iat"].(float64)), int64(f.claims["exp"].(float64))
	if f.claims["iss"] != "123456" || iat != now.Add(-60*time.Second).Unix() || exp-now.Unix() > 600 || exp-iat > 600 || exp <= now.Unix() {
		t.Fatalf("claims = %v", f.claims)
	}
	repos, _ := f.body["repositories"].([]any)
	perms, _ := f.body["permissions"].(map[string]any)
	if len(repos) != 2 || repos[0] != "web" || perms["contents"] != "read" || perms["issues"] != "write" {
		t.Fatalf("request body = %v", f.body)
	}
	if _, ok := f.body["repository_ids"]; ok {
		t.Fatal("empty repository_ids sent")
	}
	if tok.Value != testInstallToken || tok.Kind != KindGitHubApp || !tok.ExpiresAt.Equal(time.Date(2026, 11, 13, 13, 0, 0, 0, time.UTC)) {
		t.Fatalf("token = %v", tok)
	}
	if tok.Metadata["repositories"] != "api,web" || tok.Metadata["repositorySelection"] != "selected" ||
		tok.Metadata["permissions"] != `{"contents":"read","issues":"write"}` || tok.Metadata["installationId"] != "987" {
		t.Fatalf("metadata = %v", tok.Metadata)
	}
}

func TestGitHubAppDefaultsAndIDs(t *testing.T) {
	f := &fakeGitHub{}
	g := newTestGitHub(t, f, func(c *GitHubAppConfig) {
		c.RepositoryIDs = []int64{42}
		c.Permissions = map[string]string{"metadata": "read"}
	})
	if _, err := g.Mint(context.Background(), Params{}); err != nil {
		t.Fatal(err)
	}
	ids, _ := f.body["repository_ids"].([]any)
	if len(ids) != 1 || ids[0] != float64(42) || f.body["permissions"].(map[string]any)["metadata"] != "read" {
		t.Fatalf("defaults not applied: %v", f.body)
	}
}

func TestGitHubAppErrors(t *testing.T) {
	f := &fakeGitHub{status: http.StatusUnauthorized}
	g := newTestGitHub(t, f, nil)
	_, err := g.Mint(context.Background(), Params{})
	var pe *ProviderError
	if !errors.As(err, &pe) || pe.Status != 401 {
		t.Fatalf("err = %v", err)
	}
	noSecrets(t, err, testInstallToken, "Bad credentials")

	g = newTestGitHub(t, &fakeGitHub{}, nil)
	for name, p := range map[string]Params{
		"owner in repo":   {Repositories: []string{"acme/web"}},
		"bad permission":  {Permissions: map[string]string{"contents": "owner"}},
		"bad perm name":   {Permissions: map[string]string{"Contents!": "read"}},
		"negative repoID": {RepositoryIDs: []int64{-1}},
	} {
		if _, err := g.Mint(context.Background(), p); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestParseGitHubAppKey(t *testing.T) {
	key := githubTestKey(t)
	if _, err := ParseGitHubAppKey(pkcs1PEM(key)); err != nil {
		t.Fatalf("PKCS#1: %v", err)
	}
	p8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseGitHubAppKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8})); err != nil {
		t.Fatalf("PKCS#8: %v", err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec8, _ := x509.MarshalPKCS8PrivateKey(ec)
	if _, err := ParseGitHubAppKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ec8})); err == nil {
		t.Fatal("EC key accepted")
	}
	for name, in := range map[string][]byte{
		"not PEM":      []byte("-----not a key-----"),
		"garbage DER":  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("secret-key-material")}),
		"wrong type":   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}),
		"public key":   pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1}}),
		"empty":        nil,
		"pkcs8 broken": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret-key-material")}),
	} {
		_, err := ParseGitHubAppKey(in)
		if err == nil {
			t.Errorf("%s accepted", name)
		}
		noSecrets(t, err, "secret-key-material")
	}
	// A 1024-bit key is refused. Go's FIPS module will not generate one, so
	// this case only runs outside fips140=only.
	if small, err := rsa.GenerateKey(rand.Reader, 1024); err == nil {
		if _, err := ParseGitHubAppKey(pkcs1PEM(small)); err == nil {
			t.Fatal("1024-bit key accepted")
		}
	}
}

func TestNewGitHubAppValidation(t *testing.T) {
	key := pkcs1PEM(githubTestKey(t))
	base := GitHubAppConfig{AppID: "Iv1.abc123", InstallationID: 1, PrivateKeyPEM: key}
	if _, err := NewGitHubApp(base, &http.Client{}); err != nil {
		t.Fatalf("valid config (client ID issuer) refused: %v", err)
	}
	for name, mod := range map[string]func(*GitHubAppConfig){
		"http base":       func(c *GitHubAppConfig) { c.BaseURL = "http://ghe.local/api/v3" },
		"bad app id":      func(c *GitHubAppConfig) { c.AppID = "a b" },
		"no installation": func(c *GitHubAppConfig) { c.InstallationID = 0 },
		"no key":          func(c *GitHubAppConfig) { c.PrivateKeyPEM = nil },
		"bad default":     func(c *GitHubAppConfig) { c.Repositories = []string{"a/b"} },
	} {
		cfg := base
		mod(&cfg)
		if _, err := NewGitHubApp(cfg, &http.Client{}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
