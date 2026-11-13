package citadel_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/servertest"
	"github.com/worlddrknss/citadel/sdk/citadel"
)

// These tests run the SDK against the real server (memory store) from
// internal/servertest, so they check real API behaviour, not a mock.

func newClient(t *testing.T, env *servertest.Env, key servertest.Key) *citadel.Client {
	t.Helper()
	c, err := citadel.New(citadel.Config{BaseURL: env.URL, AccessKeyID: key.ID, SecretAccessKey: key.Secret, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// rawPost calls an operation the SDK does not wrap (test setup only).
func rawPost(t *testing.T, env *servertest.Env, key servertest.Key, path string, body any, out any) {
	t.Helper()
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, env.URL+path, bytes.NewReader(buf))
	req.Header.Set("Authorization", "Bearer "+key.Token())
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		var e map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&e)
		t.Fatalf("POST %s: %d %v", path, resp.StatusCode, e)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMe(t *testing.T) {
	env := servertest.New(t)
	me, err := newClient(t, env, env.Editor).Me(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if me.Role != "editor" || me.AccountID != env.AccountID || me.Username != env.Editor.ID {
		t.Fatalf("me = %+v", me)
	}
}

func TestHierarchyAndSecrets(t *testing.T) {
	ctx := context.Background()
	env := servertest.New(t)
	c := newClient(t, env, env.Editor)

	if err := c.CreateProject(ctx, "shop", "Shop"); err != nil {
		t.Fatal(err)
	}
	if err := c.CreateEnvironment(ctx, "shop", "prod", "Production"); err != nil {
		t.Fatal(err)
	}
	if err := c.CreateFolder(ctx, "shop", "prod", "api/db"); err != nil {
		t.Fatal(err)
	}
	ref := citadel.SecretRef{Project: "shop", Env: "prod", Path: "api/db", Key: "PASSWORD"}
	res, err := c.PutSecret(ctx, citadel.PutSecretInput{Project: ref.Project, Env: ref.Env, Path: ref.Path, Key: ref.Key, Value: "v1"})
	if err != nil || !res.Created {
		t.Fatalf("put: %+v %v", res, err)
	}
	if res, err = c.PutSecret(ctx, citadel.PutSecretInput{Project: ref.Project, Env: ref.Env, Path: ref.Path, Key: ref.Key, Value: "v2"}); err != nil || res.Created {
		t.Fatalf("second put: %+v %v", res, err)
	}

	projects, err := c.ListProjects(ctx)
	if err != nil || len(projects) != 1 || projects[0].Slug != "shop" || projects[0].Name != "Shop" {
		t.Fatalf("projects = %+v %v", projects, err)
	}
	root, err := c.ListSecrets(ctx, "shop", "prod", "")
	if err != nil || len(root.Folders) != 1 || root.Folders[0] != "api" {
		t.Fatalf("root listing = %+v %v", root, err)
	}
	folder, err := c.ListSecrets(ctx, "shop", "prod", "api/db")
	if err != nil || len(folder.Items) != 1 || folder.Items[0].Key != "PASSWORD" || folder.Items[0].UpdatedAt.IsZero() {
		t.Fatalf("folder listing = %+v %v", folder, err)
	}

	v, err := c.GetSecret(ctx, ref, nil)
	if err != nil || v.Value != "v2" {
		t.Fatalf("get = %+v %v", v, err)
	}
	versions, err := c.ListSecretVersions(ctx, ref)
	if err != nil || len(versions) != 2 {
		t.Fatalf("versions = %+v %v", versions, err)
	}
	var first citadel.SecretVersion
	for _, ver := range versions {
		if ver.Version == 1 {
			first = ver
		}
	}
	old, err := c.GetSecret(ctx, ref, &citadel.GetSecretOptions{VersionID: first.VersionID})
	if err != nil || old.Value != "v1" {
		t.Fatalf("get v1 = %+v %v", old, err)
	}

	if err := c.DeleteSecret(ctx, ref, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.RestoreSecret(ctx, ref); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteSecret(ctx, ref, &citadel.DeleteSecretOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
	_, err = c.GetSecret(ctx, ref, nil)
	if !citadel.IsNotFound(err) || citadel.ErrorCode(err) != citadel.CodeNotFound {
		t.Fatalf("get after force delete: %v", err)
	}
}

func TestTypedErrors(t *testing.T) {
	ctx := context.Background()
	env := servertest.New(t)

	// Viewers may not write.
	_, err := newClient(t, env, env.Viewer).PutSecret(ctx, citadel.PutSecretInput{Project: "p", Env: "e", Key: "K", Value: "v"})
	var apiErr *citadel.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusForbidden || apiErr.Code != citadel.CodeForbidden || !citadel.IsForbidden(err) {
		t.Fatalf("viewer put: %v", err)
	}
	// A wrong secret is unauthorized.
	bad := newClient(t, env, servertest.Key{ID: env.Editor.ID, Secret: "wrong"})
	if _, err := bad.ListProjects(ctx); !citadel.IsUnauthorized(err) {
		t.Fatalf("bad key: %v", err)
	}
	// Invalid input is a 400 with the API's code.
	_, err = newClient(t, env, env.Editor).PutSecret(ctx, citadel.PutSecretInput{Project: "bad/slug", Env: "e", Key: "K", Value: "v"})
	if citadel.ErrorCode(err) != citadel.CodeInvalidRequest {
		t.Fatalf("invalid put: %v", err)
	}
}

func TestParameters(t *testing.T) {
	ctx := context.Background()
	env := servertest.New(t)
	c := newClient(t, env, env.Editor)
	if _, err := c.PutParameter(ctx, citadel.PutParameterInput{Name: "/app/url", Value: "https://a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PutParameter(ctx, citadel.PutParameterInput{Name: "/app/url", Value: "https://b"}); citadel.ErrorCode(err) != citadel.CodeAlreadyExists {
		t.Fatalf("put without overwrite: %v", err)
	}
	if _, err := c.PutParameter(ctx, citadel.PutParameterInput{Name: "/app/url", Value: "https://b", Overwrite: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PutParameter(ctx, citadel.PutParameterInput{Name: "/app/token", Type: citadel.ParameterSecureString, Value: "s3cret"}); err != nil {
		t.Fatal(err)
	}
	list, err := c.ListParameters(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %+v %v", list, err)
	}
	for _, p := range list {
		if p.Type == citadel.ParameterSecureString && p.Value != "" {
			t.Fatal("listing exposed a SecureString value")
		}
	}
	p, err := c.GetParameter(ctx, "/app/token", 0)
	if err != nil || p.Value != "s3cret" {
		t.Fatalf("get secure = %+v %v", p, err)
	}
	p, err = c.GetParameter(ctx, "/app/url", 1)
	if err != nil || p.Value != "https://a" || p.Version != 1 {
		t.Fatalf("get v1 = %+v %v", p, err)
	}
	hist, err := c.ParameterHistory(ctx, "/app/url")
	if err != nil || len(hist) != 2 {
		t.Fatalf("history = %+v %v", hist, err)
	}
	if err := c.DeleteParameter(ctx, "/app/url"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetParameter(ctx, "/app/url", 0); !citadel.IsNotFound(err) {
		t.Fatalf("get deleted: %v", err)
	}
}

func TestKMS(t *testing.T) {
	ctx := context.Background()
	env := servertest.New(t)
	c := newClient(t, env, env.Editor)
	keys, err := c.ListKeys(ctx)
	if err != nil || len(keys) == 0 {
		t.Fatalf("keys = %+v %v", keys, err)
	}
	keyID := keys[0].KeyID
	encCtx := map[string]string{"purpose": "test"}
	out, err := c.Encrypt(ctx, keyID, []byte("hello"), encCtx)
	if err != nil || len(out.CiphertextBlob) == 0 {
		t.Fatalf("encrypt = %+v %v", out, err)
	}
	pt, err := c.Decrypt(ctx, keyID, out.CiphertextBlob, encCtx)
	if err != nil || string(pt) != "hello" {
		t.Fatalf("decrypt = %q %v", pt, err)
	}
	if _, err := c.Decrypt(ctx, keyID, out.CiphertextBlob, map[string]string{"purpose": "other"}); err == nil {
		t.Fatal("decrypt with the wrong context succeeded")
	}
}

func TestCertificates(t *testing.T) {
	ctx := context.Background()
	env := servertest.New(t)
	var ca struct {
		CAID string `json:"caId"`
	}
	rawPost(t, env, env.Admin, "/v1/certificates/authorities", map[string]any{"caType": "ROOT", "keyAlgorithm": "EC_prime256v1", "commonName": "Test Root"}, &ca)

	c := newClient(t, env, env.Editor)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "svc.example.com"}, DNSNames: []string{"svc.example.com"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	cert, err := c.IssueCertificate(ctx, citadel.IssueCertificateInput{CA: ca.CAID, CSRPEM: csr, ValidityDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cert.PEM, "BEGIN CERTIFICATE") || cert.ChainPEM == "" {
		t.Fatalf("issued = %+v", cert)
	}
	gen, err := c.IssueGeneratedCertificate(ctx, citadel.IssueGeneratedCertificateInput{CAID: ca.CAID, CommonName: "gen.example.com", KeyAlgorithm: citadel.KeyECP256})
	if err != nil || !strings.Contains(gen.PrivateKeyPEM, "PRIVATE KEY") {
		t.Fatalf("generated = %+v %v", gen, err)
	}
	list, err := c.ListCertificates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var cas, certs int
	for _, row := range list {
		switch row.Source {
		case citadel.SourceCA:
			cas++
		case citadel.SourceCertificate:
			certs++
		}
	}
	if cas != 1 || certs != 2 {
		t.Fatalf("list = %+v", list)
	}
}

func TestWorkloadIdentityToken(t *testing.T) {
	ctx := context.Background()
	env := servertest.New(t)
	var created struct {
		ClientID string `json:"clientId"`
	}
	rawPost(t, env, env.Admin, "/v1/workload-identity/clients", map[string]any{
		"name": "ci", "audiences": []string{"sts.example.com"}, "tokenTtlSeconds": 600, "subjectFormat": "{name}:{username}",
		"auth": map[string]any{"method": "access-key", "allowedUsers": []string{"editor"}},
	}, &created)

	tok, err := newClient(t, env, env.Editor).IssueWorkloadToken(ctx, citadel.WorkloadTokenInput{ClientID: created.ClientID, Audience: "sts.example.com", TTL: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(tok.Token, ".") != 2 || tok.TokenType != "id_token" || time.Until(tok.ExpiresAt) > 6*time.Minute {
		t.Fatalf("token = %+v", tok)
	}
	// The viewer is not an allowed user of the client.
	if _, err := newClient(t, env, env.Viewer).IssueWorkloadToken(ctx, citadel.WorkloadTokenInput{ClientID: created.ClientID, Audience: "sts.example.com"}); err == nil {
		t.Fatal("viewer got a token")
	}
}

func TestNewConfig(t *testing.T) {
	t.Setenv(citadel.EnvURL, "")
	t.Setenv(citadel.EnvAccessKeyID, "")
	t.Setenv(citadel.EnvSecretAccessKey, "")
	if _, err := citadel.New(citadel.Config{}); !errors.Is(err, citadel.ErrNoCredentials) {
		t.Fatalf("no credentials: %v", err)
	}
	if _, err := citadel.New(citadel.Config{BaseURL: "ftp://x", AccessKeyID: "a", SecretAccessKey: "b"}); err == nil {
		t.Fatal("accepted a non-HTTP base URL")
	}
	t.Setenv(citadel.EnvURL, "https://citadel.example.com/")
	t.Setenv(citadel.EnvAccessKeyID, "AKIAEXAMPLE")
	t.Setenv(citadel.EnvSecretAccessKey, "secret")
	c, err := citadel.New(citadel.Config{})
	if err != nil || c.BaseURL() != "https://citadel.example.com" {
		t.Fatalf("from env: %v %v", c, err)
	}
}
