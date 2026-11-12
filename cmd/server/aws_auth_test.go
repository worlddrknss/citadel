package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/config"
	"github.com/worlddrknss/citadel/internal/sigv4"
	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/memory"
)

// sigV4Sign signs req with SigV4 the way an AWS SDK does for JSON-protocol
// services: host, x-amz-date and x-amz-target are signed, service "kms".
func sigV4Sign(t *testing.T, req *http.Request, body []byte, accessKey, secret string, at time.Time) {
	t.Helper()
	amzDate := at.UTC().Format("20060102T150405Z")
	date := amzDate[:8]
	req.Header.Set("X-Amz-Date", amzDate)
	sum := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(sum[:])

	signed := []string{"host", "x-amz-date", "x-amz-target"}
	var ch strings.Builder
	for _, h := range signed {
		v := req.Header.Get(h)
		if h == "host" {
			v = req.Host
		}
		ch.WriteString(h + ":" + strings.TrimSpace(v) + "\n")
	}
	canonical := strings.Join([]string{req.Method, "/", "", ch.String(), strings.Join(signed, ";"), bodyHash}, "\n")
	hc := sha256.Sum256([]byte(canonical))
	scope := date + "/us-east-1/kms/aws4_request"
	sts := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, scope, hex.EncodeToString(hc[:])}, "\n")
	sig := hex.EncodeToString(sigv4.HMACSHA256(sigv4.DeriveSigningKey(secret, date, "us-east-1", "kms"), []byte(sts)))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+accessKey+"/"+scope+
		", SignedHeaders="+strings.Join(signed, ";")+", Signature="+sig)
}

func postSigned(t *testing.T, h http.Handler, target string, body map[string]any, accessKey, secret string, at time.Time) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(b))
	req.Header.Set("X-Amz-Target", target)
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	sigV4Sign(t, req, b, accessKey, secret, at)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func staticKeyServer() (*server, *http.ServeMux) {
	s := &server{cfg: config.Config{ExpectedAccessKey: "AKIASTATIC", SecretAccessKey: "static-secret"}, store: &memory.Store{DefaultKey: sampleKey(1)}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleKMS)
	return s, mux
}

func TestAWSAuthStaticKey(t *testing.T) {
	_, mux := staticKeyServer()
	now := time.Now().UTC()

	if rec := postSigned(t, mux, "TrentService.ListKeys", map[string]any{}, "AKIASTATIC", "static-secret", now); rec.Code != http.StatusOK {
		t.Fatalf("valid signature: status %d body %s", rec.Code, rec.Body.String())
	}
	if rec := postSigned(t, mux, "TrentService.ListKeys", map[string]any{}, "AKIASTATIC", "wrong-secret", now); rec.Code != http.StatusForbidden {
		t.Fatalf("wrong secret: status %d, want 403", rec.Code)
	}
	if rec := postSigned(t, mux, "TrentService.ListKeys", map[string]any{}, "AKIASTATIC", "static-secret", now.Add(-20*time.Minute)); rec.Code != http.StatusForbidden {
		t.Fatalf("stale X-Amz-Date: status %d, want 403", rec.Code)
	}
	if rec := post(t, mux, "TrentService.ListKeys", map[string]any{}); rec.Code != http.StatusForbidden {
		t.Fatalf("unsigned: status %d, want 403", rec.Code)
	}
}

func TestAWSAuthRejectsTamperedBody(t *testing.T) {
	_, mux := staticKeyServer()
	b, _ := json.Marshal(map[string]any{})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{"Limit":1}`)))
	req.Header.Set("X-Amz-Target", "TrentService.ListKeys")
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	sigV4Sign(t, req, b, "AKIASTATIC", "static-secret", time.Now())
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("tampered body: status %d, want 403", rec.Code)
	}
}

func TestAWSAuthCallerReachesPolicyPrincipal(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r = r.WithContext(withAWSCaller(context.Background(), awsCaller{Username: "ci", AccountID: "123456789012"}))
	if got, want := requestPrincipal(r), "arn:aws:iam::123456789012:user/ci"; got != want {
		t.Fatalf("principal %q, want %q", got, want)
	}
	// A header alone must not set the principal account.
	r2 := httptest.NewRequest(http.MethodPost, "/", nil)
	r2.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAX/20260101/us-east-1/kms/aws4_request")
	if _, ok := store.CallerAccountFromContext(r2.Context()); ok {
		t.Fatal("unverified header produced a caller account")
	}
}

func TestNativeSessionRequiresUsersOutsideDevMode(t *testing.T) {
	s := &server{cfg: config.Config{}, store: &memory.Store{DefaultKey: sampleKey(1)}}
	rec := httptest.NewRecorder()
	if _, _, ok := s.nativeSession(rec, httptest.NewRequest(http.MethodGet, "/v1/me", nil), "viewer"); ok {
		t.Fatal("got a session with no users configured and insecure dev off")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}

	dev := &server{cfg: config.Config{InsecureDev: true}, store: &memory.Store{DefaultKey: sampleKey(1)}}
	if _, _, ok := dev.nativeSession(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/me", nil), "admin"); !ok {
		t.Fatal("insecure dev mode should get the local admin session")
	}
}

func TestNativeTokenRejectsTemporaryCredentials(t *testing.T) {
	s := &server{cfg: config.Config{}, store: &memory.Store{DefaultKey: sampleKey(1)}}
	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.Header.Set("Authorization", "Bearer ASIAEXAMPLEEXAMPLE12:secret")
	rec := httptest.NewRecorder()
	if _, _, ok := s.nativeSession(rec, req, "viewer"); ok {
		t.Fatal("STS temporary credentials were accepted as a /v1 bearer token")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
}
