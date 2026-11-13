package providertoken

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/sigv4"
)

const (
	testSourceKey    = "AKIASOURCEEXAMPLE"
	testSourceSecret = "source-secret-access-key-0123456789"
	testTempSecret   = "temporary-secret-0123456789"
	testTempToken    = "temporary-session-token-0123456789"
	testRoleARN      = "arn:aws:iam::123456789012:role/agent-deployer"
)

const assumeRoleXML = `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIATEMPEXAMPLE</AccessKeyId>
      <SecretAccessKey>` + testTempSecret + `</SecretAccessKey>
      <SessionToken>` + testTempToken + `</SessionToken>
      <Expiration>2026-11-13T13:00:00Z</Expiration>
    </Credentials>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::123456789012:assumed-role/agent-deployer/build-42</Arn>
      <AssumedRoleId>AROAEXAMPLE:build-42</AssumedRoleId>
    </AssumedRoleUser>
  </AssumeRoleResult>
  <ResponseMetadata><RequestId>req-1</RequestId></ResponseMetadata>
</AssumeRoleResponse>`

// fakeSTS verifies the SigV4 signature with the source secret and records
// the form it received.
type fakeSTS struct {
	mu      sync.Mutex
	form    map[string]string
	token   string
	sigErr  error
	status  int
	reply   string
	delay   time.Duration
	reqPath string
}

func (f *fakeSTS) handler(w http.ResponseWriter, r *http.Request) {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-r.Context().Done():
			return
		}
	}
	hash, err := sigv4.DrainAndHashBody(r, 1<<20)
	if err == nil {
		err = sigv4.VerifySignature(r, hash, testSourceSecret)
	}
	if err == nil && r.Header.Get("X-Amz-Content-Sha256") != hash {
		err = errors.New("payload hash header mismatch")
	}
	_ = r.ParseForm()
	f.mu.Lock()
	f.sigErr = err
	f.token = r.Header.Get("X-Amz-Security-Token")
	f.reqPath = r.URL.Path
	f.form = map[string]string{}
	for k := range r.PostForm {
		f.form[k] = r.PostForm.Get(k)
	}
	f.mu.Unlock()
	status := f.status
	if status == 0 {
		status = http.StatusOK
	}
	reply := f.reply
	if reply == "" {
		reply = assumeRoleXML
	}
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(status)
	io.WriteString(w, reply)
}

func newTestSTS(t *testing.T, f *fakeSTS, mod func(*AWSSTSConfig)) *AWSSTS {
	t.Helper()
	srv, client := newTLS(t, f.handler)
	cfg := AWSSTSConfig{
		Endpoint:   srv.URL + "/",
		Region:     "us-east-1",
		Source:     AWSCredentials{AccessKeyID: testSourceKey, SecretAccessKey: testSourceSecret, SessionToken: "source-session-token"},
		RoleARN:    testRoleARN,
		ExternalID: "ext-id-123",
	}
	if mod != nil {
		mod(&cfg)
	}
	a, err := NewAWSSTS(cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAWSSTSMint(t *testing.T) {
	f := &fakeSTS{}
	a := newTestSTS(t, f, nil)
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
	tok, err := a.Mint(context.Background(), Params{SessionName: "build-42", SessionPolicy: policy, Duration: 30 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if f.sigErr != nil {
		t.Fatalf("fake STS rejected the signature: %v", f.sigErr)
	}
	if f.token != "source-session-token" {
		t.Fatal("source session token not sent")
	}
	want := map[string]string{
		"Action": "AssumeRole", "Version": "2011-06-15", "RoleArn": testRoleARN,
		"RoleSessionName": "build-42", "DurationSeconds": "1800", "ExternalId": "ext-id-123", "Policy": policy,
	}
	for k, v := range want {
		if f.form[k] != v {
			t.Errorf("form %s = %q, want %q", k, f.form[k], v)
		}
	}
	if tok.Kind != KindAWSSTS || !tok.ExpiresAt.Equal(time.Date(2026, 11, 13, 13, 0, 0, 0, time.UTC)) {
		t.Fatalf("token = %v", tok)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(tok.Value), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["Version"] != float64(1) || doc["AccessKeyId"] != "ASIATEMPEXAMPLE" || doc["SecretAccessKey"] != testTempSecret ||
		doc["SessionToken"] != testTempToken || doc["Expiration"] != "2026-11-13T13:00:00Z" {
		t.Fatalf("credential_process document = %v", doc)
	}
	if tok.Metadata["assumedRoleArn"] != "arn:aws:sts::123456789012:assumed-role/agent-deployer/build-42" || tok.Metadata["accessKeyId"] != "ASIATEMPEXAMPLE" {
		t.Fatalf("metadata = %v", tok.Metadata)
	}
	for _, v := range tok.Metadata {
		if strings.Contains(v, testTempSecret) || strings.Contains(v, testTempToken) {
			t.Fatal("metadata holds a secret")
		}
	}
}

func TestAWSSTSDefaults(t *testing.T) {
	f := &fakeSTS{}
	a := newTestSTS(t, f, func(c *AWSSTSConfig) { c.ExternalID = ""; c.Source.SessionToken = "" })
	if _, err := a.Mint(context.Background(), Params{}); err != nil {
		t.Fatal(err)
	}
	if f.sigErr != nil {
		t.Fatal(f.sigErr)
	}
	if f.form["RoleSessionName"] != "citadel-agent" || f.form["DurationSeconds"] != "3600" {
		t.Fatalf("defaults = %v", f.form)
	}
	if _, ok := f.form["ExternalId"]; ok {
		t.Fatal("empty ExternalId sent")
	}
	if _, ok := f.form["Policy"]; ok {
		t.Fatal("empty Policy sent")
	}
	if f.token != "" {
		t.Fatal("security token sent for long-term source keys")
	}
}

func TestAWSSTSErrors(t *testing.T) {
	t.Run("provider error keeps only the code", func(t *testing.T) {
		f := &fakeSTS{status: http.StatusForbidden, reply: `<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>key ` + testSourceSecret + ` denied</Message></Error></ErrorResponse>`}
		a := newTestSTS(t, f, nil)
		_, err := a.Mint(context.Background(), Params{})
		var pe *ProviderError
		if !errors.As(err, &pe) || pe.Status != 403 || pe.Code != "AccessDenied" {
			t.Fatalf("err = %v", err)
		}
		noSecrets(t, err, testSourceSecret, "denied")
	})
	t.Run("malformed code dropped", func(t *testing.T) {
		f := &fakeSTS{status: 400, reply: `<ErrorResponse><Error><Code>` + testSourceSecret + ` with spaces</Code></Error></ErrorResponse>`}
		_, err := newTestSTS(t, f, nil).Mint(context.Background(), Params{})
		noSecrets(t, err, testSourceSecret)
	})
	t.Run("redirect not followed", func(t *testing.T) {
		var followed bool
		target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed = true }))
		defer target.Close()
		srv, client := newTLS(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
		})
		a, err := NewAWSSTS(AWSSTSConfig{Endpoint: srv.URL, Source: AWSCredentials{AccessKeyID: "a", SecretAccessKey: testSourceSecret}, RoleARN: testRoleARN}, client)
		if err != nil {
			t.Fatal(err)
		}
		_, err = a.Mint(context.Background(), Params{})
		var pe *ProviderError
		if !errors.As(err, &pe) || pe.Status != http.StatusTemporaryRedirect || followed {
			t.Fatalf("err = %v, followed = %v", err, followed)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		f := &fakeSTS{delay: 2 * time.Second}
		a := newTestSTS(t, f, func(c *AWSSTSConfig) { c.Timeout = 50 * time.Millisecond })
		_, err := a.Mint(context.Background(), Params{})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want deadline exceeded", err)
		}
	})
	t.Run("missing credentials in response", func(t *testing.T) {
		f := &fakeSTS{reply: `<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>A</AccessKeyId></Credentials></AssumeRoleResult></AssumeRoleResponse>`}
		if _, err := newTestSTS(t, f, nil).Mint(context.Background(), Params{}); err == nil {
			t.Fatal("incomplete response accepted")
		}
	})
	t.Run("bad expiration", func(t *testing.T) {
		f := &fakeSTS{reply: strings.Replace(assumeRoleXML, "2026-11-13T13:00:00Z", "tomorrow", 1)}
		_, err := newTestSTS(t, f, nil).Mint(context.Background(), Params{})
		if err == nil {
			t.Fatal("bad expiration accepted")
		}
		noSecrets(t, err, testTempSecret, testTempToken)
	})
	t.Run("params validation", func(t *testing.T) {
		a := newTestSTS(t, &fakeSTS{}, func(c *AWSSTSConfig) { c.SessionPolicy = `{"Version":"2012-10-17"}`; c.MaxDuration = time.Hour })
		for name, p := range map[string]Params{
			"second policy":      {SessionPolicy: `{"Statement":[]}`},
			"bad session name":   {SessionName: "has space"},
			"duration too long":  {Duration: 2 * time.Hour},
			"duration too short": {Duration: time.Minute},
		} {
			if _, err := a.Mint(context.Background(), p); err == nil {
				t.Errorf("%s accepted", name)
			}
		}
	})
}

func TestNewAWSSTSValidation(t *testing.T) {
	client := &http.Client{}
	base := AWSSTSConfig{Source: AWSCredentials{AccessKeyID: "AKIA", SecretAccessKey: testSourceSecret}, RoleARN: testRoleARN}
	if _, err := NewAWSSTS(base, client); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
	for name, mod := range map[string]func(*AWSSTSConfig){
		"http endpoint":     func(c *AWSSTSConfig) { c.Endpoint = "http://sts.local/" },
		"userinfo":          func(c *AWSSTSConfig) { c.Endpoint = "https://u:p@sts.local/" },
		"bad ARN":           func(c *AWSSTSConfig) { c.RoleARN = "role/agent" },
		"no source":         func(c *AWSSTSConfig) { c.Source = AWSCredentials{} },
		"bad external ID":   func(c *AWSSTSConfig) { c.ExternalID = "x" },
		"bad region":        func(c *AWSSTSConfig) { c.Region = "US EAST" },
		"invalid policy":    func(c *AWSSTSConfig) { c.SessionPolicy = "{" },
		"oversized policy":  func(c *AWSSTSConfig) { c.SessionPolicy = `"` + strings.Repeat("a", 2100) + `"` },
		"duration too long": func(c *AWSSTSConfig) { c.Duration = 13 * time.Hour },
	} {
		cfg := base
		mod(&cfg)
		_, err := NewAWSSTS(cfg, client)
		if err == nil {
			t.Errorf("%s accepted", name)
		}
		noSecrets(t, err, testSourceSecret)
	}
	if _, err := NewAWSSTS(base, nil); err == nil {
		t.Error("nil client accepted")
	}
	cfg := base
	cfg.Endpoint, cfg.AllowInsecureHTTP = "http://localhost:8080/", true
	if _, err := NewAWSSTS(cfg, client); err != nil {
		t.Errorf("http with AllowInsecureHTTP refused: %v", err)
	}
}

func TestSignAWSRequest(t *testing.T) {
	creds := AWSCredentials{AccessKeyID: "ASIATEMP", SecretAccessKey: testTempSecret, SessionToken: testTempToken, Expiration: time.Now().Add(time.Hour)}
	body := `{"KeyId":"alias/app"}`
	var verr error
	var gotBody, gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hash, err := sigv4.DrainAndHashBody(r, 1<<20)
		if err == nil {
			err = sigv4.VerifySignature(r, hash, testTempSecret)
		}
		b, _ := io.ReadAll(r.Body)
		verr, gotBody, gotToken = err, string(b), r.Header.Get("X-Amz-Security-Token")
	}))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "TrentService.DescribeKey")
	req.Header.Set("Authorization", "Bearer agent-supplied")
	if err := SignAWSRequest(req, creds, "us-east-1", "kms", time.Now()); err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if verr != nil || gotBody != body || gotToken != testTempToken {
		t.Fatalf("verify=%v body=%q token ok=%v", verr, gotBody, gotToken == testTempToken)
	}

	expired := creds
	expired.Expiration = time.Now().Add(-time.Minute)
	req2, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	if err := SignAWSRequest(req2, expired, "us-east-1", "kms", time.Now()); err == nil {
		t.Fatal("expired credentials used")
	}
	req3, _ := http.NewRequest(http.MethodPost, srv.URL+"/", strings.NewReader(strings.Repeat("x", maxSignedBody+1)))
	if err := SignAWSRequest(req3, creds, "us-east-1", "kms", time.Now()); err == nil {
		t.Fatal("oversized body signed")
	}
}
