package sigv4

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// TestSignRequestMatchesSDK signs the same request with SignRequest and with
// the AWS SDK's signer and requires identical Authorization headers.
func TestSignRequestMatchesSDK(t *testing.T) {
	now := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	creds := SigningCredentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}
	for _, tc := range []struct {
		name, service, target, token string
	}{
		{"root", "service", "/", ""},
		{"query", "kms", "/?Param2=value2&Param1=value%201", ""},
		{"path with space, non-s3 double encodes", "execute-api", "/a%20b/c", ""},
		{"s3 single encodes", "s3", "/bucket/a%20b", ""},
		{"session token", "sts", "/", "FwoGZXIvYXdzEXAMPLETOKEN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mk := func() *http.Request {
				r, err := http.NewRequest(http.MethodGet, "https://example.amazonaws.com"+tc.target, nil)
				if err != nil {
					t.Fatal(err)
				}
				r.Header.Set("Content-Type", "application/x-amz-json-1.1")
				r.Header.Set("X-Amz-Target", "Service.Op")
				return r
			}
			hash := HashPayload(nil)
			c := creds
			c.SessionToken = tc.token
			ours := mk()
			if err := SignRequest(ours, hash, c, "us-east-1", tc.service, now); err != nil {
				t.Fatal(err)
			}
			sdk := mk()
			sdk.Header.Set("X-Amz-Content-Sha256", hash)
			opts := func(o *v4.SignerOptions) { o.DisableURIPathEscaping = tc.service == "s3" }
			sdkCreds := aws.Credentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken}
			if err := v4.NewSigner(opts).SignHTTP(context.Background(), sdkCreds, sdk, hash, tc.service, "us-east-1", now); err != nil {
				t.Fatal(err)
			}
			if got, want := ours.Header.Get("Authorization"), sdk.Header.Get("Authorization"); got != want {
				t.Fatalf("Authorization mismatch\n ours: %s\n  sdk: %s", got, want)
			}
			if tc.token != "" && ours.Header.Get("X-Amz-Security-Token") != tc.token {
				t.Fatal("security token header not set")
			}
		})
	}
}

// TestSignRequestVerifies signs with SignRequest and verifies with
// VerifySignature (the server side) over a real HTTP round trip.
func TestSignRequestVerifies(t *testing.T) {
	const secret = "citadel-test-secret-key-0123456789"
	body := []byte("Action=GetCallerIdentity&Version=2011-06-15")
	var gotErr error
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hash, err := DrainAndHashBody(r, 1<<20)
		if err == nil {
			err = VerifySignature(r, hash, secret)
		}
		gotErr = err
	}))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/?x=a%20b", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	creds := SigningCredentials{AccessKeyID: "AKIDTEST", SecretAccessKey: secret, SessionToken: "tok"}
	if err := SignRequest(req, HashPayload(body), creds, "us-east-1", "sts", time.Now()); err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotErr != nil {
		t.Fatalf("server rejected signature: %v", gotErr)
	}
	if !strings.Contains(req.Header.Get("Authorization"), "x-amz-security-token") {
		t.Fatal("session token not signed")
	}
}

func TestSignRequestValidation(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	now := time.Now()
	ok := SigningCredentials{AccessKeyID: "a", SecretAccessKey: "secret-key-0123456789"}
	if err := SignRequest(req, HashPayload(nil), SigningCredentials{}, "us-east-1", "sts", now); err == nil {
		t.Fatal("missing credentials accepted")
	}
	if err := SignRequest(req, HashPayload(nil), ok, "", "sts", now); err == nil {
		t.Fatal("missing region accepted")
	}
	// Too short for a FIPS-approved HMAC key: an error, never a panic.
	if err := SignRequest(req, HashPayload(nil), SigningCredentials{AccessKeyID: "a", SecretAccessKey: "short"}, "us-east-1", "sts", now); err == nil {
		t.Fatal("short secret accepted")
	}
	if err := SignRequest(req, "", ok, "us-east-1", "sts", now); err == nil {
		t.Fatal("missing payload hash accepted")
	}
}
