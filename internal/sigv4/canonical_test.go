package sigv4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

func TestCanonicalQueryString(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"", ""},
		{"b=2&a=1", "a=1&b=2"},
		{"a=2&a=1", "a=1&a=2"},
		{"q=hello%20world", "q=hello%20world"},
		{"q=hello+world", "q=hello%2Bworld"}, // a literal + is a plus
		{"q=a%2Fb&x=~-_.", "q=a%2Fb&x=~-_."},
		{"flag", "flag="},
		{"k=%2a", "k=%2A"},
		{"k=caf%C3%A9", "k=caf%C3%A9"},
	}
	for _, c := range cases {
		if got := CanonicalQueryString(c.raw); got != c.want {
			t.Errorf("CanonicalQueryString(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}

func TestURIEncode(t *testing.T) {
	if got := URIEncode("a b*c~d/é"); got != "a%20b%2Ac~d%2F%C3%A9" {
		t.Fatalf("URIEncode = %q", got)
	}
}

// TestVerifyRealSDKSignature signs requests with the AWS SDK's own SigV4
// signer and verifies them server-side: query values with spaces and
// symbols, repeated keys, and a body (Content-Length is signed, and Go's
// server moves it out of the header map).
func TestVerifyRealSDKSignature(t *testing.T) {
	const secret = "citadel-test-secret-key-0123456789"
	signer := v4.NewSigner()
	creds := aws.Credentials{AccessKeyID: "AKIDCITADELTEST", SecretAccessKey: secret}

	for _, tc := range []struct {
		name, method, target, body string
	}{
		{"query with spaces and symbols", http.MethodGet, "/?Action=List&Filter=a%20b&Name=x%2By&z=%7E*", ""},
		{"repeated query keys", http.MethodGet, "/?k=2&k=1&a=", ""},
		{"json body", http.MethodPost, "/", `{"KeyId":"alias/app"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotErr error
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hash, err := DrainAndHashBody(r, 1<<20)
				if err == nil {
					err = VerifySignature(r, hash, secret)
				}
				gotErr = err
			}))
			defer srv.Close()

			req, err := http.NewRequest(tc.method, srv.URL+tc.target, bytes.NewReader([]byte(tc.body)))
			if err != nil {
				t.Fatal(err)
			}
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/x-amz-json-1.1")
				req.Header.Set("X-Amz-Target", "TrentService.DescribeKey")
			}
			sum := sha256.Sum256([]byte(tc.body))
			if err := signer.SignHTTP(context.Background(), creds, req, hex.EncodeToString(sum[:]), "kms", "us-east-1", time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if gotErr != nil {
				t.Fatalf("server rejected SDK signature: %v", gotErr)
			}
		})
	}
}
