package providertoken

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTLS starts a TLS test server and returns it with a client that trusts
// it, standing in for the server's SSRF-guarded client.
func newTLS(t *testing.T, h http.HandlerFunc) (*httptest.Server, *http.Client) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	return srv, srv.Client()
}

// noSecrets fails if err's message contains any of the secrets.
func noSecrets(t *testing.T, err error, secrets ...string) {
	t.Helper()
	if err == nil {
		return
	}
	msg := err.Error()
	for _, s := range secrets {
		if s != "" && strings.Contains(msg, s) {
			t.Fatalf("error message leaks a secret: %q", msg)
		}
	}
}

func TestTokenRedaction(t *testing.T) {
	const secret = "super-secret-token-value"
	tok := Token{Value: secret, Kind: KindOAuth2Client, ExpiresAt: time.Now()}
	var buf strings.Builder
	slog.New(slog.NewTextHandler(&buf, nil)).Info("minted", "token", tok)
	for _, s := range []string{fmt.Sprint(tok), fmt.Sprintf("%v", tok), fmt.Sprintf("%+v", tok), fmt.Sprintf("%#v", tok), fmt.Sprintf("%s", tok), buf.String()} {
		if strings.Contains(s, secret) {
			t.Fatalf("token value leaked: %s", s)
		}
	}
	c := AWSCredentials{AccessKeyID: "ASIAEXAMPLE", SecretAccessKey: secret, SessionToken: secret}
	for _, s := range []string{fmt.Sprint(c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c)} {
		if strings.Contains(s, secret) {
			t.Fatalf("AWS credentials leaked: %s", s)
		}
	}
}

func TestStatic(t *testing.T) {
	tok, err := Static{Value: "v", Metadata: map[string]string{"a": "b"}}.Mint(context.Background(), Params{})
	if err != nil || tok.Value != "v" || tok.Kind != KindStatic || tok.Metadata["a"] != "b" {
		t.Fatalf("Static.Mint = %+v, %v", tok, err)
	}
	if _, err := (Static{}).Mint(context.Background(), Params{}); err == nil {
		t.Fatal("empty static value accepted")
	}
	var _ Minter = Static{}
	var _ Minter = (*AWSSTS)(nil)
	var _ Minter = (*GitHubApp)(nil)
	var _ Minter = (*OAuth2ClientCredentials)(nil)
	var _ Minter = (*TOTP)(nil)
}

func TestCheckEndpoint(t *testing.T) {
	for _, tc := range []struct {
		raw       string
		allowHTTP bool
		ok        bool
	}{
		{"https://sts.amazonaws.com/", false, true},
		{"https://ghe.example.com/api/v3", false, true},
		{"http://localhost:8080/", false, false},
		{"http://localhost:8080/", true, true},
		{"https://user:pass@example.com/", false, false},
		{"https://example.com/?x=1", false, false},
		{"https://example.com/#f", false, false},
		{"ftp://example.com/", true, false},
		{"/relative", false, false},
	} {
		_, err := checkEndpoint(KindOAuth2Client, tc.raw, tc.allowHTTP)
		if (err == nil) != tc.ok {
			t.Errorf("checkEndpoint(%q, %v) err=%v, want ok=%v", tc.raw, tc.allowHTTP, err, tc.ok)
		}
		if err != nil && strings.Contains(err.Error(), "pass") {
			t.Errorf("endpoint echoed in error: %v", err)
		}
	}
}

func TestNilClientRefused(t *testing.T) {
	if _, err := NewOAuth2ClientCredentials(OAuth2Config{TokenURL: "https://example.com/token", ClientID: "a", ClientSecret: "b"}, nil); err == nil {
		t.Fatal("nil client accepted")
	}
}

func TestTransportErrorHidesURL(t *testing.T) {
	srv, client := newTLS(t, func(w http.ResponseWriter, r *http.Request) {})
	url := srv.URL + "/token"
	srv.Close()
	o, err := NewOAuth2ClientCredentials(OAuth2Config{TokenURL: url, ClientID: "id", ClientSecret: "client-secret-xyz"}, client)
	if err != nil {
		t.Fatal(err)
	}
	_, err = o.Mint(context.Background(), Params{})
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if strings.Contains(err.Error(), srv.Listener.Addr().String()) || strings.Contains(err.Error(), "/token") {
		t.Fatalf("transport error leaks the endpoint: %v", err)
	}
	noSecrets(t, err, "client-secret-xyz")
	var pe *ProviderError
	if errors.As(err, &pe) {
		t.Fatal("transport error reported as a provider error")
	}
}
