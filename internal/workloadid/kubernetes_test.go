package workloadid

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/jose"
)

// fakeTokenReview emulates the TokenReview API for a few known tokens.
type fakeTokenReview struct {
	srv *httptest.Server

	mu         sync.Mutex
	lastBearer string
	lastSpec   tokenReviewSpec
}

func newFakeTokenReview(t *testing.T) *fakeTokenReview {
	f := &fakeTokenReview{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/apis/authentication.k8s.io/v1/tokenreviews" {
			http.NotFound(w, r)
			return
		}
		var tr tokenReview
		if err := json.NewDecoder(r.Body).Decode(&tr); err != nil || tr.Kind != "TokenReview" {
			http.Error(w, "bad", 400)
			return
		}
		f.mu.Lock()
		f.lastBearer = r.Header.Get("Authorization")
		f.lastSpec = tr.Spec
		f.mu.Unlock()
		if f.lastBearer != "Bearer reviewer-token" {
			w.WriteHeader(401)
			return
		}
		st := &tr.Status
		// Token audiences known to the fake cluster.
		var tokenAud []string
		switch tr.Spec.Token {
		case "sa-prod-deployer":
			st.Authenticated = true
			st.User.Username = "system:serviceaccount:prod:deployer"
			st.User.UID = "uid-1"
			st.User.Extra = map[string][]string{"authentication.kubernetes.io/pod-name": {"deployer-abc"}}
			tokenAud = []string{"citadel"}
		case "sa-dev-deployer":
			st.Authenticated = true
			st.User.Username = "system:serviceaccount:dev:deployer"
			tokenAud = []string{"citadel"}
		case "sa-prod-other":
			st.Authenticated = true
			st.User.Username = "system:serviceaccount:prod:other"
			tokenAud = []string{"citadel"}
		case "sa-default-aud":
			st.Authenticated = true
			st.User.Username = "system:serviceaccount:prod:deployer"
			tokenAud = []string{"https://kubernetes.default.svc"}
		case "user-token":
			st.Authenticated = true
			st.User.Username = "alice@example.com"
			tokenAud = []string{"citadel"}
		default:
			st.Error = "invalid bearer token"
		}
		// The API server intersects requested and token audiences.
		if st.Authenticated && len(tr.Spec.Audiences) > 0 {
			var inter []string
			for _, a := range tokenAud {
				if contains(tr.Spec.Audiences, a) {
					inter = append(inter, a)
				}
			}
			if len(inter) == 0 {
				st.Authenticated = false
				st.Error = "token audiences do not match"
				st.User.Username = ""
			}
			st.Audiences = inter
		}
		tr.Spec.Token = ""
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(tr)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func k8sClient(apiServer string) Client {
	return Client{
		ID: "k8s-deployer", AccountRef: "acct-1", AllowedAudiences: []string{"sts.amazonaws.com"},
		SubjectTemplate: "system:serviceaccount:{namespace}:{service_account}", AuthMethod: AuthKubernetes,
		Kubernetes: &KubernetesConfig{APIServer: apiServer, Audiences: []string{"citadel"}, Namespaces: []string{"prod"}, ServiceAccounts: []string{"prod/deployer"}},
	}
}

func TestKubernetesAuthenticator(t *testing.T) {
	f := newFakeTokenReview(t)
	var injected bool
	a := &KubernetesAuthenticator{
		AllowInsecureHTTP: true,
		HTTPClient: func(k KubernetesConfig) (*http.Client, error) {
			injected = true
			return f.srv.Client(), nil
		},
		ReviewerToken: func(ctx context.Context, c Client) (string, error) { return "reviewer-token", nil },
	}
	c := k8sClient(f.srv.URL)
	ctx := context.Background()

	w, err := a.Authenticate(ctx, &AuthRequest{Client: c, Credential: "sa-prod-deployer"})
	if err != nil {
		t.Fatal(err)
	}
	if !injected || w.AccountRef != "acct-1" || w.ClientID != "k8s-deployer" || w.Subject != "system:serviceaccount:prod:deployer" ||
		w.Attributes["namespace"] != "prod" || w.Attributes["service_account"] != "deployer" || w.Attributes["pod"] != "deployer-abc" || w.Attributes["service_account_uid"] != "uid-1" {
		t.Fatalf("workload %+v", w)
	}
	if len(f.lastSpec.Audiences) != 1 || f.lastSpec.Audiences[0] != "citadel" {
		t.Fatalf("audiences not sent to TokenReview: %v", f.lastSpec.Audiences)
	}

	for _, tc := range []struct {
		name  string
		token string
		mod   func(*Client)
		want  error
	}{
		{"unauthenticated", "garbage", nil, ErrUnauthenticated},
		{"empty token", "", nil, ErrUnauthenticated},
		{"wrong audience", "sa-default-aud", nil, ErrUnauthenticated},
		{"disallowed namespace", "sa-dev-deployer", nil, ErrForbidden},
		{"disallowed service account", "sa-prod-other", nil, ErrForbidden},
		{"not a service account", "user-token", func(c *Client) { c.Kubernetes.Namespaces = nil; c.Kubernetes.ServiceAccounts = nil }, ErrForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cc := k8sClient(f.srv.URL)
			if tc.mod != nil {
				tc.mod(&cc)
			}
			if _, err := a.Authenticate(ctx, &AuthRequest{Client: cc, Credential: tc.token}); !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}

	// Wildcard namespace and bare service-account name.
	cc := k8sClient(f.srv.URL)
	cc.Kubernetes.Namespaces = []string{"*"}
	cc.Kubernetes.ServiceAccounts = []string{"deployer"}
	if _, err := a.Authenticate(ctx, &AuthRequest{Client: cc, Credential: "sa-dev-deployer"}); err != nil {
		t.Fatal(err)
	}

	// Without a reviewer token the workload's own token is the bearer; the
	// fake cluster rejects it (401), which must surface as unauthenticated.
	a2 := &KubernetesAuthenticator{AllowInsecureHTTP: true, HTTPClient: a.HTTPClient}
	if _, err := a2.Authenticate(ctx, &AuthRequest{Client: c, Credential: "sa-prod-deployer"}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("own-token bearer: %v", err)
	}
	if f.lastBearer != "Bearer sa-prod-deployer" {
		t.Fatalf("bearer %q", f.lastBearer)
	}

	// https is required unless explicitly allowed.
	a3 := &KubernetesAuthenticator{HTTPClient: a.HTTPClient, ReviewerToken: a.ReviewerToken}
	if _, err := a3.Authenticate(ctx, &AuthRequest{Client: c, Credential: "sa-prod-deployer"}); err == nil {
		t.Fatal("http API server accepted")
	}
}

func TestKubernetesEndToEnd(t *testing.T) {
	f := newFakeTokenReview(t)
	k8s := &KubernetesAuthenticator{
		AllowInsecureHTTP: true,
		HTTPClient:        func(KubernetesConfig) (*http.Client, error) { return f.srv.Client(), nil },
		ReviewerToken:     func(context.Context, Client) (string, error) { return "reviewer-token", nil },
	}
	ring, _ := NewKeyRing(ecSigner(t, "k1"))
	store := NewMemoryClientStore(nil)
	if _, err := store.Create(context.Background(), k8sClient(f.srv.URL)); err != nil {
		t.Fatal(err)
	}
	iss, err := New(Config{
		IssuerURL: "https://citadel.example/wi", Signers: ring, Clients: store,
		Authenticator: MethodRouter{AuthKubernetes: k8s},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(iss.Handler())
	defer srv.Close()
	// The handler routes on the issuer path, so call it with that path.
	post := func(token string) (*http.Response, map[string]any) {
		req, _ := http.NewRequest("POST", srv.URL+"/wi/token", strings.NewReader(`{"client_id":"k8s-deployer","audience":"sts.amazonaws.com"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		return resp, out
	}
	resp, out := post("sa-prod-deployer")
	if resp.StatusCode != 200 {
		t.Fatalf("%d %v", resp.StatusCode, out)
	}
	set, _ := iss.JWKS(context.Background())
	j, err := jose.Verify(context.Background(), out["token"].(string), set)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := jose.ParseClaims(j.Payload)
	if sub, _ := c.String("sub"); sub != "system:serviceaccount:prod:deployer" {
		t.Fatalf("sub %q", sub)
	}
	if err := (jose.Validator{Issuer: "https://citadel.example/wi", Audience: "sts.amazonaws.com", Now: func() time.Time { return time.Now() }}).Validate(c); err != nil {
		t.Fatal(err)
	}
	if resp, out := post("sa-dev-deployer"); resp.StatusCode != 403 || out["error"] != "access_denied" {
		t.Fatalf("dev namespace: %d %v", resp.StatusCode, out)
	}
	if resp, out := post("garbage"); resp.StatusCode != 401 || resp.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("garbage: %d %v", resp.StatusCode, out)
	}
}
