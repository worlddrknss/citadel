package workloadid

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/worlddrknss/citadel/internal/jose"
)

// KubernetesAuthenticator authenticates service account tokens by calling
// the cluster's TokenReview API (authentication.k8s.io/v1), then enforces
// the client's audience, namespace and service account allow-lists.
//
// The identity calling TokenReview needs the system:auth-delegator cluster
// role. Supply its token with ReviewerToken; when nil, the workload's own
// token is used as the bearer (which then needs that role itself).
type KubernetesAuthenticator struct {
	// HTTPClient returns the client used for a cluster. Tests inject a fake
	// here. Default: a client trusting k.CA (or system roots), TLS 1.2+,
	// refusing redirects.
	HTTPClient func(k KubernetesConfig) (*http.Client, error)
	// ReviewerToken returns the bearer token for TokenReview calls.
	ReviewerToken func(ctx context.Context, c Client) (string, error)
	// AllowInsecureHTTP permits http:// API servers. Tests only.
	AllowInsecureHTTP bool
	// Timeout bounds each TokenReview call (default 10s).
	Timeout time.Duration

	clients sync.Map // APIServer+CA -> *http.Client
}

const (
	maxSATokenBytes  = 16 << 10
	maxReviewBytes   = 256 << 10
	saUsernamePrefix = "system:serviceaccount:"
)

type tokenReview struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Spec       tokenReviewSpec   `json:"spec"`
	Status     tokenReviewStatus `json:"status,omitempty"`
}

type tokenReviewSpec struct {
	Token     string   `json:"token"`
	Audiences []string `json:"audiences,omitempty"`
}

type tokenReviewStatus struct {
	Authenticated bool     `json:"authenticated"`
	Audiences     []string `json:"audiences,omitempty"`
	Error         string   `json:"error,omitempty"`
	User          struct {
		Username string              `json:"username"`
		UID      string              `json:"uid"`
		Groups   []string            `json:"groups"`
		Extra    map[string][]string `json:"extra"`
	} `json:"user"`
}

// Authenticate implements Authenticator.
func (a *KubernetesAuthenticator) Authenticate(ctx context.Context, req *AuthRequest) (Workload, error) {
	c := req.Client
	if c.AuthMethod != AuthKubernetes || c.Kubernetes == nil {
		return Workload{}, fmt.Errorf("%w: client %q is not a kubernetes client", ErrUnauthenticated, c.ID)
	}
	k := *c.Kubernetes
	if len(k.Audiences) == 0 {
		return Workload{}, fmt.Errorf("%w: client %q has no kubernetes audiences configured", ErrForbidden, c.ID)
	}
	token := req.Credential
	if token == "" || len(token) > maxSATokenBytes {
		return Workload{}, fmt.Errorf("%w: missing or oversized service account token", ErrUnauthenticated)
	}
	if err := jose.CheckURL(k.APIServer, a.AllowInsecureHTTP); err != nil {
		return Workload{}, fmt.Errorf("workloadid: API server: %w", err)
	}
	hc, err := a.client(k)
	if err != nil {
		return Workload{}, err
	}
	bearer := token
	if a.ReviewerToken != nil {
		if bearer, err = a.ReviewerToken(ctx, c); err != nil {
			return Workload{}, fmt.Errorf("workloadid: reviewer token: %w", err)
		}
	}
	status, err := a.review(ctx, hc, k, bearer, token)
	if err != nil {
		return Workload{}, err
	}
	if !status.Authenticated {
		return Workload{}, fmt.Errorf("%w: TokenReview: %s", ErrUnauthenticated, sanitize(status.Error))
	}
	if !intersects(status.Audiences, k.Audiences) {
		return Workload{}, fmt.Errorf("%w: token audiences %q do not include %q", ErrUnauthenticated, status.Audiences, k.Audiences)
	}
	user := status.User.Username
	rest, ok := strings.CutPrefix(user, saUsernamePrefix)
	ns, sa, ok2 := strings.Cut(rest, ":")
	if !ok || !ok2 || ns == "" || sa == "" || strings.Contains(sa, ":") {
		return Workload{}, fmt.Errorf("%w: %q is not a service account", ErrForbidden, user)
	}
	if !allowed(k.Namespaces, ns) {
		return Workload{}, fmt.Errorf("%w: namespace %q", ErrForbidden, ns)
	}
	if len(k.ServiceAccounts) > 0 && !contains(k.ServiceAccounts, ns+"/"+sa) && !contains(k.ServiceAccounts, sa) {
		return Workload{}, fmt.Errorf("%w: service account %s/%s", ErrForbidden, ns, sa)
	}
	attrs := map[string]string{
		"namespace":       ns,
		"service_account": sa,
	}
	if status.User.UID != "" {
		attrs["service_account_uid"] = status.User.UID
	}
	for attr, key := range map[string]string{
		"pod":      "authentication.kubernetes.io/pod-name",
		"pod_uid":  "authentication.kubernetes.io/pod-uid",
		"node":     "authentication.kubernetes.io/node-name",
		"node_uid": "authentication.kubernetes.io/node-uid",
	} {
		if v := status.User.Extra[key]; len(v) == 1 && v[0] != "" {
			attrs[attr] = v[0]
		}
	}
	return Workload{AccountRef: c.AccountRef, ClientID: c.ID, Subject: user, Attributes: attrs}, nil
}

func (a *KubernetesAuthenticator) review(ctx context.Context, hc *http.Client, k KubernetesConfig, bearer, token string) (*tokenReviewStatus, error) {
	timeout := a.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	body, _ := json.Marshal(tokenReview{
		APIVersion: "authentication.k8s.io/v1",
		Kind:       "TokenReview",
		Spec:       tokenReviewSpec{Token: token, Audiences: k.Audiences},
	})
	u := strings.TrimSuffix(k.APIServer, "/") + "/apis/authentication.k8s.io/v1/tokenreviews"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("workloadid: TokenReview: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxReviewBytes+1))
	if err != nil || len(data) > maxReviewBytes {
		return nil, errors.New("workloadid: TokenReview response unreadable or too large")
	}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("%w: TokenReview HTTP 401", ErrUnauthenticated)
	default:
		return nil, fmt.Errorf("workloadid: TokenReview HTTP %d", resp.StatusCode)
	}
	var tr tokenReview
	if err := json.Unmarshal(data, &tr); err != nil {
		return nil, fmt.Errorf("workloadid: TokenReview response: %w", err)
	}
	return &tr.Status, nil
}

func (a *KubernetesAuthenticator) client(k KubernetesConfig) (*http.Client, error) {
	if a.HTTPClient != nil {
		return a.HTTPClient(k)
	}
	key := k.APIServer + "\x00" + k.CA
	if c, ok := a.clients.Load(key); ok {
		return c.(*http.Client), nil
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if k.CA != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(k.CA)) {
			return nil, errors.New("workloadid: kubernetes CA bundle contains no certificates")
		}
		tlsCfg.RootCAs = pool
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	tr.Proxy = nil
	c := &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	actual, _ := a.clients.LoadOrStore(key, c)
	return actual.(*http.Client), nil
}

func allowed(list []string, v string) bool {
	return len(list) == 0 || contains(list, "*") || contains(list, v)
}

func intersects(a, b []string) bool {
	for _, x := range a {
		if contains(b, x) {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func sanitize(s string) string {
	if len(s) > 128 {
		s = s[:128]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}
