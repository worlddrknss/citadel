package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRouteClassIsBounded(t *testing.T) {
	cases := []struct {
		method, path, target string
		status               int
		want                 string
	}{
		{"GET", "/v1/secrets", "", 200, "/v1/secrets"},
		{"GET", "/v1/auth/oidc/okta-2/callback", "", 302, "/v1/auth/oidc/{id}/callback"},
		{"GET", "/v1/does/not/exist", "", 404, "unmatched"},
		{"GET", "/random-scanner-path", "", 302, "unmatched"},
		{"POST", "/", "TrentService.Encrypt", 200, "aws"},
		{"GET", "/acme/order/ord-123", "", 200, "/acme"},
		{"GET", "/app/secrets/payments", "", 200, "/app"},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, c.path, nil)
		if c.target != "" {
			r.Header.Set("X-Amz-Target", c.target)
		}
		if got := routeClass(r, c.status); got != c.want {
			t.Errorf("%s %s: got %q, want %q", c.method, c.path, got, c.want)
		}
	}
}

func TestAWSTargetLabels(t *testing.T) {
	if svc, act, _ := awsTargetLabels("TrentService.Encrypt", 200); svc != "kms" || act != "Encrypt" {
		t.Fatalf("got %s/%s", svc, act)
	}
	if _, act, _ := awsTargetLabels("TrentService.MadeUpAction123", 400); act != "invalid" {
		t.Fatalf("4xx action leaked into labels: %s", act)
	}
	if svc, _, _ := awsTargetLabels("Evil.Thing", 200); svc != "unknown" {
		t.Fatalf("unknown service label: %s", svc)
	}
}

func TestReadyzAndRequestID(t *testing.T) {
	s := &Server{store: nil}
	h := s.withObservability(http.HandlerFunc(s.handleReady))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("ready: %d", rec.Code)
	}
	if id := rec.Header().Get("X-Request-Id"); len(id) < 8 {
		t.Fatalf("no request id: %q", id)
	}

	req := httptest.NewRequest("GET", "/readyz", nil)
	req.Header.Set("X-Request-Id", "bad id with spaces\n")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if strings.Contains(rec.Header().Get("X-Request-Id"), " ") {
		t.Fatal("unsafe inbound request id was echoed")
	}

	s.BeginShutdown()
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("draining: %d", rec.Code)
	}

	mrec := httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(mrec, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(mrec.Body.String(), `citadel_http_requests_total{route="/readyz",method="GET",code="503"} 1`) {
		t.Fatalf("metrics missing readyz series:\n%s", mrec.Body.String())
	}
}
