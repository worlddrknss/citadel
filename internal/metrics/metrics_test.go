package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExposition(t *testing.T) {
	r := NewRegistry()
	c := r.NewCounterVec("citadel_requests_total", "Requests.", "route", "code")
	c.Inc("/v1/secrets", "200")
	c.Inc("/v1/secrets", "200")
	c.Inc(`we"ird`, "500")
	h := r.NewHistogramVec("citadel_latency_seconds", "Latency.", []float64{0.1, 1}, "route")
	h.Observe(0.05, "/v1/secrets")
	h.Observe(0.5, "/v1/secrets")
	h.Observe(5, "/v1/secrets")

	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		`citadel_requests_total{route="/v1/secrets",code="200"} 2`,
		`citadel_requests_total{route="we\"ird",code="500"} 1`,
		`citadel_latency_seconds_bucket{route="/v1/secrets",le="0.1"} 1`,
		`citadel_latency_seconds_bucket{route="/v1/secrets",le="1"} 2`,
		`citadel_latency_seconds_bucket{route="/v1/secrets",le="+Inf"} 3`,
		`citadel_latency_seconds_count{route="/v1/secrets"} 3`,
		"# TYPE citadel_latency_seconds histogram",
		"go_goroutines ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}
