package server

import (
	"context"
	"crypto/fips140"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/worlddrknss/citadel/internal/metrics"
)

// Observability: request IDs, structured access logs, Prometheus metrics and
// the readiness endpoint. Metrics are served on their own listener
// (KMS_METRICS_ADDR, see cmd/server), never on the public port.

type observabilityRuntime struct {
	once     sync.Once
	reg      *metrics.Registry
	httpReqs *metrics.CounterVec
	httpDur  *metrics.HistogramVec
	awsReqs  *metrics.CounterVec
	info     *metrics.GaugeVec
	draining atomic.Bool
}

func (s *Server) obsRuntime() *observabilityRuntime {
	o := &s.obs
	o.once.Do(func() {
		o.reg = metrics.NewRegistry()
		o.httpReqs = o.reg.NewCounterVec("citadel_http_requests_total", "HTTP requests by route class, method and status code.", "route", "method", "code")
		o.httpDur = o.reg.NewHistogramVec("citadel_http_request_duration_seconds", "HTTP request latency by route class.", metrics.DefaultBuckets, "route")
		o.awsReqs = o.reg.NewCounterVec("citadel_aws_requests_total", "AWS-protocol requests by service, action and status code.", "service", "action", "code")
		o.info = o.reg.NewGaugeVec("citadel_build_info", "Always 1; labels describe the running build.", "app", "fips")
		o.info.Set(1, AppName, strconv.FormatBool(fips140.Enabled()))
	})
	return o
}

// MetricsHandler serves Prometheus metrics. Mount it on a private listener.
func (s *Server) MetricsHandler() http.Handler { return s.obsRuntime().reg.Handler() }

// BeginShutdown makes /readyz report not ready, so load balancers stop
// sending new traffic before the listener closes.
func (s *Server) BeginShutdown() { s.obsRuntime().draining.Store(true) }

// handleReady reports whether this replica should receive traffic: not while
// draining, and only when the store answers.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if s.obsRuntime().draining.Load() {
		http.Error(w, "draining", http.StatusServiceUnavailable)
		return
	}
	if p, ok := s.store.(interface{ Ping(context.Context) error }); ok {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := p.Ping(ctx); err != nil {
			slog.Warn("readiness check failed", "error", err)
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok"))
}

type requestIDCtxKey struct{}

// requestIDFromContext returns the request ID set by withObservability.
func requestIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(requestIDCtxKey{}).(string)
	return v
}

var safeRequestID = regexp.MustCompile(`^[A-Za-z0-9._-]{8,64}$`)

// statusRecorder captures the status code and size for logs and metrics.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// withObservability assigns a request ID (reusing a well-formed inbound
// X-Request-Id), then records one structured log line and metrics per request.
// The query string is never logged: it can carry secret paths.
func (s *Server) withObservability(next http.Handler) http.Handler {
	o := s.obsRuntime()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := r.Header.Get("X-Request-Id")
		if !safeRequestID.MatchString(id) {
			id = newRequestID()
		}
		w.Header().Set("X-Request-Id", id)
		r = r.WithContext(context.WithValue(r.Context(), requestIDCtxKey{}, id))
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		elapsed := time.Since(start)
		code := strconv.Itoa(rec.status)
		route := routeClass(r, rec.status)
		o.httpReqs.Inc(route, r.Method, code)
		o.httpDur.Observe(elapsed.Seconds(), route)
		target := r.Header.Get("X-Amz-Target")
		if svc, action, ok := awsTargetLabels(target, rec.status); ok {
			o.awsReqs.Inc(svc, action, code)
		}
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			return
		}
		attrs := []any{
			"request_id", id,
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"bytes", rec.bytes,
			"duration_ms", float64(elapsed.Microseconds()) / 1000,
			"remote_ip", s.clientIP(r),
		}
		if target != "" {
			attrs = append(attrs, "target", target)
		}
		level := slog.LevelInfo
		if rec.status >= 500 {
			level = slog.LevelError
		}
		slog.Log(r.Context(), level, "request", attrs...)
	})
}

func newRequestID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// routeClass maps a request to a bounded label: unmatched paths collapse to
// one value and path segments that look like identifiers become {id}, so
// clients can't create unbounded metric series.
func routeClass(r *http.Request, status int) string {
	p := r.URL.Path
	switch {
	case p == "/" || p == "/api":
		if r.Header.Get("X-Amz-Target") != "" || r.Method == http.MethodPost {
			return "aws"
		}
		return "/"
	case strings.HasPrefix(p, "/app"):
		return "/app"
	case strings.HasPrefix(p, "/acme/"):
		return "/acme"
	case strings.HasPrefix(p, "/oidc"):
		return "/oidc"
	case strings.HasPrefix(p, "/crl/"):
		return "/crl"
	case strings.HasPrefix(p, "/.well-known/"):
		return "/.well-known"
	case p == "/healthz" || p == "/readyz":
		return p
	}
	if status == http.StatusNotFound || !strings.HasPrefix(p, "/v1/") {
		return "unmatched"
	}
	segs := strings.Split(strings.Trim(p, "/"), "/")
	if len(segs) > 5 {
		segs = segs[:5]
	}
	for i, seg := range segs {
		if i > 0 && looksLikeID(seg) { // segs[0] is the "v1" version prefix
			segs[i] = "{id}"
		}
	}
	return "/" + strings.Join(segs, "/")
}

func looksLikeID(seg string) bool {
	if len(seg) > 32 {
		return true
	}
	for _, c := range seg {
		if (c >= '0' && c <= '9') || c == '.' || c == ':' {
			return true
		}
	}
	return false
}

var awsLabelPart = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

var awsServicePrefixes = map[string]string{
	"TrentService":            "kms",
	"secretsmanager":          "secretsmanager",
	"AmazonSSM":               "ssm",
	"CertificateManager":      "acm",
	"ACMPrivateCA":            "acm-pca",
	"acm":                     "acm",
	"acm-pca":                 "acm-pca",
	"AWSSecurityTokenService": "sts",
}

// awsTargetLabels returns bounded service/action labels for an X-Amz-Target.
// Actions from failed requests (4xx) are reported as "invalid", so arbitrary
// action names from clients can't create series.
func awsTargetLabels(target string, status int) (string, string, bool) {
	if target == "" {
		return "", "", false
	}
	prefix, action, ok := strings.Cut(target, ".")
	if !ok {
		return "unknown", "invalid", true
	}
	svc, known := awsServicePrefixes[prefix]
	if !known {
		return "unknown", "invalid", true
	}
	if status >= 400 && status < 500 || !awsLabelPart.MatchString(action) {
		action = "invalid"
	}
	return svc, action, true
}
