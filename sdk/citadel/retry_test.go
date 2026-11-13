package citadel

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Retry behaviour needs failures the real server won't produce on demand,
// so these tests use a scripted server.

func scripted(t *testing.T, statuses ...int) (*Client, *atomic.Int32, *[]time.Duration) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(calls.Add(1)) - 1
		if r.Header.Get("Authorization") != "Bearer AKIA:secret" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		status := http.StatusOK
		if n < len(statuses) {
			status = statuses[n]
		}
		w.Header().Set("Content-Type", "application/json")
		if status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "2")
		}
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = w.Write([]byte(`{"projects":[{"slug":"p","environments":[]}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"error":"some_code","message":"nope"}`))
	}))
	t.Cleanup(srv.Close)
	c, err := New(Config{BaseURL: srv.URL, AccessKeyID: "AKIA", SecretAccessKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	var waits []time.Duration
	c.sleep = func(ctx context.Context, d time.Duration) error {
		waits = append(waits, d)
		return ctx.Err()
	}
	return c, &calls, &waits
}

func TestRetriesTransientFailures(t *testing.T) {
	c, calls, waits := scripted(t, http.StatusServiceUnavailable, http.StatusTooManyRequests)
	projects, err := c.ListProjects(context.Background())
	if err != nil || len(projects) != 1 {
		t.Fatalf("projects = %v, err %v", projects, err)
	}
	if calls.Load() != 3 {
		t.Fatalf("calls = %d, want 3", calls.Load())
	}
	if len(*waits) != 2 || (*waits)[1] != 2*time.Second {
		t.Fatalf("waits = %v; the second should honour Retry-After", *waits)
	}
	if (*waits)[0] <= 0 || (*waits)[0] > 200*time.Millisecond {
		t.Fatalf("first backoff %v outside (0, 200ms]", (*waits)[0])
	}
}

func TestRetriesGiveUp(t *testing.T) {
	c, calls, _ := scripted(t, 503, 503, 503, 503, 503)
	_, err := c.ListProjects(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 503 || apiErr.Code != "some_code" {
		t.Fatalf("err = %v", err)
	}
	if calls.Load() != 4 {
		t.Fatalf("calls = %d, want 1 + 3 retries", calls.Load())
	}
}

func TestNoRetryOnClientErrorsOrWrite500(t *testing.T) {
	c, calls, _ := scripted(t, http.StatusBadRequest)
	if _, err := c.ListProjects(context.Background()); ErrorCode(err) != "some_code" {
		t.Fatalf("err = %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("400 was retried: %d calls", calls.Load())
	}
	c, calls, _ = scripted(t, http.StatusInternalServerError)
	if err := c.CreateProject(context.Background(), "p", ""); statusOf(err) != 500 {
		t.Fatalf("err = %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("a write that failed with 500 was retried: %d calls", calls.Load())
	}
}

func TestRetriesDisabled(t *testing.T) {
	c, calls, _ := scripted(t, 503)
	c.maxRetries = 0
	if _, err := c.ListProjects(context.Background()); statusOf(err) != 503 {
		t.Fatalf("err = %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestContextCancelStopsRetries(t *testing.T) {
	c, _, _ := scripted(t, 503, 503, 503, 503)
	ctx, cancel := context.WithCancel(context.Background())
	c.sleep = func(context.Context, time.Duration) error { cancel(); return context.Canceled }
	if _, err := c.ListProjects(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestPerAttemptTimeout(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(block)
	c, err := New(Config{BaseURL: srv.URL, AccessKeyID: "a", SecretAccessKey: "b", Timeout: 50 * time.Millisecond, MaxRetries: -1})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := c.ListProjects(context.Background()); err == nil {
		t.Fatal("expected a timeout")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("timeout not applied")
	}
}

func TestNonJSONErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}))
	defer srv.Close()
	c, _ := New(Config{BaseURL: srv.URL, AccessKeyID: "a", SecretAccessKey: "b", MaxRetries: -1})
	_, err := c.ListProjects(context.Background())
	if ErrorCode(err) != "http_502" {
		t.Fatalf("err = %v", err)
	}
}
