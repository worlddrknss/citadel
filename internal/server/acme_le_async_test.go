package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// pollLEOrder polls the order until its status is no longer processing.
func pollLEOrder(t *testing.T, e *pkiEnv, user, id string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		rec := e.do(user, "GET", "/v1/certificates/letsencrypt/orders?id="+id, nil)
		wantStatus(t, rec, http.StatusOK)
		body := decode(t, rec)
		if body["status"] != store.ACMELEOrderProcessing {
			return body
		}
		if time.Now().After(deadline) {
			t.Fatalf("order %s still processing: %v", id, body)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestLetsEncryptAsyncHTTP01: the request returns at once with an order ID;
// progress and the result are read by polling, on any replica.
func TestLetsEncryptAsyncHTTP01(t *testing.T) {
	release := make(chan struct{})
	e := newPKIEnvOn(t, pgTestStore(t), func(s *Server) {
		s.testLEIssue = func(ctx context.Context, domains []string, progress func(string)) (store.ACMELECertificate, error) {
			progress("Validating " + domains[0] + " (HTTP-01)")
			select {
			case <-release:
			case <-ctx.Done():
				return store.ACMELECertificate{}, ctx.Err()
			}
			return store.ACMELECertificate{CertID: "le-cert-1"}, nil
		}
	})
	start := time.Now()
	rec := e.do("editor", "POST", "/v1/certificates/letsencrypt/request", map[string]any{"domains": "Status.Example.com"})
	wantStatus(t, rec, http.StatusAccepted)
	if time.Since(start) > 5*time.Second {
		t.Fatal("request waited for issuance")
	}
	body := decode(t, rec)
	id, _ := body["orderId"].(string)
	if id == "" || body["status"] != "processing" || body["domains"] != "status.example.com" {
		t.Fatalf("start = %v", body)
	}
	// While running: processing, with the current step; viewers can poll,
	// other accounts can't see it.
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := decode(t, e.do("viewer", "GET", "/v1/certificates/letsencrypt/orders?id="+id, nil))
		if got["status"] != "processing" {
			t.Fatalf("status before release = %v", got)
		}
		if got["progress"] == "Validating status.example.com (HTTP-01)" && got["kind"] == "http-01" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("progress never reported: %v", got)
		}
		time.Sleep(10 * time.Millisecond)
	}
	wantStatus(t, e.do("other", "GET", "/v1/certificates/letsencrypt/orders?id="+id, nil), http.StatusNotFound)
	close(release)
	done := pollLEOrder(t, e, "editor", id)
	if done["status"] != "issued" || done["certId"] != "le-cert-1" || done["error"] != nil {
		t.Fatalf("done = %v", done)
	}
	if !leAudited(t, e.st, "citadel.RequestLetsEncrypt", "ok", "editor", e.acctA) {
		t.Fatal("issuance not audited with the requester")
	}

	// Validation errors are immediate; wildcards need DNS-01.
	wantStatus(t, e.do("editor", "POST", "/v1/certificates/letsencrypt/request", map[string]any{"domains": " "}), http.StatusBadRequest)
	wantStatus(t, e.do("editor", "POST", "/v1/certificates/letsencrypt/request", map[string]any{"domains": "*.example.com"}), http.StatusBadRequest)
	wantStatus(t, e.do("viewer", "POST", "/v1/certificates/letsencrypt/request", map[string]any{"domains": "a.example.com"}), http.StatusForbidden)
}

func TestLetsEncryptAsyncFailure(t *testing.T) {
	e := newPKIEnvOn(t, pgTestStore(t), func(s *Server) {
		s.testLEIssue = func(ctx context.Context, domains []string, progress func(string)) (store.ACMELECertificate, error) {
			return store.ACMELECertificate{}, errors.New("dial tcp 10.0.0.1:443: secret internal detail")
		}
	})
	rec := e.do("editor", "POST", "/v1/certificates/letsencrypt/request", map[string]any{"domains": "a.example.com"})
	wantStatus(t, rec, http.StatusAccepted)
	done := pollLEOrder(t, e, "editor", decode(t, rec)["orderId"].(string))
	if done["status"] != "failed" || done["error"] != "The Let's Encrypt request failed; see the server log for details." {
		t.Fatalf("failed order = %v", done)
	}
	if !leAudited(t, e.st, "citadel.RequestLetsEncrypt", "error", "editor", e.acctA) {
		t.Fatal("failure not audited")
	}
}

// TestLetsEncryptAsyncDNS01: completing a DNS-01 order starts the work once
// (a second click reports the running order) and can be retried after a
// failure.
func TestLetsEncryptAsyncDNS01(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	e := newPKIEnvOn(t, pgTestStore(t), func(s *Server) {
		s.testLEComplete = func(ctx context.Context, o store.ACMELEOrder, progress func(string)) (store.ACMELECertificate, error) {
			n := calls.Add(1)
			progress("Validating " + o.Domains + " (DNS-01)")
			if n == 1 {
				return store.ACMELECertificate{}, context.DeadlineExceeded
			}
			<-release
			return store.ACMELECertificate{CertID: "le-dns-cert"}, nil
		}
	})
	ctx := store.WithCallerAccount(context.Background(), e.acctA)
	order := store.ACMELEOrder{OrderID: "dnsorder0001", OrderURL: "https://acme.test/order/1", Domains: "example.com,*.example.com", Status: store.ACMELEOrderPending, Kind: store.ACMELEOrderDNS01}
	if err := e.st.CreateACMELEOrder(ctx, order); err != nil {
		t.Fatal(err)
	}
	got := decode(t, e.do("viewer", "GET", "/v1/certificates/letsencrypt/orders?id=dnsorder0001", nil))
	if got["status"] != "pending" || got["kind"] != "dns-01" {
		t.Fatalf("pending order = %v", got)
	}
	wantStatus(t, e.do("other", "POST", "/v1/certificates/letsencrypt/dns/complete", map[string]any{"orderId": "dnsorder0001"}), http.StatusNotFound)

	// First attempt times out.
	wantStatus(t, e.do("editor", "POST", "/v1/certificates/letsencrypt/dns/complete", map[string]any{"orderId": "dnsorder0001"}), http.StatusAccepted)
	failed := pollLEOrder(t, e, "editor", "dnsorder0001")
	if failed["status"] != "failed" || failed["error"] == nil {
		t.Fatalf("timed-out order = %v", failed)
	}
	// Retry: runs again; a concurrent second click doesn't start it twice.
	rec := e.do("editor", "POST", "/v1/certificates/letsencrypt/dns/complete", map[string]any{"orderId": "dnsorder0001"})
	wantStatus(t, rec, http.StatusAccepted)
	again := e.do("editor", "POST", "/v1/certificates/letsencrypt/dns/complete", map[string]any{"orderId": "dnsorder0001"})
	wantStatus(t, again, http.StatusAccepted)
	if decode(t, again)["status"] != "processing" {
		t.Fatalf("second click = %s", again.Body.String())
	}
	close(release)
	done := pollLEOrder(t, e, "editor", "dnsorder0001")
	if done["status"] != "issued" || done["certId"] != "le-dns-cert" {
		t.Fatalf("done = %v", done)
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("completion ran %d times, want 2", n)
	}
	// Issued orders can't be completed again.
	rec = e.do("editor", "POST", "/v1/certificates/letsencrypt/dns/complete", map[string]any{"orderId": "dnsorder0001"})
	wantStatus(t, rec, http.StatusAccepted)
	if decode(t, rec)["status"] != "issued" || calls.Load() != 2 {
		t.Fatal("an issued order ran again")
	}
}

func TestLEOrderStaleAndErrors(t *testing.T) {
	now := time.Now()
	o := store.ACMELEOrder{OrderID: "x", Status: store.ACMELEOrderProcessing, Progress: "Validating", UpdatedAt: now.Add(-leStaleAfter - time.Second)}
	if out := leOrderOut(o, now); out.Status != "failed" || out.Error == "" || out.Progress != "" {
		t.Fatalf("stale order = %+v", out)
	}
	o.UpdatedAt = now
	if out := leOrderOut(o, now); out.Status != "processing" {
		t.Fatalf("fresh order = %+v", out)
	}
	for err, want := range map[error]string{
		context.DeadlineExceeded:  "didn't finish within 3 minutes",
		context.Canceled:          "Citadel shut down",
		errors.New("db password"): "see the server log",
		pkiInvalid("bad domain"):  "bad domain",
	} {
		if got := leErrorMessage(err); !strings.Contains(got, want) {
			t.Errorf("leErrorMessage(%v) = %q, want %q", err, got, want)
		}
	}
}

// leAudited reports whether actor's action with result is in account's log.
func leAudited(t *testing.T, st store.Store, action, result, actor, account string) bool {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		events, err := st.QueryAuditEvents(store.WithCallerAccount(context.Background(), account), store.AuditQuery{Limit: 500})
		if err != nil {
			t.Fatal(err)
		}
		for _, ev := range events {
			if strings.HasSuffix(ev.Action, action) && (ev.Result == result || (result == "ok" && ev.Result == "success")) && ev.Actor == actor {
				return true
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestLetsEncryptNeedsDatabase: the memory store answers 501 at once.
func TestLetsEncryptNeedsDatabase(t *testing.T) {
	e := newPKIEnv(t, nil)
	wantStatus(t, e.do("editor", "POST", "/v1/certificates/letsencrypt/request", map[string]any{"domains": "a.example.com"}), http.StatusNotImplemented)
	wantStatus(t, e.do("viewer", "GET", "/v1/certificates/letsencrypt/orders?id=abc", nil), http.StatusNotImplemented)
}

// TestJobRunnerGo: background tasks keep the caller's values, are bounded by
// their timeout, and are cancelled and waited for on shutdown.
func TestJobRunnerGo(t *testing.T) {
	j := newJobRunner()
	ctx, stop := context.WithCancel(context.Background())
	j.Start(ctx)
	type key struct{}
	base, cancelBase := context.WithCancel(context.WithValue(context.Background(), key{}, "acct"))
	cancelBase() // the request ending doesn't stop the task
	got := make(chan string, 1)
	ended := make(chan error, 1)
	j.Go("t", base, time.Minute, func(ctx context.Context) {
		got <- ctx.Value(key{}).(string)
		<-ctx.Done()
		ended <- ctx.Err()
	})
	if v := <-got; v != "acct" {
		t.Fatalf("value = %q", v)
	}
	stop()
	j.Wait()
	if err := <-ended; !errors.Is(err, context.Canceled) {
		t.Fatalf("task ended with %v", err)
	}
	// The timeout bounds a task, also on a nil runner.
	var nilRunner *jobRunner
	done := make(chan error, 1)
	nilRunner.Go("t2", context.Background(), 20*time.Millisecond, func(ctx context.Context) {
		<-ctx.Done()
		done <- ctx.Err()
	})
	if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout = %v", err)
	}
}
