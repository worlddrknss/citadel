package server

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// seedLECert stores a Let's Encrypt certificate in account A.
func (e *pkiEnv) seedLECert(id, kind string, notAfter time.Time) {
	e.t.Helper()
	ctx := store.WithCallerAccount(context.Background(), e.acctA)
	if err := e.st.CreateACMELECertificate(ctx, store.ACMELECertificate{
		CertID: id, DirectoryURL: "https://acme.test/dir", Domains: id + ".example.com", Serial: "1", CertB64: "AA==",
		KeyDER: []byte{1}, Status: "ISSUED", NotBefore: notAfter.Add(-90 * 24 * time.Hour), NotAfter: notAfter,
		ChallengeKind: kind, AutoRenew: kind == store.ACMELEOrderHTTP01,
	}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *pkiEnv) leCert(id string) store.ACMELECertificate {
	e.t.Helper()
	c, err := e.st.GetACMELECertificate(store.WithCallerAccount(context.Background(), e.acctA), id)
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

func (e *pkiEnv) auditedResult(action, result string) bool {
	e.t.Helper()
	events, err := e.st.QueryAuditEvents(store.WithCallerAccount(context.Background(), e.acctA), store.AuditQuery{Limit: 500})
	if err != nil {
		e.t.Fatal(err)
	}
	for _, ev := range events {
		if ev.Action == action && store.NormalizeAuditResult(ev.Result, ev.ErrorType) == result {
			return true
		}
	}
	return false
}

func TestLetsEncryptAutoRenewToggleAndStatus(t *testing.T) {
	e := newPKIEnvOn(t, pgTestStore(t), nil)
	now := time.Now().UTC()
	e.seedLECert("le-http", store.ACMELEOrderHTTP01, now.Add(60*24*time.Hour))
	e.seedLECert("le-dns", store.ACMELEOrderDNS01, now.Add(20*24*time.Hour))

	rows := map[string]nativeCertificate{}
	for _, r := range e.listRows("viewer") {
		rows[r.ID] = r
	}
	h, d := rows["le-http"], rows["le-dns"]
	if h.Renewal == nil || !h.Renewal.AutoRenew || h.Renewal.Manual || h.Renewal.Kind != "http-01" {
		t.Fatalf("http row renewal = %+v", h.Renewal)
	}
	next, err := time.Parse(time.RFC3339, h.Renewal.NextRenewalAt)
	if err != nil || next.Sub(now.Add(30*24*time.Hour)).Abs() > time.Minute {
		t.Fatalf("nextRenewalAt = %q %v", h.Renewal.NextRenewalAt, err)
	}
	if d.Renewal == nil || d.Renewal.AutoRenew || !d.Renewal.Manual || d.Renewal.NextRenewalAt != "" {
		t.Fatalf("dns row renewal = %+v", d.Renewal)
	}
	if det := e.detail("viewer", "lets-encrypt", "le-http"); det.Renewal == nil || !det.Renewal.AutoRenew {
		t.Fatalf("detail renewal = %+v", det.Renewal)
	}

	toggle := func(user, id string, on bool) int {
		return e.do(user, "POST", "/v1/certificates/letsencrypt/auto-renew", map[string]any{"certId": id, "autoRenew": on}).Code
	}
	if code := toggle("viewer", "le-http", false); code != http.StatusForbidden {
		t.Fatalf("viewer toggle = %d", code)
	}
	if code := toggle("other", "le-http", false); code != http.StatusNotFound {
		t.Fatalf("other account toggle = %d", code)
	}
	if code := toggle("editor", "le-dns", true); code != http.StatusBadRequest {
		t.Fatalf("enable DNS-01 = %d", code)
	}
	if code := e.do("editor", "POST", "/v1/certificates/letsencrypt/auto-renew", map[string]any{"certId": "le-http"}).Code; code != http.StatusBadRequest {
		t.Fatalf("missing flag = %d", code)
	}
	rec := e.do("editor", "POST", "/v1/certificates/letsencrypt/auto-renew", map[string]any{"certId": "le-http", "autoRenew": false})
	wantStatus(t, rec, http.StatusOK)
	if r := decode(t, rec)["renewal"].(map[string]any); r["autoRenew"] != false || r["nextRenewalAt"] != nil {
		t.Fatalf("toggle off = %v", r)
	}
	if e.leCert("le-http").AutoRenew {
		t.Fatal("auto-renew still on")
	}
	if !e.audited("citadel.SetLetsEncryptAutoRenew") {
		t.Fatal("toggle not audited")
	}

	// Deleting a Let's Encrypt certificate.
	wantStatus(t, e.do("admin", "DELETE", "/v1/certificates?"+url.Values{"source": {"lets-encrypt"}, "id": {"le-dns"}}.Encode(), nil), http.StatusOK)
	wantStatus(t, e.do("admin", "DELETE", "/v1/certificates?"+url.Values{"source": {"lets-encrypt"}, "id": {"le-dns"}}.Encode(), nil), http.StatusNotFound)
}

func TestLetsEncryptAutoRenewJob(t *testing.T) {
	var calls atomic.Int32
	var fail atomic.Bool

	e := newPKIEnvOn(t, pgTestStore(t), func(s *Server) {
		s.testLEIssue = func(ctx context.Context, domains []string, progress func(string)) (store.ACMELECertificate, error) {
			calls.Add(1)
			progress("Validating " + domains[0] + " (HTTP-01)")
			if fail.Load() {
				return store.ACMELECertificate{}, errors.New("connection refused")
			}
			c := store.ACMELECertificate{CertID: "le-new-" + cryptoutil.RandomHex(4), Domains: strings.Join(domains, ","), Serial: "2", CertB64: "AA==",
				KeyDER: []byte{1}, Status: "ISSUED", NotBefore: time.Now(), NotAfter: time.Now().Add(90 * 24 * time.Hour),
				ChallengeKind: store.ACMELEOrderHTTP01, AutoRenew: true}
			// The real flow stores the certificate in the caller's account.
			if err := s.store.CreateACMELECertificate(ctx, c); err != nil {
				return store.ACMELECertificate{}, err
			}
			return c, nil
		}
	})
	now := time.Now().UTC()
	e.seedLECert("le-due", store.ACMELEOrderHTTP01, now.Add(10*24*time.Hour))
	e.seedLECert("le-later", store.ACMELEOrderHTTP01, now.Add(80*24*time.Hour))
	e.seedLECert("le-dns", store.ACMELEOrderDNS01, now.Add(5*24*time.Hour))

	// A failure: recorded, backed off, alert-worthy audit event.
	fail.Store(true)
	if n := e.s.renewDueLECertificates(context.Background(), now); n != 0 || calls.Load() != 1 {
		t.Fatalf("renewed %d, calls %d", n, calls.Load())
	}
	c := e.leCert("le-due")
	if c.RenewAttempts != 1 || c.RenewLastError == "" || c.RenewNextAttemptAt == nil || c.RenewNextAttemptAt.Sub(now.Add(time.Hour)).Abs() > time.Minute {
		t.Fatalf("after failure = %+v", c)
	}
	if !e.auditedResult("citadel.LetsEncryptAutoRenewFailed", store.AuditResultError) {
		t.Fatal("failure not audited")
	}
	row := e.detail("viewer", "lets-encrypt", "le-due")
	if row.Renewal == nil || row.Renewal.LastError == "" || row.Renewal.Attempts != 1 || row.Renewal.LastAttemptAt == "" {
		t.Fatalf("renewal status after failure = %+v", row.Renewal)
	}
	// Backoff: not retried before the next attempt time, then 2 h after the second failure.
	e.s.renewDueLECertificates(context.Background(), now.Add(30*time.Minute))
	if calls.Load() != 1 {
		t.Fatalf("retried during backoff: %d calls", calls.Load())
	}
	later := now.Add(61 * time.Minute)
	e.s.renewDueLECertificates(context.Background(), later)
	if c = e.leCert("le-due"); calls.Load() != 2 || c.RenewAttempts != 2 || c.RenewNextAttemptAt.Sub(time.Now().Add(2*time.Hour)).Abs() > time.Minute {
		t.Fatalf("second failure: calls %d, %+v", calls.Load(), c)
	}

	// Success after the backoff: the replacement is recorded, auto-renews itself.
	fail.Store(false)
	if n := e.s.renewDueLECertificates(context.Background(), now.Add(3*time.Hour)); n != 1 {
		t.Fatalf("renewed %d", n)
	}
	c = e.leCert("le-due")
	if c.RenewedBy == "" || c.RenewAttempts != 0 || c.RenewLastError != "" {
		t.Fatalf("after success = %+v", c)
	}
	repl := e.leCert(c.RenewedBy)
	if !repl.AutoRenew || repl.ChallengeKind != store.ACMELEOrderHTTP01 || repl.AccountID != e.acctA {
		t.Fatalf("replacement = %+v", repl)
	}
	if !e.audited("citadel.LetsEncryptAutoRenew") {
		t.Fatal("renewal not audited")
	}
	// Done: nothing more is due (the later and DNS-01 certificates aren't).
	before := calls.Load()
	if n := e.s.renewDueLECertificates(context.Background(), now.Add(4*time.Hour)); n != 0 || calls.Load() != before {
		t.Fatalf("second pass renewed %d (calls %d)", n, calls.Load()-before)
	}
	if e.leCert("le-dns").RenewLastAttemptAt != nil || e.leCert("le-later").RenewLastAttemptAt != nil {
		t.Fatal("a certificate that isn't due was attempted")
	}
}

func TestLERenewBackoff(t *testing.T) {
	for failures, want := range map[int]time.Duration{1: time.Hour, 2: 2 * time.Hour, 3: 4 * time.Hour, 5: 16 * time.Hour, 6: 24 * time.Hour, 20: 24 * time.Hour} {
		if got := leRenewBackoff(failures); got != want {
			t.Errorf("backoff(%d) = %v, want %v", failures, got, want)
		}
	}
}
