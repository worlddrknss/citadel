package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/config"
	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/memory"
)

// toggleAuditStore fails audit appends on demand: every append (fail), or
// only outcomes, letting write-ahead attempts through (failOutcomes).
type toggleAuditStore struct {
	store.Store
	fail         atomic.Bool
	failOutcomes atomic.Bool
}

func (s *toggleAuditStore) RecordAudit(ctx context.Context, ev store.AuditEvent) error {
	if s.fail.Load() || (s.failOutcomes.Load() && ev.Result != store.AuditResultPending) {
		return errors.New("audit store unavailable")
	}
	return s.Store.RecordAudit(ctx, ev)
}

const (
	waAccessKey = "AKIAWRITEAHEAD"
	waSecret    = "write-ahead-secret"
)

func newWriteAheadEnv(t *testing.T) (*pkiEnv, *toggleAuditStore) {
	t.Helper()
	mem := &memory.Store{DefaultKey: sampleKey(1)}
	ts := &toggleAuditStore{Store: &keyStore{Store: mem, keys: map[string]store.KMSKey{}}}
	e := newPKIEnvOn(t, ts, func(s *Server) {
		s.cfg.ExpectedAccessKey, s.cfg.SecretAccessKey = waAccessKey, waSecret
	})
	return e, ts
}

func (e *pkiEnv) aws(target string, body map[string]any) *httptest.ResponseRecorder {
	e.t.Helper()
	return postSigned(e.t, e.h, target, body, waAccessKey, waSecret, time.Now())
}

func bodyHas(rec *httptest.ResponseRecorder, s string) bool {
	return strings.Contains(rec.Body.String(), s)
}

// TestWriteAheadAuditLeavesStateUnchanged: with the audit store down, a
// state-changing action is refused before it changes anything, in every
// domain and on both APIs.
func TestWriteAheadAuditLeavesStateUnchanged(t *testing.T) {
	e, ts := newWriteAheadEnv(t)
	ca := e.createCA("admin", map[string]any{"caType": "ROOT", "keyAlgorithm": "EC_prime256v1", "commonName": "WA Root"})
	wantStatus(t, e.aws("secretsmanager.CreateSecret", map[string]any{"Name": "wa-existing", "SecretString": "v1"}), http.StatusOK)
	rec := e.do("editor", "POST", "/v1/certificates/issue/generate", map[string]any{"caId": ca, "commonName": "revoke-me.example.com", "keyAlgorithm": "EC_prime256v1"})
	wantStatus(t, rec, http.StatusOK)
	certID := decode(t, rec)["certId"].(string)

	cases := []struct {
		name    string
		act     func() *httptest.ResponseRecorder
		changed func() bool // evaluated with the audit store back up
	}{
		{"Secrets CreateSecret (AWS)",
			func() *httptest.ResponseRecorder {
				return e.aws("secretsmanager.CreateSecret", map[string]any{"Name": "wa-new", "SecretString": "x"})
			},
			func() bool {
				return e.aws("secretsmanager.DescribeSecret", map[string]any{"SecretId": "wa-new"}).Code == http.StatusOK
			}},
		{"Secrets PutSecretValue (AWS)",
			func() *httptest.ResponseRecorder {
				return e.aws("secretsmanager.PutSecretValue", map[string]any{"SecretId": "wa-existing", "SecretString": "v2"})
			},
			func() bool {
				return bodyHas(e.aws("secretsmanager.GetSecretValue", map[string]any{"SecretId": "wa-existing"}), "v2")
			}},
		{"Secrets DeleteSecret (AWS)",
			func() *httptest.ResponseRecorder {
				return e.aws("secretsmanager.DeleteSecret", map[string]any{"SecretId": "wa-existing", "ForceDeleteWithoutRecovery": true})
			},
			func() bool {
				return e.aws("secretsmanager.DescribeSecret", map[string]any{"SecretId": "wa-existing"}).Code != http.StatusOK
			}},
		{"Parameters PutParameter (native)",
			func() *httptest.ResponseRecorder {
				return e.do("admin", "POST", "/v1/parameters", map[string]any{"name": "/wa/native", "type": "String", "value": "v"})
			},
			func() bool { return bodyHas(e.do("admin", "GET", "/v1/parameters", nil), "/wa/native") }},
		{"Parameters PutParameter (AWS)",
			func() *httptest.ResponseRecorder {
				return e.aws("AmazonSSM.PutParameter", map[string]any{"Name": "/wa/aws", "Value": "v", "Type": "String"})
			},
			func() bool {
				return e.aws("AmazonSSM.GetParameter", map[string]any{"Name": "/wa/aws"}).Code == http.StatusOK
			}},
		{"PKI issue",
			func() *httptest.ResponseRecorder {
				return e.do("editor", "POST", "/v1/certificates/issue/generate", map[string]any{"caId": ca, "commonName": "wa-leaf.example.com", "keyAlgorithm": "EC_prime256v1"})
			},
			func() bool { return bodyHas(e.do("admin", "GET", "/v1/certificates", nil), "wa-leaf.example.com") }},
		{"PKI revoke",
			func() *httptest.ResponseRecorder {
				return e.do("admin", "POST", "/v1/certificates/revoke", map[string]any{"certId": certID, "reason": "KeyCompromise"})
			},
			func() bool { return bodyHas(e.do("admin", "GET", "/v1/certificates", nil), "REVOKED") }},
		{"IAM CreateOpenIDConnectProvider (native)",
			func() *httptest.ResponseRecorder {
				return e.do("admin", "POST", "/v1/iam/oidc-providers", map[string]any{"url": "https://wa-idp.example.com", "clientIds": []string{"sts"}})
			},
			func() bool { return bodyHas(e.do("admin", "GET", "/v1/iam/oidc-providers", nil), "wa-idp.example.com") }},
		{"Admin create user (native)",
			func() *httptest.ResponseRecorder {
				return e.do("admin", "POST", "/v1/admin/users", map[string]any{"username": "wa-dave", "role": "viewer", "password": "new-password-1"})
			},
			func() bool { return bodyHas(e.do("admin", "GET", "/v1/admin/users", nil), "wa-dave") }},
	}
	for _, tc := range cases {
		ts.fail.Store(true)
		rec := tc.act()
		ts.fail.Store(false)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("%s with audit down: status %d %s, want 500", tc.name, rec.Code, rec.Body.String())
		}
		if tc.changed() {
			t.Errorf("%s with audit down: the change took effect", tc.name)
		}
	}
	// Sanity: the same actions succeed with the audit store up.
	for _, tc := range cases {
		if rec := tc.act(); rec.Code != http.StatusOK {
			t.Errorf("%s with audit up: %d %s", tc.name, rec.Code, rec.Body.String())
		} else if !tc.changed() {
			t.Errorf("%s with audit up: no change observed", tc.name)
		}
	}
}

// TestWriteAheadAuditKMS: KMS CreateKey and ScheduleKeyDeletion with the
// audit store down change nothing.
func TestWriteAheadAuditKMS(t *testing.T) {
	ts := &toggleAuditStore{Store: &memory.Store{AccountID: "000000000000"}}
	s := &Server{cfg: config.Config{ExpectedAccessKey: waAccessKey, SecretAccessKey: waSecret}, store: ts}
	h := s.Handler()
	call := func(target string, body map[string]any) *httptest.ResponseRecorder {
		return postSigned(t, h, target, body, waAccessKey, waSecret, time.Now())
	}
	countKeys := func() int {
		keys, _ := decode(t, call("TrentService.ListKeys", map[string]any{}))["Keys"].([]any)
		return len(keys)
	}
	rec := call("TrentService.CreateKey", map[string]any{})
	wantStatus(t, rec, http.StatusOK)
	keyID := decode(t, rec)["KeyMetadata"].(map[string]any)["KeyId"].(string)
	n := countKeys()

	ts.fail.Store(true)
	wantStatus(t, call("TrentService.CreateKey", map[string]any{}), http.StatusInternalServerError)
	wantStatus(t, call("TrentService.ScheduleKeyDeletion", map[string]any{"KeyId": keyID, "PendingWindowInDays": 7}), http.StatusInternalServerError)
	wantStatus(t, call("TrentService.DisableKey", map[string]any{"KeyId": keyID}), http.StatusInternalServerError)
	// Metadata reads keep working.
	wantStatus(t, call("TrentService.ListKeys", map[string]any{}), http.StatusOK)
	ts.fail.Store(false)

	if got := countKeys(); got != n {
		t.Fatalf("keys = %d after a refused CreateKey, want %d", got, n)
	}
	md := decode(t, call("TrentService.DescribeKey", map[string]any{"KeyId": keyID}))["KeyMetadata"].(map[string]any)
	if md["KeyState"] != "Enabled" {
		t.Fatalf("key state after refused deletion/disable = %v", md["KeyState"])
	}
	wantStatus(t, call("TrentService.ScheduleKeyDeletion", map[string]any{"KeyId": keyID, "PendingWindowInDays": 7}), http.StatusOK)
	md = decode(t, call("TrentService.DescribeKey", map[string]any{"KeyId": keyID}))["KeyMetadata"].(map[string]any)
	if md["KeyState"] != "PendingDeletion" {
		t.Fatalf("key state = %v", md["KeyState"])
	}
}

// TestWriteAheadAuditOutcomeQueue: an outcome that cannot be written does
// not fail the (audited) change; it is queued, flushed later, and linked to
// its attempt by correlation ID.
func TestWriteAheadAuditOutcomeQueue(t *testing.T) {
	e, ts := newWriteAheadEnv(t)
	ts.failOutcomes.Store(true)
	rec := e.do("admin", "POST", "/v1/parameters", map[string]any{"name": "/wa/queued", "type": "String", "value": "v"})
	if rec.Code != http.StatusOK {
		t.Fatalf("put with outcomes failing: %d %s", rec.Code, rec.Body.String())
	}
	if n := e.s.auditOutcomeBacklog(); n != 1 {
		t.Fatalf("backlog = %d, want 1", n)
	}
	if err := e.s.flushAuditOutcomes(context.Background()); err == nil {
		t.Fatal("flush succeeded while the store is down")
	}
	ts.failOutcomes.Store(false)
	if err := e.s.flushAuditOutcomes(context.Background()); err != nil || e.s.auditOutcomeBacklog() != 0 {
		t.Fatalf("flush: %v, backlog %d", err, e.s.auditOutcomeBacklog())
	}
	actx := store.WithCallerAccount(context.Background(), e.acctA)
	evs, err := e.st.QueryAuditEvents(actx, store.AuditQuery{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	var attempt, outcome store.AuditRecord
	for _, ev := range evs {
		switch {
		case ev.Result == store.AuditResultPending && ev.Action == "POST /v1/parameters":
			attempt = ev
		case ev.Action == "citadel.PutParameter":
			outcome = ev
		}
	}
	if attempt.CorrelationID == "" || outcome.CorrelationID != attempt.CorrelationID || outcome.Result != store.AuditResultSuccess {
		t.Fatalf("attempt %+v\noutcome %+v", attempt, outcome)
	}
	if attempt.Actor != "admin" || attempt.Resource != "/wa/queued" {
		t.Fatalf("attempt identity: actor %q resource %q", attempt.Actor, attempt.Resource)
	}
	linked, _ := e.st.QueryAuditEvents(actx, store.AuditQuery{Correlation: attempt.CorrelationID})
	if len(linked) != 2 {
		t.Fatalf("correlation filter returned %d events", len(linked))
	}
}

// TestWriteAheadAuditImplicitOutcome: a request that changes nothing and
// records no event of its own still closes its attempt, from the status.
func TestWriteAheadAuditImplicitOutcome(t *testing.T) {
	e, _ := newWriteAheadEnv(t)
	wantStatus(t, e.do("admin", "POST", "/v1/parameters", map[string]any{"name": "", "type": "String", "value": "v"}), http.StatusBadRequest)
	evs, _ := e.st.QueryAuditEvents(store.WithCallerAccount(context.Background(), e.acctA), store.AuditQuery{Action: "POST /v1/parameters"})
	if len(evs) != 2 || evs[0].Result != store.AuditResultError || evs[0].ErrorType != "HTTP400" || evs[1].Result != store.AuditResultPending || evs[0].CorrelationID != evs[1].CorrelationID {
		t.Fatalf("events = %+v", evs)
	}
	// Reads write no attempt.
	before := len(evs)
	wantStatus(t, e.do("admin", "GET", "/v1/parameters", nil), http.StatusOK)
	all, _ := e.st.QueryAuditEvents(store.WithCallerAccount(context.Background(), e.acctA), store.AuditQuery{Result: store.AuditResultPending})
	if len(all) != before/2 {
		t.Fatalf("pending events after a read: %d", len(all))
	}
}

// TestWriteAheadAuditSecretsPurgeJob: a background purge whose attempt
// cannot be written deletes nothing; the next run (audit back) does.
func TestWriteAheadAuditSecretsPurgeJob(t *testing.T) {
	e, ts := newWriteAheadEnv(t)
	wantStatus(t, e.aws("secretsmanager.CreateSecret", map[string]any{"Name": "wa-purge", "SecretString": "x"}), http.StatusOK)
	wantStatus(t, e.aws("secretsmanager.DeleteSecret", map[string]any{"SecretId": "wa-purge", "RecoveryWindowInDays": 7}), http.StatusOK)
	later := time.Now().Add(8 * 24 * time.Hour)
	ts.fail.Store(true)
	if n := e.s.purgeExpiredSecrets(context.Background(), later); n != 0 {
		t.Fatalf("purged %d with audit down", n)
	}
	ts.fail.Store(false)
	if n := e.s.purgeExpiredSecrets(context.Background(), later); n != 1 {
		t.Fatalf("purged %d with audit up", n)
	}
}

func TestAWSWriteAheadClassification(t *testing.T) {
	for target, want := range map[string]bool{
		"TrentService.CreateKey": true, "TrentService.ScheduleKeyDeletion": true, "secretsmanager.PutSecretValue": true,
		"AmazonSSM.PutParameter": true, "CertificateManager.RequestCertificate": true, "ACMPrivateCA.IssueCertificate": true,
		"TrentService.Encrypt": false, "TrentService.Sign": false, "secretsmanager.GetSecretValue": false,
		"TrentService.ListKeys": false, "AmazonSSM.GetParameter": false, "CertificateManager.ExportCertificate": false,
	} {
		if got := awsWriteAhead(target); got != want {
			t.Errorf("awsWriteAhead(%s) = %v, want %v", target, got, want)
		}
	}
}
