package server

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/config"
	"github.com/worlddrknss/citadel/internal/store"
)

const testSlackURL = "https://hooks.slack.com/services/T0000TEST/B0000TEST/sl4ckS3cretPart0123456789"

func (e *secretsTestEnv) createChannel(user string, body map[string]any, want int) map[string]any {
	e.t.Helper()
	c, b := e.do(user, "POST", "/v1/notifications/channels", body)
	e.want(c, want, b, "create channel")
	return b
}

func channelID(t *testing.T, b map[string]any) string {
	t.Helper()
	ch, _ := b["channel"].(map[string]any)
	id, _ := ch["id"].(string)
	if id == "" {
		t.Fatalf("no channel id in %v", b)
	}
	return id
}

func auditActions(t *testing.T, st store.Store, account string) []store.AuditRecord {
	t.Helper()
	recs, err := st.ListAuditEvents(store.WithCallerAccount(context.Background(), account), 1000)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func TestNotificationChannelsAPI(t *testing.T) {
	e := newSecretsTestEnv(t)

	// Account admins only.
	for _, u := range []string{"alice", "victor"} {
		c, b := e.do(u, "GET", "/v1/notifications/channels", nil)
		e.want(c, 403, b, u+" lists channels")
	}
	c, b := e.do("", "GET", "/v1/notifications/channels", nil)
	e.want(c, 401, b, "anonymous lists channels")
	e.createChannel("alice", map[string]any{"name": "x", "type": "webhook", "url": "https://example.com/h"}, 403)

	c, b = e.do("carol", "GET", "/v1/notifications/channels", nil)
	e.want(c, 200, b, "empty list")
	if chs, _ := b["channels"].([]any); len(chs) != 0 || b["emailAvailable"] != false {
		t.Fatalf("empty list = %v", b)
	}
	if evs, _ := b["events"].([]any); len(evs) != len(notificationEvents) {
		t.Fatalf("event catalog = %v", b["events"])
	}

	// Validation.
	for name, body := range map[string]map[string]any{
		"bad type":       {"name": "a", "type": "sms"},
		"bad name":       {"name": "a/b", "type": "webhook", "url": "https://example.com/"},
		"http url":       {"name": "a", "type": "webhook", "url": "http://example.com/"},
		"creds in url":   {"name": "a", "type": "webhook", "url": "https://u:p@example.com/"},
		"no url":         {"name": "a", "type": "webhook"},
		"unknown event":  {"name": "a", "type": "webhook", "url": "https://example.com/", "events": []string{"agent.exploded"}},
		"not slack":      {"name": "a", "type": "slack", "url": "https://evil.example.com/services/x"},
		"slack port":     {"name": "a", "type": "slack", "url": "https://hooks.slack.com:8443/services/x"},
		"slack no path":  {"name": "a", "type": "slack", "url": "https://hooks.slack.com/"},
		"webhook rcpts":  {"name": "a", "type": "webhook", "url": "https://example.com/", "recipients": []string{"a@example.com"}},
		"unknown member": {"name": "a", "type": "webhook", "url": "https://example.com/", "secret": "mine"},
	} {
		c, b := e.do("carol", "POST", "/v1/notifications/channels", body)
		e.want(c, 400, b, name)
	}
	b = e.createChannel("carol", map[string]any{"name": "mail", "type": "email", "recipients": []string{"ops@example.com"}}, 400)
	if b["error"] != "email_unavailable" {
		t.Fatalf("email without SMTP = %v", b)
	}

	// A webhook: the signing secret is returned once.
	b = e.createChannel("carol", map[string]any{"name": "Ops hook", "type": "webhook", "url": "https://hooks.example.com/citadel",
		"events": []string{"security.kill_switch", "agent.suspended", "agent.suspended", "test"}}, 201)
	hookID := channelID(t, b)
	secret, _ := b["signingSecret"].(string)
	if !strings.HasPrefix(secret, "whsec_") || len(secret) != 6+64 {
		t.Fatalf("signing secret = %q", secret)
	}
	ch := b["channel"].(map[string]any)
	if evs := ch["events"].([]any); len(evs) != 2 || evs[0] != "agent.suspended" || evs[1] != "security.kill_switch" {
		t.Fatalf("events not normalized: %v", evs)
	}
	if ch["hasSigningSecret"] != true || ch["enabled"] != true || ch["createdBy"] != "carol" {
		t.Fatalf("webhook channel = %v", ch)
	}
	e.createChannel("dave", map[string]any{"name": "Ops hook", "type": "webhook", "url": "https://example.com/"}, 409)

	// Slack: the URL is a credential, sealed and never returned.
	b = e.createChannel("carol", map[string]any{"name": "ops-slack", "type": "slack", "url": testSlackURL, "events": []string{"agent.anomaly"}}, 201)
	slackID := channelID(t, b)
	if _, ok := b["signingSecret"]; ok {
		t.Fatal("a Slack channel got a signing secret")
	}
	if ch := b["channel"].(map[string]any); ch["urlHint"] != "hooks.slack.com/services/T0000TEST/B0000TEST/…" || ch["url"] != nil {
		t.Fatalf("slack channel = %v", ch)
	}
	stored, _ := e.st.GetNotificationChannel(context.Background(), tAcctA, slackID)
	if stored.URL != "" || len(stored.URLSealed) == 0 || strings.Contains(string(stored.URLSealed), "sl4ckS3cret") {
		t.Fatalf("slack URL stored in the clear: %+v", stored)
	}

	// Account isolation: mallory (admin in B) sees and touches nothing.
	c, b = e.do("mallory", "GET", "/v1/notifications/channels", nil)
	e.want(c, 200, b, "mallory lists")
	if chs, _ := b["channels"].([]any); len(chs) != 0 {
		t.Fatalf("mallory sees %v", chs)
	}
	for _, r := range []struct{ method, path string }{
		{"POST", "/v1/notifications/channels/update"},
		{"POST", "/v1/notifications/channels/test"},
		{"POST", "/v1/notifications/channels/signing-secret"},
	} {
		c, b := e.do("mallory", r.method, r.path, map[string]any{"id": hookID})
		e.want(c, 404, b, "mallory "+r.path)
	}
	c, b = e.do("mallory", "DELETE", "/v1/notifications/channels"+q("id", hookID), nil)
	e.want(c, 404, b, "mallory deletes")
	c, b = e.do("mallory", "GET", "/v1/notifications/deliveries"+q("channelId", hookID), nil)
	e.want(c, 404, b, "mallory reads the log")

	// Update: rename, disable, resubscribe; omitted members are kept.
	c, b = e.do("dave", "POST", "/v1/notifications/channels/update", map[string]any{"id": hookID, "name": "Ops webhook", "enabled": false, "events": []string{"agent.anomaly"}})
	e.want(c, 200, b, "update")
	ch = b["channel"].(map[string]any)
	if ch["name"] != "Ops webhook" || ch["enabled"] != false || ch["url"] != "https://hooks.example.com/citadel" || ch["updatedBy"] != "dave" || len(ch["events"].([]any)) != 1 {
		t.Fatalf("updated = %v", ch)
	}
	c, b = e.do("dave", "POST", "/v1/notifications/channels/update", map[string]any{"id": slackID, "url": "https://example.com/x"})
	e.want(c, 400, b, "slack url moved off slack")
	c, b = e.do("dave", "POST", "/v1/notifications/channels/update", map[string]any{"id": slackID, "name": "Ops webhook"})
	e.want(c, 409, b, "rename onto a taken name")

	// Rotate the signing secret: a new one, once; Slack has none.
	c, b = e.do("carol", "POST", "/v1/notifications/channels/signing-secret", map[string]any{"id": hookID})
	e.want(c, 200, b, "rotate")
	if s2, _ := b["signingSecret"].(string); !strings.HasPrefix(s2, "whsec_") || s2 == secret {
		t.Fatalf("rotated secret = %q", s2)
	}
	c, b = e.do("carol", "POST", "/v1/notifications/channels/signing-secret", map[string]any{"id": slackID})
	e.want(c, 400, b, "rotate slack")

	// Test sends queue a delivery even on a disabled channel.
	c, b = e.do("carol", "POST", "/v1/notifications/channels/test", map[string]any{"id": hookID})
	e.want(c, 202, b, "test")
	c, b = e.do("carol", "GET", "/v1/notifications/deliveries"+q("channelId", hookID), nil)
	e.want(c, 200, b, "log")
	ds, _ := b["deliveries"].([]any)
	if len(ds) != 1 {
		t.Fatalf("log = %v", b)
	}
	d := ds[0].(map[string]any)
	if d["eventType"] != "test" || d["status"] != "pending" || d["data"].(map[string]any)["requestedBy"] != "carol" {
		t.Fatalf("test delivery = %v", d)
	}
	c, b = e.do("carol", "GET", "/v1/notifications/deliveries"+q("limit", "0"), nil)
	e.want(c, 400, b, "bad limit")
	c, b = e.do("carol", "POST", "/v1/notifications/deliveries/retry", map[string]any{"id": d["id"]})
	e.want(c, 404, b, "retry a pending delivery")

	// Delete.
	c, b = e.do("carol", "DELETE", "/v1/notifications/channels"+q("id", slackID), nil)
	e.want(c, 200, b, "delete")
	c, b = e.do("carol", "DELETE", "/v1/notifications/channels"+q("id", slackID), nil)
	e.want(c, 404, b, "delete again")

	// Every change is audited, without secrets.
	recs := auditActions(t, e.st, tAcctA)
	seen := map[string]bool{}
	for _, r := range recs {
		res := "ok"
		if store.NormalizeAuditResult(r.Result, r.ErrorType) != store.AuditResultSuccess {
			res = "error"
		}
		seen[r.Action+"/"+res] = true
		raw, _ := json.Marshal(r)
		if strings.Contains(string(raw), "whsec_") || strings.Contains(string(raw), "sl4ckS3cret") {
			t.Fatalf("secret in audit record: %s", raw)
		}
	}
	for _, a := range []string{"citadel.CreateNotificationChannel/ok", "citadel.CreateNotificationChannel/error", "citadel.UpdateNotificationChannel/ok",
		"citadel.RotateNotificationSigningSecret/ok", "citadel.TestNotificationChannel/ok", "citadel.DeleteNotificationChannel/ok"} {
		if !seen[a] {
			t.Errorf("no %s audit event", a)
		}
	}
}

// webhookSink is a TLS endpoint that records what it receives.
type webhookSink struct {
	srv    *httptest.Server
	mu     sync.Mutex
	status int
	got    []sinkRequest
}

type sinkRequest struct {
	header http.Header
	body   []byte
}

func newWebhookSink(t *testing.T) *webhookSink {
	k := &webhookSink{status: 204}
	k.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		k.mu.Lock()
		k.got = append(k.got, sinkRequest{r.Header.Clone(), b})
		status := k.status
		k.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(k.srv.Close)
	return k
}

func (k *webhookSink) requests() []sinkRequest {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]sinkRequest(nil), k.got...)
}

func (k *webhookSink) setStatus(code int) {
	k.mu.Lock()
	k.status = code
	k.mu.Unlock()
}

// verifySignature is what a receiver does (docs/notifications.md).
func verifySignature(secret, header string, body []byte, now time.Time) bool {
	var ts, sig string
	for _, part := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(part, "=")
		switch k {
		case "t":
			ts = v
		case "v1":
			sig = v
		}
	}
	n, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || now.Sub(time.Unix(n, 0)).Abs() > 5*time.Minute {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(sig))
}

func TestNotificationWebhookDelivery(t *testing.T) {
	e := newSecretsTestEnv(t)
	sink := newWebhookSink(t)
	e.s.notif.client = sink.srv.Client()
	ctx := context.Background()

	b := e.createChannel("carol", map[string]any{"name": "hook", "type": "webhook", "url": sink.srv.URL + "/citadel", "events": []string{"agent.suspended"}}, 201)
	hookID, secret := channelID(t, b), b["signingSecret"].(string)
	// Subscribed elsewhere, disabled, or another account: not notified.
	e.createChannel("carol", map[string]any{"name": "other", "type": "webhook", "url": sink.srv.URL + "/other", "events": []string{"agent.anomaly"}}, 201)
	e.createChannel("carol", map[string]any{"name": "off", "type": "webhook", "url": sink.srv.URL + "/off", "events": []string{"agent.suspended"}, "enabled": false}, 201)
	e.createChannel("mallory", map[string]any{"name": "b", "type": "webhook", "url": sink.srv.URL + "/b", "events": []string{"agent.suspended"}}, 201)

	if err := e.s.notify(ctx, tAcctA, "agent.exploded", nil); err == nil {
		t.Fatal("unknown event accepted")
	}
	if err := e.s.notify(ctx, tAcctA, EventAgentSuspended, []string{"not an object"}); err == nil {
		t.Fatal("non-object payload accepted")
	}
	if err := e.s.notify(ctx, tAcctA, EventAgentSuspended, map[string]any{"agentId": "agt_1", "name": "builder", "summary": "builder was suspended"}); err != nil {
		t.Fatal(err)
	}
	if n := e.s.deliverNotifications(ctx); n != 1 {
		t.Fatalf("delivered %d, want 1", n)
	}
	got := sink.requests()
	if len(got) != 1 {
		t.Fatalf("sink got %d requests", len(got))
	}
	req := got[0]
	if !verifySignature(secret, req.header.Get("X-Citadel-Signature"), req.body, time.Now()) {
		t.Fatalf("signature %q does not verify", req.header.Get("X-Citadel-Signature"))
	}
	if verifySignature("whsec_wrong_secret_0123456789", req.header.Get("X-Citadel-Signature"), req.body, time.Now()) {
		t.Fatal("signature verifies with the wrong secret")
	}
	if req.header.Get("X-Citadel-Event") != EventAgentSuspended || req.header.Get("Content-Type") != "application/json" || req.header.Get("X-Citadel-Delivery") == "" {
		t.Fatalf("headers = %v", req.header)
	}
	var env notificationEnvelope
	if err := json.Unmarshal(req.body, &env); err != nil {
		t.Fatal(err)
	}
	var data map[string]any
	_ = json.Unmarshal(env.Data, &data)
	if env.Type != EventAgentSuspended || env.AccountID != tAcctA || !strings.HasPrefix(env.ID, "evt_") || data["agentId"] != "agt_1" ||
		env.ID != req.header.Get("X-Citadel-Event-Id") {
		t.Fatalf("envelope = %+v", env)
	}
	log, _ := e.st.ListNotificationDeliveries(ctx, tAcctA, hookID, 10)
	if len(log) != 1 || log[0].Status != store.NotificationDelivered || log[0].StatusCode != 204 || log[0].Attempts != 1 {
		t.Fatalf("log = %+v", log)
	}

	// Failures are retried with backoff, then dead-lettered.
	sink.setStatus(500)
	e.s.notif.backoff = func(int) time.Duration { return 0 }
	if err := e.s.notify(ctx, tAcctA, EventAgentSuspended, map[string]any{"agentId": "agt_2"}); err != nil {
		t.Fatal(err)
	}
	e.s.deliverNotifications(ctx)
	log, _ = e.st.ListNotificationDeliveries(ctx, tAcctA, hookID, 10)
	if d := log[0]; d.Status != store.NotificationPending || d.Attempts != 1 || d.StatusCode != 500 ||
		d.LastError != "the destination returned HTTP 500" || d.NextAttemptAt == nil {
		t.Fatalf("after one failure = %+v", d)
	}
	// Due again (no backoff in this test); fail it on its last attempt.
	ch, _ := e.st.GetNotificationChannel(ctx, tAcctA, hookID)
	claimed := claimAfterBackoff(t, e)
	claimed.Attempts = notificationMaxAttempts - 1
	e.s.deliverNotification(ctx, ch, claimed)
	log, _ = e.st.ListNotificationDeliveries(ctx, tAcctA, hookID, 10)
	if d := log[0]; d.Status != store.NotificationDead || d.NextAttemptAt != nil {
		t.Fatalf("after the last attempt = %+v", d)
	}

	// A dead delivery can be retried from the API.
	sink.setStatus(200)
	c, rb := e.do("carol", "POST", "/v1/notifications/deliveries/retry", map[string]any{"id": log[0].ID})
	e.want(c, 200, rb, "retry dead")
	e.s.deliverNotifications(ctx)
	log, _ = e.st.ListNotificationDeliveries(ctx, tAcctA, hookID, 10)
	if d := log[0]; d.Status != store.NotificationDelivered || d.Attempts != 1 {
		t.Fatalf("after retry = %+v", d)
	}

	// A disabled channel drops queued events (but not tests).
	c, rb = e.do("carol", "POST", "/v1/notifications/channels/update", map[string]any{"id": hookID, "enabled": false})
	e.want(c, 200, rb, "disable")
	if _, err := e.st.EnqueueNotification(ctx, store.NotificationEnqueue{AccountID: tAcctA, EventID: "evt_x", EventType: EventAgentSuspended, Payload: "{}", ChannelID: hookID}); err != nil {
		t.Fatal(err)
	}
	c, rb = e.do("carol", "POST", "/v1/notifications/channels/test", map[string]any{"id": hookID})
	e.want(c, 202, rb, "test disabled")
	e.s.deliverNotifications(ctx)
	log, _ = e.st.ListNotificationDeliveries(ctx, tAcctA, hookID, 2)
	if log[0].EventType != EventTest || log[0].Status != store.NotificationDelivered || log[1].Status != store.NotificationDead {
		t.Fatalf("disabled channel = %+v", log)
	}
}

// claimAfterBackoff claims the one due delivery.
func claimAfterBackoff(t *testing.T, e *secretsTestEnv) store.NotificationDelivery {
	t.Helper()
	items, err := e.st.ClaimNotificationDeliveries(context.Background(), 10, time.Minute)
	if err != nil || len(items) != 1 {
		t.Fatalf("claim = %+v, %v", items, err)
	}
	return items[0]
}

func TestNotificationSignatureFormat(t *testing.T) {
	// HMAC-SHA256("whsec_test_secret_0123456789", "1700000000.{}")
	mac := hmac.New(sha256.New, []byte("whsec_test_secret_0123456789"))
	mac.Write([]byte("1700000000.{}"))
	want := "t=1700000000,v1=" + hex.EncodeToString(mac.Sum(nil))
	if got := notificationSignature("whsec_test_secret_0123456789", 1700000000, []byte("{}")); got != want {
		t.Fatalf("signature = %q, want %q", got, want)
	}
}

func TestNotificationSSRFRefused(t *testing.T) {
	e := newSecretsTestEnv(t)
	sink := newWebhookSink(t) // on 127.0.0.1: loopback is refused by the default client
	ctx := context.Background()
	b := e.createChannel("carol", map[string]any{"name": "loop", "type": "webhook", "url": sink.srv.URL + "/x", "events": []string{"agent.suspended"}}, 201)
	id := channelID(t, b)
	if err := e.s.notify(ctx, tAcctA, EventAgentSuspended, nil); err != nil {
		t.Fatal(err)
	}
	e.s.deliverNotifications(ctx)
	if n := len(sink.requests()); n != 0 {
		t.Fatalf("loopback webhook received %d requests", n)
	}
	log, _ := e.st.ListNotificationDeliveries(ctx, tAcctA, id, 1)
	if log[0].Status != store.NotificationPending || !strings.Contains(log[0].LastError, "not allowed") {
		t.Fatalf("delivery = %+v", log[0])
	}

	// The shared guarded client allows listed CIDRs.
	client := newGuardedHTTPClient([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, 5*time.Second)
	pool := x509.NewCertPool()
	pool.AddCert(sink.srv.Certificate())
	client.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool
	resp, err := client.Post(sink.srv.URL, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("allowed CIDR refused: %v", err)
	}
	resp.Body.Close()
	if _, err := newGuardedHTTPClient(nil, 5*time.Second).Get("https://169.254.169.254/latest/meta-data/"); err == nil || !strings.Contains(err.Error(), errSSRFBlocked.Error()) {
		t.Fatalf("metadata address = %v", err)
	}
}

// rewriteTransport sends every request to target (a test server standing in
// for hooks.slack.com).
type rewriteTransport struct {
	target *url.URL
	base   http.RoundTripper
	seen   []string
	mu     sync.Mutex
}

func (rt *rewriteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.mu.Lock()
	rt.seen = append(rt.seen, r.URL.String())
	rt.mu.Unlock()
	r2 := r.Clone(r.Context())
	r2.URL.Scheme, r2.URL.Host = rt.target.Scheme, rt.target.Host
	return rt.base.RoundTrip(r2)
}

func TestNotificationSlackDelivery(t *testing.T) {
	e := newSecretsTestEnv(t)
	sink := newWebhookSink(t)
	sink.setStatus(200)
	target, _ := url.Parse(sink.srv.URL)
	rt := &rewriteTransport{target: target, base: sink.srv.Client().Transport}
	e.s.notif.client = &http.Client{Transport: rt}
	ctx := context.Background()
	e.createChannel("carol", map[string]any{"name": "slack", "type": "slack", "url": testSlackURL, "events": []string{"security.kill_switch"}}, 201)
	if err := e.s.notify(ctx, tAcctA, EventSecurityKillSwitch, map[string]any{"actor": "carol", "agents": 3, "note": "<!channel> `x`"}); err != nil {
		t.Fatal(err)
	}
	e.s.deliverNotifications(ctx)
	if len(rt.seen) != 1 || rt.seen[0] != testSlackURL {
		t.Fatalf("slack requests = %v", rt.seen)
	}
	var msg map[string]string
	if err := json.Unmarshal(sink.requests()[0].body, &msg); err != nil {
		t.Fatal(err)
	}
	text := msg["text"]
	for _, want := range []string{":rotating_light: *Kill switch used*", "• actor: `carol`", "• agents: `3`", "&lt;!channel&gt; 'x'", tAcctA} {
		if !strings.Contains(text, want) {
			t.Errorf("slack text lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "<!channel>") {
		t.Fatal("slack mention not escaped")
	}
}

// ---- email -------------------------------------------------------------------

type fakeMail struct {
	from, auth string
	to         []string
	data       string
	tls        bool
}

// fakeSMTP is a minimal ESMTP server: STARTTLS (when offered), AUTH PLAIN
// (only over TLS), MAIL, RCPT, DATA and QUIT.
type fakeSMTP struct {
	ln            net.Listener
	tlsCfg        *tls.Config
	implicit      bool
	offerStartTLS bool
	mu            sync.Mutex
	mails         []fakeMail
	sawAuthPlain  bool
}

func newFakeSMTP(t *testing.T, implicit, offerStartTLS bool) (*fakeSMTP, *x509.CertPool) {
	t.Helper()
	certSrv := httptest.NewUnstartedServer(http.NotFoundHandler())
	certSrv.StartTLS()
	pool := x509.NewCertPool()
	pool.AddCert(certSrv.Certificate())
	cert := certSrv.TLS.Certificates[0]
	certSrv.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln, tlsCfg: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, implicit: implicit, offerStartTLS: offerStartTLS}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return f, pool
}

func (f *fakeSMTP) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

func (f *fakeSMTP) serve(conn net.Conn) {
	defer conn.Close()
	isTLS := f.implicit
	if f.implicit {
		conn = tls.Server(conn, f.tlsCfg)
	}
	tp := textproto.NewConn(conn)
	_ = tp.PrintfLine("220 fake ESMTP")
	var cur fakeMail
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO", "HELO":
			lines := []string{"250-fake"}
			if f.offerStartTLS && !isTLS {
				lines = append(lines, "250-STARTTLS")
			}
			if isTLS {
				lines = append(lines, "250-AUTH PLAIN")
			}
			lines = append(lines, "250 OK")
			for _, l := range lines {
				_ = tp.PrintfLine("%s", l)
			}
		case "STARTTLS":
			_ = tp.PrintfLine("220 go ahead")
			tc := tls.Server(conn, f.tlsCfg)
			if err := tc.Handshake(); err != nil {
				return
			}
			conn, isTLS = tc, true
			tp = textproto.NewConn(conn)
		case "AUTH":
			mech, resp, _ := strings.Cut(arg, " ")
			raw, _ := base64.StdEncoding.DecodeString(resp)
			f.mu.Lock()
			f.sawAuthPlain = f.sawAuthPlain || strings.EqualFold(mech, "PLAIN")
			f.mu.Unlock()
			cur.auth = string(raw)
			_ = tp.PrintfLine("235 ok")
		case "MAIL":
			cur.from = strings.TrimSuffix(strings.TrimPrefix(arg, "FROM:<"), ">")
			_ = tp.PrintfLine("250 ok")
		case "RCPT":
			to := strings.TrimSuffix(strings.TrimPrefix(arg, "TO:<"), ">")
			if strings.HasPrefix(to, "reject") {
				_ = tp.PrintfLine("550 5.1.1 no such user %s", to)
				continue
			}
			cur.to = append(cur.to, to)
			_ = tp.PrintfLine("250 ok")
		case "DATA":
			_ = tp.PrintfLine("354 go")
			data, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			cur.data, cur.tls = string(data), isTLS
			f.mu.Lock()
			f.mails = append(f.mails, cur)
			f.mu.Unlock()
			cur = fakeMail{}
			_ = tp.PrintfLine("250 queued")
		case "QUIT":
			_ = tp.PrintfLine("221 bye")
			return
		default:
			_ = tp.PrintfLine("250 ok")
		}
	}
}

func (f *fakeSMTP) received() []fakeMail {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeMail(nil), f.mails...)
}

func TestNotificationEmailDelivery(t *testing.T) {
	for _, mode := range []string{config.SMTPStartTLS, config.SMTPImplicitTLS} {
		t.Run(mode, func(t *testing.T) {
			e := newSecretsTestEnv(t)
			srv, pool := newFakeSMTP(t, mode == config.SMTPImplicitTLS, true)
			e.s.cfg.SMTP = config.SMTPConfig{Host: "127.0.0.1", Port: srv.port(), TLS: mode, Username: "citadel", Password: "smtp-password-123", From: `"Citadel" <citadel@example.com>`}
			e.s.notif.smtpRootCAs = pool
			ctx := context.Background()

			c, b := e.do("carol", "GET", "/v1/notifications/channels", nil)
			e.want(c, 200, b, "list")
			if b["emailAvailable"] != true {
				t.Fatal("emailAvailable is false with SMTP configured")
			}
			e.createChannel("carol", map[string]any{"name": "m", "type": "email", "recipients": []string{"not-an-address"}}, 400)
			e.createChannel("carol", map[string]any{"name": "m", "type": "email", "url": "https://x.example.com/", "recipients": []string{"a@example.com"}}, 400)
			b = e.createChannel("carol", map[string]any{"name": "mail", "type": "email", "events": []string{"agent.approval_requested"},
				"recipients": []string{"Ops Team <ops@example.com>", "sec@example.com", "ops@example.com"}}, 201)
			if r := b["channel"].(map[string]any)["recipients"].([]any); len(r) != 2 || r[0] != "ops@example.com" {
				t.Fatalf("recipients = %v", r)
			}
			if err := e.s.notify(ctx, tAcctA, EventAgentApprovalRequested, map[string]any{"agent": "deployer", "credential": "github-pat", "summary": "deployer asks to use github-pat\r\nBcc: evil@example.com"}); err != nil {
				t.Fatal(err)
			}
			e.s.deliverNotifications(ctx)
			mails := srv.received()
			if len(mails) != 1 {
				log, _ := e.st.ListNotificationDeliveries(ctx, tAcctA, "", 5)
				t.Fatalf("got %d mails; log %+v", len(mails), log)
			}
			m := mails[0]
			if !m.tls || m.auth != "\x00citadel\x00smtp-password-123" || m.from != "citadel@example.com" || strings.Join(m.to, ",") != "ops@example.com,sec@example.com" {
				t.Fatalf("mail = %+v", m)
			}
			msg, err := textproto.NewReader(bufio.NewReader(strings.NewReader(m.data))).ReadMIMEHeader()
			if err != nil {
				t.Fatal(err)
			}
			if msg.Get("Subject") != "[Citadel] Agent approval requested" || msg.Get("Bcc") != "" || msg.Get("From") != `"Citadel" <citadel@example.com>` {
				t.Fatalf("headers = %v", msg)
			}
			if !strings.Contains(m.data, "credential: github-pat") || !strings.Contains(m.data, "deployer asks to use github-pat  Bcc: evil@example.com") {
				t.Fatalf("body = %s", m.data)
			}
		})
	}
}

func TestNotificationEmailRefusesPlaintext(t *testing.T) {
	e := newSecretsTestEnv(t)
	srv, pool := newFakeSMTP(t, false, false) // no STARTTLS offered
	e.s.cfg.SMTP = config.SMTPConfig{Host: "127.0.0.1", Port: srv.port(), TLS: config.SMTPStartTLS, Username: "citadel", Password: "smtp-password-123", From: "citadel@example.com"}
	e.s.notif.smtpRootCAs = pool
	ctx := context.Background()
	b := e.createChannel("carol", map[string]any{"name": "mail", "type": "email", "recipients": []string{"ops@example.com"}}, 201)
	c, rb := e.do("carol", "POST", "/v1/notifications/channels/test", map[string]any{"id": channelID(t, b)})
	e.want(c, 202, rb, "test")
	e.s.deliverNotifications(ctx)
	if len(srv.received()) != 0 || srv.sawAuthPlain {
		t.Fatal("sent or authenticated without TLS")
	}
	log, _ := e.st.ListNotificationDeliveries(ctx, tAcctA, "", 1)
	if !strings.Contains(log[0].LastError, "does not offer STARTTLS") {
		t.Fatalf("error = %q", log[0].LastError)
	}

	// A rejected recipient reports the reply code, not the server's text.
	srv2, pool2 := newFakeSMTP(t, true, false)
	e.s.cfg.SMTP = config.SMTPConfig{Host: "127.0.0.1", Port: srv2.port(), TLS: config.SMTPImplicitTLS, From: "citadel@example.com"}
	e.s.notif.smtpRootCAs = pool2
	b = e.createChannel("carol", map[string]any{"name": "mail2", "type": "email", "recipients": []string{"reject-me@example.com"}}, 201)
	c, rb = e.do("carol", "POST", "/v1/notifications/channels/test", map[string]any{"id": channelID(t, b)})
	e.want(c, 202, rb, "test 2")
	e.s.deliverNotifications(ctx)
	log, _ = e.st.ListNotificationDeliveries(ctx, tAcctA, channelID(t, b), 1)
	if log[0].LastError != "smtp: RCPT TO refused (550)" {
		t.Fatalf("error = %q", log[0].LastError)
	}

	// An untrusted certificate is refused.
	e.s.notif.smtpRootCAs = x509.NewCertPool()
	if err := e.s.smtpSend(ctx, e.s.cfg.SMTP, "citadel@example.com", []string{"a@example.com"}, []byte("x")); err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("untrusted cert = %v", err)
	}
}

func TestSlackURLHelpers(t *testing.T) {
	if h := slackURLHint(testSlackURL); h != "hooks.slack.com/services/T0000TEST/B0000TEST/…" {
		t.Fatalf("hint = %q", h)
	}
	if h := slackURLHint("https://hooks.slack.com/secret"); h != "hooks.slack.com/…" {
		t.Fatalf("hint = %q", h)
	}
	for _, bad := range []string{"https://hooks.slack.com.evil.example/x", "https://evilhooks.slack.com/x", "http://hooks.slack.com/x"} {
		if validateSlackURL(bad) == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if notificationBackoff(1) != 30*time.Second || notificationBackoff(3) != 2*time.Minute || notificationBackoff(30) != time.Hour {
		t.Fatal("backoff schedule changed")
	}
}
