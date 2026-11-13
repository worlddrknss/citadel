package server

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// waitRotation waits for the next rotation run to finish.
func waitRotation(t *testing.T, s *Server) {
	t.Helper()
	select {
	case <-s.rot.done:
	case <-time.After(15 * time.Second):
		t.Fatal("rotation did not finish")
	}
}

func rotationCtxA() context.Context {
	return store.WithCallerAccount(context.Background(), tAcctA)
}

func (e *secretsTestEnv) rotationStatus(key string) map[string]any {
	e.t.Helper()
	c, b := e.do("victor", "GET", "/v1/secrets/rotation"+q("project", "pay", "env", "dev", "path", "/", "key", key), nil)
	e.want(c, 200, b, "rotation status")
	return b
}

func TestRotationRandomFourSteps(t *testing.T) {
	e := newSecretsTestEnv(t)
	e.s.rot.done = make(chan string, 4)
	e.want2(e.put("alice", "dev", "/", "TOKEN", "old-value"))
	before, _ := e.st.DescribeSecret(rotationCtxA(), "pay/dev/TOKEN")

	// Viewers can't configure rotation.
	c, b := e.do("victor", "POST", "/v1/secrets/rotation", map[string]any{"project": "pay", "env": "dev", "path": "/", "key": "TOKEN", "rotator": map[string]any{"type": "random"}})
	e.want(c, 403, b, "viewer configures")
	// Unknown config members are refused.
	c, b = e.do("alice", "POST", "/v1/secrets/rotation", map[string]any{"project": "pay", "env": "dev", "path": "/", "key": "TOKEN",
		"rotator": map[string]any{"type": "random", "config": map[string]any{"bogus": 1}}})
	e.want(c, 400, b, "unknown config member")

	c, b = e.do("alice", "POST", "/v1/secrets/rotation", map[string]any{"project": "pay", "env": "dev", "path": "/", "key": "TOKEN",
		"rotator":            map[string]any{"type": "random", "config": map[string]any{"length": 24, "excludePunctuation": true}},
		"scheduleExpression": "cron(0 4 ? * MON *)", "duration": "2h", "rotateImmediately": true})
	e.want(c, 200, b, "configure")
	token, _ := b["versionId"].(string)
	if token == "" || b["builtin"] != true {
		t.Fatalf("configure = %v", b)
	}
	waitRotation(t, e.s)

	meta, _ := e.st.DescribeSecret(rotationCtxA(), "pay/dev/TOKEN")
	if meta.CurrentVersionID != token || meta.PreviousVersionID != before.CurrentVersionID || store.PendingRotationToken(meta) != "" {
		t.Fatalf("stages after rotation: %v", meta.VersionStages)
	}
	if got := meta.VersionStages[token]; len(got) != 1 || got[0] != store.CurrentVersionStage {
		t.Fatalf("AWSPENDING left on the new version: %v", got)
	}
	v, _ := e.st.GetSecretValue(rotationCtxA(), "pay/dev/TOKEN", "", "")
	if len(*v.SecretString) != 24 || strings.ContainsAny(*v.SecretString, "!#$%&*") {
		t.Fatalf("rotated value %q", *v.SecretString)
	}
	if meta.RotationLambdaARN != "arn:citadel:rotator:us-west-2:"+tAcctA+":random" {
		t.Fatalf("RotationLambdaARN = %q", meta.RotationLambdaARN)
	}
	st := e.rotationStatus("TOKEN")
	if st["mode"] != "builtin" || st["status"] != "succeeded" || st["lastRotatedDate"] == nil {
		t.Fatalf("status = %v", st)
	}
	if sch := st["schedule"].(map[string]any); sch["expression"] != "cron(0 4 ? * MON *)" || sch["duration"] != "2h" {
		t.Fatalf("schedule = %v", sch)
	}
	next, _ := time.Parse(time.RFC3339, st["nextRotationDate"].(string))
	if next.Weekday() != time.Monday || next.Hour() != 4 || !next.After(time.Now()) {
		t.Fatalf("next window = %v", next)
	}
	if end, _ := time.Parse(time.RFC3339, st["windowEnd"].(string)); end.Sub(next) != 2*time.Hour {
		t.Fatalf("window end = %v", end)
	}
	hist := st["history"].([]any)
	if len(hist) != 1 || hist[0].(map[string]any)["status"] != "succeeded" || hist[0].(map[string]any)["trigger"] != "immediate" {
		t.Fatalf("history = %v", hist)
	}
	for _, step := range rotationSteps {
		if !auditedIn(t, e.st, "secretsmanager.RotationStep."+step, "ok", rotationActor, tAcctA) {
			t.Fatalf("step %s not audited", step)
		}
	}
	if !auditedIn(t, e.st, "secretsmanager.RotationSucceeded", "ok", rotationActor, tAcctA) || !auditedIn(t, e.st, "citadel.ConfigureItemRotation", "ok", "alice", tAcctA) {
		t.Fatal("rotation not audited")
	}

	// Rotate now, as an editor; account B can't see it.
	c, b = e.do("alice", "POST", "/v1/secrets/rotation/rotate", map[string]any{"project": "pay", "env": "dev", "path": "/", "key": "TOKEN"})
	e.want(c, 202, b, "rotate now")
	waitRotation(t, e.s)
	if h := e.rotationStatus("TOKEN")["history"].([]any); len(h) != 2 {
		t.Fatalf("history after rotate now = %v", h)
	}
	c, b = e.do("mallory", "GET", "/v1/secrets/rotation"+q("project", "pay", "env", "dev", "path", "/", "key", "TOKEN"), nil)
	e.want(c, 404, b, "other account")
	c, b = e.do("mallory", "POST", "/v1/secrets/rotation/rotate", map[string]any{"project": "pay", "env": "dev", "path": "/", "key": "TOKEN"})
	e.want(c, 404, b, "other account rotates")
	if !auditedIn(t, e.st, "citadel.RotateItemNow", "ok", "alice", tAcctA) {
		t.Fatal("rotate now not audited")
	}
}

// want2 adapts e.put's two results.
func (e *secretsTestEnv) want2(c int, b map[string]any) {
	e.t.Helper()
	e.want(c, 200, b, "request")
}

func TestRotationRandomJSONKeyAndScheduleJob(t *testing.T) {
	e := newSecretsTestEnv(t)
	e.want2(e.put("alice", "dev", "/", "DB", `{"username":"app","password":"old","port":5432}`))
	c, b := e.do("alice", "POST", "/v1/secrets/rotation", map[string]any{"project": "pay", "env": "dev", "path": "/", "key": "DB",
		"rotator": map[string]any{"type": "random", "config": map[string]any{"jsonKey": "password", "length": 40}}, "afterDays": 7})
	e.want(c, 200, b, "configure")
	if _, ok := b["versionId"]; ok {
		t.Fatal("rotation started without rotateImmediately")
	}
	// Not due yet: the job does nothing.
	if err := e.s.rotationJob(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h, _ := e.st.ListSecretRotationHistory(rotationCtxA(), "pay/dev/DB", 0); len(h) != 0 {
		t.Fatalf("rotated before the window: %v", h)
	}
	// Open the window, then run the job.
	meta, _ := e.st.DescribeSecret(rotationCtxA(), "pay/dev/DB")
	rot, _ := e.st.GetSecretRotation(rotationCtxA(), "pay/dev/DB")
	past := time.Now().Add(-time.Minute)
	if _, err := e.st.ConfigureSecretRotation(rotationCtxA(), store.SecretRotationConfig{SecretID: meta.Name, LambdaARN: meta.RotationLambdaARN, AfterDays: 7, NextRotationDate: &past, RotatorType: rot.RotatorType, Config: rot.Config}); err != nil {
		t.Fatal(err)
	}
	c, b = e.do("victor", "GET", "/v1/secrets"+q("project", "pay", "env", "dev", "path", "/"), nil)
	e.want(c, 200, b, "list")
	if it := b["items"].([]any)[0].(map[string]any); it["rotationDue"] != true {
		t.Fatalf("list item = %v", it)
	}
	if err := e.s.rotationJob(context.Background()); err != nil {
		t.Fatal(err)
	}
	v, _ := e.st.GetSecretValue(rotationCtxA(), "pay/dev/DB", "", "")
	var obj map[string]any
	if err := json.Unmarshal([]byte(*v.SecretString), &obj); err != nil {
		t.Fatal(err)
	}
	if obj["username"] != "app" || obj["port"] != float64(5432) || len(obj["password"].(string)) != 40 {
		t.Fatalf("rotated JSON = %v", obj)
	}
	meta, _ = e.st.DescribeSecret(rotationCtxA(), "pay/dev/DB")
	if want := time.Now().UTC().AddDate(0, 0, 7); meta.NextRotationDate == nil || meta.NextRotationDate.Day() != want.Day() {
		t.Fatalf("next rotation = %v", meta.NextRotationDate)
	}
}

// webhookTestServer is an https rotation endpoint that checks signatures.
type webhookTestServer struct {
	*httptest.Server
	mu       sync.Mutex
	key      string
	steps    []string
	bodies   []webhookRequest
	failStep string
	failures int
	badSig   int
}

func newWebhookTestServer(t *testing.T) *webhookTestServer {
	ws := &webhookTestServer{}
	ws.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ws.mu.Lock()
		defer ws.mu.Unlock()
		ts := r.Header.Get(webhookTimestampHdr)
		sec, err := strconv.ParseInt(ts, 10, 64)
		if err != nil || time.Since(time.Unix(sec, 0)).Abs() > 5*time.Minute ||
			!hmac.Equal([]byte(r.Header.Get(webhookSignatureHdr)), []byte(signWebhook(ws.key, ts, body))) {
			ws.badSig++
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var req webhookRequest
		_ = json.Unmarshal(body, &req)
		if req.Step != r.Header.Get(webhookStepHdr) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ws.steps = append(ws.steps, req.Step)
		ws.bodies = append(ws.bodies, req)
		if req.Step == ws.failStep && ws.failures > 0 {
			ws.failures--
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if req.Step == "createSecret" {
			_ = json.NewEncoder(w).Encode(webhookCreateResponse{SecretString: "from-webhook-" + req.ClientRequestToken[:6]})
		}
	}))
	t.Cleanup(ws.Close)
	return ws
}

func TestRotationWebhookSignedAndRetried(t *testing.T) {
	e := newSecretsTestEnv(t)
	e.s.rot.done = make(chan string, 4)
	ws := newWebhookTestServer(t)
	e.s.rot.webhookClient = ws.Client()
	ws.failStep, ws.failures = "testSecret", 1
	e.want2(e.put("alice", "dev", "/", "API", "old-key"))

	c, b := e.do("alice", "POST", "/v1/secrets/rotation", map[string]any{"project": "pay", "env": "dev", "path": "/", "key": "API",
		"rotator": map[string]any{"type": "webhook", "config": map[string]any{"url": "http://insecure.example.com/hook"}}})
	e.want(c, 400, b, "http url")
	c, b = e.do("alice", "POST", "/v1/secrets/rotation", map[string]any{"project": "pay", "env": "dev", "path": "/", "key": "API",
		"rotator": map[string]any{"type": "webhook", "config": map[string]any{"url": ws.URL + "/hook"}}, "afterDays": 30})
	e.want(c, 200, b, "configure webhook")
	key, _ := b["signingSecret"].(string)
	if len(key) < 32 {
		t.Fatalf("signing secret = %q", key)
	}
	ws.key = key
	// The secret is only returned once.
	if st := e.rotationStatus("API"); st["rotator"].(map[string]any)["hasSigningSecret"] != true || strings.Contains(mustJSON(t, st), key) {
		t.Fatalf("status leaks or lacks the signing secret: %v", st)
	}

	c, b = e.do("alice", "POST", "/v1/secrets/rotation/rotate", map[string]any{"project": "pay", "env": "dev", "path": "/", "key": "API"})
	e.want(c, 202, b, "rotate")
	token := b["versionId"].(string)
	waitRotation(t, e.s)

	// testSecret failed: AWSPENDING is kept, AWSCURRENT unchanged, retry scheduled.
	meta, _ := e.st.DescribeSecret(rotationCtxA(), "pay/dev/API")
	if store.PendingRotationToken(meta) != token {
		t.Fatalf("pending after failure = %q, want %q", store.PendingRotationToken(meta), token)
	}
	if v, _ := e.st.GetSecretValue(rotationCtxA(), "pay/dev/API", "", ""); *v.SecretString != "old-key" {
		t.Fatalf("AWSCURRENT changed by a failed rotation: %q", *v.SecretString)
	}
	st := e.rotationStatus("API")
	if st["status"] != "retrying" || st["lastStep"] != "testSecret" || st["attempts"] != float64(1) || st["nextAttemptAt"] == nil || st["pendingVersionId"] != token {
		t.Fatalf("status after failure = %v", st)
	}
	if !strings.Contains(st["lastError"].(string), "HTTP 500") {
		t.Fatalf("lastError = %v", st["lastError"])
	}
	if !auditedIn(t, e.st, "secretsmanager.RotationStep.testSecret", "error", rotationActor, tAcctA) {
		t.Fatal("failed step not audited")
	}
	c, b = e.do("alice", "GET", "/v1/secrets"+q("project", "pay", "env", "dev", "path", "/"), nil)
	e.want(c, 200, b, "list")
	if it := b["items"].([]any)[0].(map[string]any); it["rotationStatus"] != "retrying" {
		t.Fatalf("list item = %v", it)
	}

	// The retry resumes the same token and finishes.
	got, err := e.s.startRotation(context.Background(), tAcctA, "pay/dev/API", "retry", "", false)
	if err != nil || got != token {
		t.Fatalf("retry token = %q (%v), want %q", got, err, token)
	}
	if v, _ := e.st.GetSecretValue(rotationCtxA(), "pay/dev/API", "", ""); *v.SecretString != "from-webhook-"+token[:6] {
		t.Fatalf("value after retry = %q", *v.SecretString)
	}
	ws.mu.Lock()
	defer ws.mu.Unlock()
	want := "createSecret,setSecret,testSecret,setSecret,testSecret,finishSecret" // createSecret is not repeated
	if strings.Join(ws.steps, ",") != want || ws.badSig != 0 {
		t.Fatalf("webhook steps = %v (bad signatures %d)", ws.steps, ws.badSig)
	}
	if ws.bodies[0].CurrentValue != "old-key" || ws.bodies[1].PendingValue != "from-webhook-"+token[:6] || ws.bodies[0].ClientRequestToken != token {
		t.Fatalf("webhook bodies = %+v", ws.bodies)
	}
	if h := e.rotationStatus("API")["history"].([]any); len(h) != 2 || h[0].(map[string]any)["trigger"] != "retry" || h[1].(map[string]any)["status"] != "failed" {
		t.Fatalf("history = %v", h)
	}

	// A regenerated secret replaces the old one: the old key no longer signs.
	c, b = e.do("alice", "POST", "/v1/secrets/rotation/signing-secret", map[string]any{"project": "pay", "env": "dev", "path": "/", "key": "API"})
	e.want(c, 200, b, "regenerate")
	if b["signingSecret"] == key || b["signingSecret"] == "" {
		t.Fatalf("regenerated = %v", b)
	}
}

func mustJSON(t *testing.T, v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRotationWebhookSSRFRefused(t *testing.T) {
	for _, target := range []string{"", "https://169.254.169.254/latest", "https://[::1]/hook"} {
		e := newSecretsTestEnv(t)
		ws := newWebhookTestServer(t)
		url := target
		if url == "" {
			url = ws.URL // 127.0.0.1: loopback
		}
		e.want2(e.put("alice", "dev", "/", "API", "old-key"))
		c, b := e.do("alice", "POST", "/v1/secrets/rotation", map[string]any{"project": "pay", "env": "dev", "path": "/", "key": "API",
			"rotator": map[string]any{"type": "webhook", "config": map[string]any{"url": url}}})
		e.want(c, 200, b, "configure")
		if _, err := e.s.startRotation(context.Background(), tAcctA, "pay/dev/API", "immediate", "", false); err != nil {
			t.Fatal(err)
		}
		st := e.rotationStatus("API")
		if st["status"] != "retrying" || !strings.Contains(st["lastError"].(string), "not allowed") {
			t.Fatalf("%s: status = %v", url, st)
		}
		ws.mu.Lock()
		if len(ws.steps)+ws.badSig != 0 {
			t.Fatalf("the blocked webhook was called")
		}
		ws.mu.Unlock()
	}
}

func TestRotationApprovalAndLambdaScheduleOnly(t *testing.T) {
	e := newSecretsTestEnv(t)
	e.want2(e.put("alice", "prod", "/", "DB", "v"))
	e.want2(e.put("alice", "dev", "/", "L", "v"))
	c, b := e.do("carol", "POST", "/v1/change-requests/policies", map[string]any{"project": "pay", "env": "prod", "approvalsRequired": 1})
	e.want(c, 200, b, "policy")
	c, b = e.do("alice", "POST", "/v1/secrets/rotation", map[string]any{"project": "pay", "env": "prod", "path": "/", "key": "DB", "rotator": map[string]any{"type": "random"}})
	e.want(c, 409, b, "rotator in an approval environment")
	c, b = e.do("alice", "POST", "/v1/secrets/rotation/rotate", map[string]any{"project": "pay", "env": "prod", "path": "/", "key": "DB"})
	e.want(c, 409, b, "rotate now in an approval environment")

	c, b = e.do("alice", "POST", "/v1/secrets/rotation", map[string]any{"project": "pay", "env": "dev", "path": "/", "key": "L",
		"lambdaArn": "arn:aws:lambda:us-east-1:123456789012:function:rotate", "afterDays": 30, "rotateImmediately": true})
	e.want(c, 200, b, "lambda schedule")
	st := e.rotationStatus("L")
	if st["mode"] != "lambda" || st["enabled"] != true || len(st["history"].([]any)) != 0 || st["pendingVersionId"] != nil {
		t.Fatalf("lambda status = %v", st)
	}
	c, b = e.do("alice", "POST", "/v1/secrets/rotation/rotate", map[string]any{"project": "pay", "env": "dev", "path": "/", "key": "L"})
	e.want(c, 409, b, "rotate now without a rotator")
	c, b = e.do("alice", "POST", "/v1/secrets/rotation", map[string]any{"project": "pay", "env": "dev", "path": "/", "key": "L",
		"rotator": map[string]any{"type": "random"}, "scheduleExpression": "cron(0 25 * * ? *)"})
	e.want(c, 400, b, "bad cron")
	c, b = e.do("alice", "DELETE", "/v1/secrets/rotation"+q("project", "pay", "env", "dev", "path", "/", "key", "L"), nil)
	e.want(c, 200, b, "turn off")
	if st := e.rotationStatus("L"); st["enabled"] != false {
		t.Fatalf("after turn off = %v", st)
	}
}

// TestRotationNoDoubleRotation runs the job on two servers sharing a store,
// concurrently: each due secret rotates exactly once.
func TestRotationNoDoubleRotation(t *testing.T) {
	e := newSecretsTestEnv(t)
	runNoDoubleRotation(t, e.s, &Server{cfg: e.s.cfg, store: e.st})
}

func runNoDoubleRotation(t *testing.T, a, b *Server) {
	t.Helper()
	ctx := store.WithActor(rotationCtxA(), "alice")
	if _, err := a.store.EnsureAccountDefaultKey(ctx, tAcctA); err != nil && err != store.ErrUnsupported {
		t.Fatal(err)
	}
	names := []string{"pay/dev/A", "pay/dev/B", "pay/dev/C"}
	for _, n := range names {
		if _, _, err := a.store.CreateSecret(ctx, store.CreateSecretRequest{Name: n, SecretString: "v"}); err != nil {
			t.Fatal(err)
		}
		if _, err := a.configureRotation(ctx, secretRotationRequest{SecretID: n, RotatorType: store.RotatorRandom, AfterDays: 1}); err != nil {
			t.Fatal(err)
		}
		meta, _ := a.store.DescribeSecret(ctx, n)
		rot, _ := a.store.GetSecretRotation(ctx, n)
		past := time.Now().Add(-time.Minute)
		if _, err := a.store.ConfigureSecretRotation(ctx, store.SecretRotationConfig{SecretID: n, LambdaARN: meta.RotationLambdaARN, AfterDays: 1, NextRotationDate: &past, RotatorType: rot.RotatorType, Config: rot.Config}); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	for range 3 {
		for _, s := range []*Server{a, b} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := s.rotationJob(context.Background()); err != nil {
					t.Error(err)
				}
			}()
		}
	}
	wg.Wait()
	for _, n := range names {
		h, err := a.store.ListSecretRotationHistory(ctx, n, 0)
		if err != nil || len(h) != 1 || h[0].Status != store.RotationStatusSucceeded {
			t.Fatalf("%s history = %+v %v", n, h, err)
		}
		versions, _ := a.store.ListSecretVersionIDs(ctx, n)
		if len(versions) != 2 {
			t.Fatalf("%s has %d versions, want 2", n, len(versions))
		}
	}
}

func TestParseRotatorARN(t *testing.T) {
	ok := []struct{ in, typ, cfg string }{
		{"arn:citadel:rotator:us-west-2:111111111111:random", "random", ""},
		{"arn:citadel:rotator:us-west-2:111111111111:webhook/hooks/billing", "webhook", "hooks/billing"},
		{"arn:citadel:rotator:us-west-2:111111111111:postgresql/db/admin", "postgresql", "db/admin"},
	}
	for _, tc := range ok {
		a, isRot, err := parseRotatorARN(tc.in, "us-west-2", "111111111111")
		if !isRot || err != nil || a.Type != tc.typ || a.ConfigID != tc.cfg {
			t.Errorf("%s = %+v %v %v", tc.in, a, isRot, err)
		}
	}
	for _, in := range []string{
		"arn:citadel:rotator:eu-west-1:111111111111:random",
		"arn:citadel:rotator:us-west-2:222222222222:random",
		"arn:citadel:rotator:us-west-2:111111111111:mysql",
		"arn:citadel:rotator:us-west-2:111111111111:webhook/",
		"arn:citadel:rotator:us-west-2",
	} {
		if _, isRot, err := parseRotatorARN(in, "us-west-2", "111111111111"); !isRot || err == nil {
			t.Errorf("%s accepted", in)
		}
	}
	if _, isRot, _ := parseRotatorARN("arn:aws:lambda:us-east-1:1:function:f", "us-west-2", "1"); isRot {
		t.Error("Lambda ARN parsed as a rotator")
	}
}
