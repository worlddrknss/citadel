package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/config"
	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/memory"
)

const (
	tAcctA = "111111111111"
	tAcctB = "222222222222"
)

type secretsTestEnv struct {
	t  *testing.T
	s  *Server
	st *memory.Store
	h  http.Handler
}

// newSecretsTestEnv serves the full handler chain over the in-memory store,
// with console sessions (cookie = username):
//
//	account A: alice, bob, erin (editors), carol, dave (admins), victor (viewer)
//	account B: mallory (admin)
func newSecretsTestEnv(t *testing.T) *secretsTestEnv {
	t.Helper()
	st := newTenantTestStore()
	st.AuditHMACKey = bytes.Repeat([]byte{9}, 32)
	users := map[string]store.UIUser{}
	accts := map[string]string{}
	for _, u := range []struct{ n, r, a string }{
		{"alice", "editor", tAcctA}, {"bob", "editor", tAcctA}, {"erin", "editor", tAcctA},
		{"carol", "admin", tAcctA}, {"dave", "admin", tAcctA}, {"victor", "viewer", tAcctA},
		{"mallory", "admin", tAcctB},
	} {
		users[u.n] = store.UIUser{Username: u.n, Role: u.r, DisplayName: strings.ToUpper(u.n[:1]) + u.n[1:], Accounts: []string{u.a}}
		accts[u.n] = u.a
	}
	cfg := config.Config{UIUsers: users, SessionIdleTTL: time.Hour, SessionAbsTTL: time.Hour, WrappingKey: bytes.Repeat([]byte{3}, 32), AuditHMACKey: st.AuditHMACKey}
	s := &Server{cfg: cfg, store: st}
	now := time.Now().UTC()
	for name, acct := range accts {
		if err := st.CreateConsoleSession(context.Background(), store.ConsoleSession{
			ID: name, TokenHash: hashSessionToken(name), Username: name, AccountID: acct,
			Method: store.SessionMethodPassword, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}
	return &secretsTestEnv{t: t, s: s, st: st, h: s.Handler()}
}

// do sends a request as user ("" = anonymous) and decodes the JSON reply.
func (e *secretsTestEnv) do(user, method, path string, body any) (int, map[string]any) {
	e.t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	if user != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: user})
		req.Header.Set(csrfHeader, "1")
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (e *secretsTestEnv) want(code int, wantCode int, body map[string]any, what string) {
	e.t.Helper()
	if code != wantCode {
		e.t.Fatalf("%s: status %d, want %d; body %v", what, code, wantCode, body)
	}
}

func q(kv ...string) string {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return "?" + v.Encode()
}

func (e *secretsTestEnv) put(user, env, path, key, value string) (int, map[string]any) {
	return e.do(user, "POST", "/v1/secrets", map[string]any{"project": "pay", "env": env, "path": path, "key": key, "value": value})
}

func TestSecretsRevealViewerSetting(t *testing.T) {
	e := newSecretsTestEnv(t)
	c, b := e.put("alice", "dev", "/", "TOKEN", "s3cr3t-value")
	e.want(c, 200, b, "put")
	reveal := "/v1/secrets/value" + q("project", "pay", "env", "dev", "path", "/", "key", "TOKEN")

	c, b = e.do("victor", "GET", reveal, nil)
	e.want(c, 403, b, "viewer reveal by default")
	if b["error"] != "reveal_forbidden" {
		t.Fatalf("error = %v", b["error"])
	}
	c, b = e.do("alice", "GET", reveal, nil)
	e.want(c, 200, b, "editor reveal")
	if b["value"] != "s3cr3t-value" {
		t.Fatalf("value = %v", b["value"])
	}

	c, b = e.do("victor", "GET", "/v1/secrets/settings", nil)
	e.want(c, 200, b, "viewer reads settings")
	if b["viewersCanReveal"] != false {
		t.Fatalf("default viewersCanReveal = %v", b["viewersCanReveal"])
	}
	c, b = e.do("alice", "POST", "/v1/secrets/settings", map[string]any{"viewersCanReveal": true})
	e.want(c, 403, b, "editor changes settings")
	c, b = e.do("carol", "POST", "/v1/secrets/settings", map[string]any{})
	e.want(c, 400, b, "settings without field")
	c, b = e.do("carol", "POST", "/v1/secrets/settings", map[string]any{"viewersCanReveal": true})
	e.want(c, 200, b, "admin enables viewer reveal")
	c, b = e.do("victor", "GET", reveal, nil)
	e.want(c, 200, b, "viewer reveal when allowed")

	// The setting is per account: B's admin turning it on doesn't affect A,
	// and A's setting doesn't leak into B.
	c, b = e.do("mallory", "GET", "/v1/secrets/settings", nil)
	e.want(c, 200, b, "account B settings")
	if b["viewersCanReveal"] != false {
		t.Fatal("account A's setting leaked into account B")
	}
	c, b = e.do("", "GET", "/v1/secrets/settings", nil)
	e.want(c, 401, b, "anonymous settings")
}

func TestSecretsOptionalFields(t *testing.T) {
	e := newSecretsTestEnv(t)
	e.put("alice", "dev", "/", "A", "one")
	e.put("bob", "dev", "/", "A", "two")
	e.put("alice", "dev", "/db", "PASSWORD", "pw")
	e.put("alice", "dev", "/db/replica", "PASSWORD", "pw2")
	e.put("alice", "prod", "/", "A", "p")
	c, b := e.do("alice", "POST", "/v1/secrets/tags", map[string]any{"project": "pay", "env": "dev", "path": "/", "key": "A", "tags": []map[string]string{{"key": "team", "value": "core"}}})
	e.want(c, 200, b, "tag")

	c, b = e.do("victor", "GET", "/v1/secrets"+q("project", "pay", "env", "dev", "path", "/"), nil)
	e.want(c, 200, b, "list")
	items := b["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items = %v", items)
	}
	it := items[0].(map[string]any)
	if it["version"] != float64(2) || it["updatedBy"] != "bob" || len(it["tags"].([]any)) != 1 {
		t.Fatalf("list item = %v", it)
	}
	if fc := b["folderCounts"].(map[string]any); fc["db"] != float64(2) {
		t.Fatalf("folderCounts = %v", fc)
	}

	c, b = e.do("victor", "GET", "/v1/projects", nil)
	e.want(c, 200, b, "projects")
	p := b["projects"].([]any)[0].(map[string]any)
	if ec := p["environmentCounts"].(map[string]any); ec["dev"] != float64(3) || ec["prod"] != float64(1) {
		t.Fatalf("environmentCounts = %v", ec)
	}

	c, b = e.do("victor", "GET", "/v1/secrets/versions"+q("project", "pay", "env", "dev", "path", "/", "key", "A"), nil)
	e.want(c, 200, b, "versions")
	vs := b["versions"].([]any)
	if len(vs) != 2 || vs[0].(map[string]any)["createdBy"] != "bob" || vs[1].(map[string]any)["createdBy"] != "alice" {
		t.Fatalf("versions = %v", vs)
	}

	c, b = e.do("victor", "GET", "/v1/secrets/detail"+q("project", "pay", "env", "dev", "path", "/", "key", "A"), nil)
	e.want(c, 200, b, "detail")
	fp, _ := b["fingerprint"].(string)
	if b["valueLength"] != float64(3) || b["updatedBy"] != "bob" || !strings.HasPrefix(fp, "hmac:") || len(fp) != len("hmac:")+12 {
		t.Fatalf("detail = %v", b)
	}
	// Keyed: not a prefix of the plain SHA-256 of "two".
	if strings.Contains(fp, "3fc4ccfe745870e2c0d99f71f30ff0656c8dedd41cc1d7d3d376b0dbe685e2f3"[:12]) {
		t.Fatal("fingerprint is a plain sha256")
	}

	// Account B sees none of it.
	c, b = e.do("mallory", "GET", "/v1/secrets"+q("project", "pay", "env", "dev", "path", "/"), nil)
	e.want(c, 200, b, "account B list")
	if len(b["items"].([]any)) != 0 {
		t.Fatal("account B lists account A's secrets")
	}
	c, b = e.do("mallory", "GET", "/v1/secrets/detail"+q("project", "pay", "env", "dev", "path", "/", "key", "A"), nil)
	e.want(c, 404, b, "account B detail")
}

func TestApprovalPolicyAndGating(t *testing.T) {
	e := newSecretsTestEnv(t)
	e.put("alice", "prod", "/", "DB", "old")

	c, b := e.do("alice", "POST", "/v1/change-requests/policies", map[string]any{"project": "pay", "env": "prod", "approvalsRequired": 1})
	e.want(c, 403, b, "editor sets policy")
	c, b = e.do("carol", "POST", "/v1/change-requests/policies", map[string]any{"project": "pay", "env": "bad/env", "approvalsRequired": 1})
	e.want(c, 400, b, "invalid env")
	c, b = e.do("carol", "POST", "/v1/change-requests/policies", map[string]any{"project": "pay", "env": "prod", "approvalsRequired": 11})
	e.want(c, 400, b, "too many approvals")
	c, b = e.do("carol", "POST", "/v1/change-requests/policies", map[string]any{"project": "pay", "env": "prod", "approvalsRequired": 1, "approverRoles": []string{"owner"}})
	e.want(c, 400, b, "bad role")
	c, b = e.do("carol", "POST", "/v1/change-requests/policies", map[string]any{"project": "pay", "env": "prod", "approvalsRequired": 2, "approverRoles": []string{"editor"}})
	e.want(c, 200, b, "admin sets policy")

	c, b = e.do("victor", "GET", "/v1/change-requests/policies", nil)
	e.want(c, 200, b, "list policies")
	pol := b["policies"].([]any)
	if len(pol) != 1 || pol[0].(map[string]any)["approvalsRequired"] != float64(2) {
		t.Fatalf("policies = %v", pol)
	}
	c, b = e.do("mallory", "GET", "/v1/change-requests/policies", nil)
	e.want(c, 200, b, "account B policies")
	if len(b["policies"].([]any)) != 0 {
		t.Fatal("account B sees account A's policy")
	}

	// Direct writes are refused in prod, allowed in dev.
	c, b = e.put("alice", "prod", "/", "DB", "new")
	e.want(c, 409, b, "direct write to approval env")
	if b["error"] != "approval_required" {
		t.Fatalf("error = %v", b["error"])
	}
	c, b = e.put("alice", "dev", "/", "DB", "x")
	e.want(c, 200, b, "write to dev")
	c, b = e.do("alice", "POST", "/v1/secrets/restore"+q("project", "pay", "env", "prod", "path", "/", "key", "DB"), nil)
	e.want(c, 409, b, "restore in approval env")
	c, b = e.do("alice", "POST", "/v1/secrets/versions/promote", map[string]any{"project": "pay", "env": "prod", "path": "/", "key": "DB", "versionId": "x"})
	e.want(c, 409, b, "promote in approval env")
	c, b = e.do("alice", "POST", "/v1/secrets/bulk", map[string]any{"project": "pay", "env": "prod", "path": "/", "keys": []string{"DB"}, "action": "move", "targetPath": "/x"})
	e.want(c, 409, b, "bulk move in approval env")
	// Account B is unaffected by A's policy.
	c, b = e.do("mallory", "POST", "/v1/secrets", map[string]any{"project": "pay", "env": "prod", "path": "/", "key": "DB", "value": "b"})
	e.want(c, 200, b, "account B write to its own prod")

	// Removing the policy re-opens direct writes.
	c, b = e.do("carol", "POST", "/v1/change-requests/policies", map[string]any{"project": "pay", "env": "prod", "approvalsRequired": 0})
	e.want(c, 200, b, "remove policy")
	c, b = e.put("alice", "prod", "/", "DB", "new")
	e.want(c, 200, b, "write after policy removed")
}

func TestChangeRequestLifecycle(t *testing.T) {
	e := newSecretsTestEnv(t)
	e.put("alice", "prod", "/", "DB", "old-value")
	e.do("carol", "POST", "/v1/change-requests/policies", map[string]any{"project": "pay", "env": "prod", "approvalsRequired": 2, "approverRoles": []string{"editor"}})

	c, b := e.do("victor", "POST", "/v1/change-requests", map[string]any{"project": "pay", "env": "prod", "path": "/", "key": "DB", "value": "new-value"})
	e.want(c, 403, b, "viewer creates CR")
	c, b = e.do("alice", "POST", "/v1/change-requests", map[string]any{"project": "pay", "env": "prod", "path": "/", "key": "../x", "value": "v"})
	e.want(c, 400, b, "invalid key")
	c, b = e.do("alice", "POST", "/v1/change-requests", map[string]any{"project": "pay", "env": "prod", "path": "/", "key": "DB", "value": "new-value", "comment": "rotate"})
	e.want(c, 200, b, "create CR")
	id := b["id"].(string)

	// The proposed value is stored only as ciphertext.
	stored, err := e.st.GetChangeRequest(store.WithCallerAccount(t.Context(), tAcctA), id)
	if err != nil || strings.Contains(stored.ProposedCiphertext, "new-value") || stored.ProposedKMSKeyID == "" {
		t.Fatalf("stored CR = %+v, %v", stored, err)
	}

	detail := "/v1/change-requests/detail" + q("id", id)
	c, b = e.do("alice", "GET", detail, nil)
	e.want(c, 200, b, "requester detail")
	if b["canApprove"] != false || !strings.Contains(b["cannotApproveReason"].(string), "own") {
		t.Fatalf("requester canApprove = %v (%v)", b["canApprove"], b["cannotApproveReason"])
	}
	ch := b["changes"].([]any)[0].(map[string]any)
	prev, prop := ch["previous"].(map[string]any), ch["proposed"].(map[string]any)
	if ch["change"] != "modified" || prev["length"] != float64(9) || prop["length"] != float64(9) || prev["sha256"] == prop["sha256"] || len(prop["sha256"].(string)) != 12 || prev["version"] != "v1" || prop["version"] != "v2" {
		t.Fatalf("changes = %v", ch)
	}
	if prop["fingerprint"] != "hmac:"+prop["sha256"].(string) {
		t.Fatalf("proposed fingerprint = %v", prop)
	}
	if b["canReject"] != true {
		t.Fatal("requester may not withdraw their request")
	}
	_, lb := e.do("bob", "GET", "/v1/change-requests", nil)
	if row := lb["changeRequests"].([]any)[0].(map[string]any); row["canApprove"] != true || row["approvalsRequired"] != float64(2) || row["approvals"] != float64(0) {
		t.Fatalf("list row for an approver = %v", row)
	}
	if b["comment"] != "rotate" || b["requesterRole"] != "editor" {
		t.Fatalf("detail = %v", b)
	}
	c, b = e.do("victor", "GET", detail, nil)
	e.want(c, 200, b, "viewer detail")
	if b["canApprove"] != false {
		t.Fatal("viewer may approve")
	}
	c, b = e.do("mallory", "GET", detail, nil)
	e.want(c, 404, b, "account B detail")

	values := "/v1/change-requests/values" + q("id", id)
	c, b = e.do("victor", "GET", values, nil)
	e.want(c, 403, b, "viewer values")
	c, b = e.do("bob", "GET", values, nil)
	e.want(c, 200, b, "editor values")
	v := b["changes"].([]any)[0].(map[string]any)
	if v["previousValue"] != "old-value" || v["proposedValue"] != "new-value" {
		t.Fatalf("values = %v", v)
	}
	c, b = e.do("mallory", "GET", values, nil)
	e.want(c, 404, b, "account B values")

	// The requester can never approve, even with an admin-level role check.
	c, b = e.do("alice", "POST", "/v1/change-requests/approve", map[string]any{"id": id})
	e.want(c, 403, b, "self approval")
	c, b = e.do("victor", "POST", "/v1/change-requests/approve", map[string]any{"id": id})
	e.want(c, 403, b, "viewer approval")
	c, b = e.do("mallory", "POST", "/v1/change-requests/approve", map[string]any{"id": id})
	e.want(c, 404, b, "cross-account approval")

	c, b = e.do("bob", "POST", "/v1/change-requests/approve", map[string]any{"id": id, "comment": "lgtm"})
	e.want(c, 200, b, "first approval")
	if b["applied"] != false || b["approvals"] != float64(1) {
		t.Fatalf("first approval = %v", b)
	}
	c, b = e.do("bob", "POST", "/v1/change-requests/approve", map[string]any{"id": id})
	e.want(c, 403, b, "same approver twice")
	reveal := "/v1/secrets/value" + q("project", "pay", "env", "prod", "path", "/", "key", "DB")
	if _, r := e.do("bob", "GET", reveal, nil); r["value"] != "old-value" {
		t.Fatalf("value changed before enough approvals: %v", r["value"])
	}
	c, b = e.do("erin", "POST", "/v1/change-requests/approve", map[string]any{"id": id, "comment": "ship"})
	e.want(c, 200, b, "second approval")
	if b["applied"] != true || b["status"] != "approved" {
		t.Fatalf("second approval = %v", b)
	}
	if _, r := e.do("bob", "GET", reveal, nil); r["value"] != "new-value" {
		t.Fatalf("value after approval = %v", r["value"])
	}
	// The applied version is attributed to the requester.
	_, r := e.do("bob", "GET", "/v1/secrets/versions"+q("project", "pay", "env", "prod", "path", "/", "key", "DB"), nil)
	if r["versions"].([]any)[0].(map[string]any)["createdBy"] != "alice" {
		t.Fatalf("applied version createdBy = %v", r["versions"])
	}
	c, b = e.do("dave", "POST", "/v1/change-requests/approve", map[string]any{"id": id})
	e.want(c, 409, b, "approve decided")

	c, b = e.do("bob", "GET", detail, nil)
	e.want(c, 200, b, "decided detail")
	if len(b["approvals"].([]any)) != 2 || b["decisionComment"] != "ship" || b["decidedBy"] != "erin" {
		t.Fatalf("decided detail = %v", b)
	}

	c, b = e.do("victor", "GET", "/v1/change-requests", nil)
	e.want(c, 200, b, "list")
	if len(b["changeRequests"].([]any)) != 1 {
		t.Fatalf("list = %v", b)
	}
	c, b = e.do("mallory", "GET", "/v1/change-requests", nil)
	e.want(c, 200, b, "account B list")
	if len(b["changeRequests"].([]any)) != 0 {
		t.Fatal("account B lists account A's change requests")
	}
}

func TestChangeRequestRejectAndDefaultPolicy(t *testing.T) {
	e := newSecretsTestEnv(t)
	c, b := e.do("alice", "POST", "/v1/change-requests", map[string]any{"project": "pay", "env": "dev", "path": "/", "key": "NEW", "value": "v"})
	e.want(c, 200, b, "create")
	id := b["id"].(string)
	// No policy: one admin approval; editors may not approve.
	c, b = e.do("bob", "POST", "/v1/change-requests/approve", map[string]any{"id": id})
	e.want(c, 403, b, "editor approves under default policy")
	c, b = e.do("bob", "POST", "/v1/change-requests/reject", map[string]any{"id": id})
	e.want(c, 403, b, "editor rejects under default policy")
	c, b = e.do("carol", "POST", "/v1/change-requests/reject", map[string]any{"id": id, "comment": "no"})
	e.want(c, 200, b, "admin rejects")
	c, b = e.do("carol", "POST", "/v1/change-requests/approve", map[string]any{"id": id})
	e.want(c, 409, b, "approve rejected")
	if _, r := e.do("carol", "GET", "/v1/secrets/detail"+q("project", "pay", "env", "dev", "path", "/", "key", "NEW"), nil); r["error"] != "not_found" {
		t.Fatal("rejected request was applied")
	}

	// The requester may withdraw their own request.
	_, b = e.do("alice", "POST", "/v1/change-requests", map[string]any{"project": "pay", "env": "dev", "path": "/", "key": "NEW", "value": "v"})
	c, b = e.do("alice", "POST", "/v1/change-requests/reject", map[string]any{"id": b["id"]})
	e.want(c, 200, b, "withdraw")

	_, b = e.do("alice", "POST", "/v1/change-requests", map[string]any{"project": "pay", "env": "dev", "path": "/", "key": "NEW", "value": "created"})
	c, b = e.do("carol", "POST", "/v1/change-requests/approve", map[string]any{"id": b["id"]})
	e.want(c, 200, b, "admin approves")
	if b["applied"] != true {
		t.Fatalf("approve = %v", b)
	}
}

func TestBulkCopyAndMove(t *testing.T) {
	e := newSecretsTestEnv(t)
	e.put("alice", "dev", "/", "A", "a1")
	e.put("alice", "dev", "/", "B", "b1")
	e.put("alice", "staging", "/", "B", "existing")
	e.do("alice", "POST", "/v1/secrets/tags", map[string]any{"project": "pay", "env": "dev", "path": "/", "key": "A", "tags": []map[string]string{{"key": "t", "value": "1"}}})

	copyReq := map[string]any{"project": "pay", "env": "dev", "path": "/", "keys": []string{"A", "B", "MISSING"}, "action": "copy", "targetEnv": "staging", "targetPath": "/", "overwrite": false}
	c, b := e.do("victor", "POST", "/v1/secrets/bulk", copyReq)
	e.want(c, 403, b, "viewer bulk")
	c, b = e.do("alice", "POST", "/v1/secrets/bulk", map[string]any{"project": "pay", "env": "dev", "path": "/", "keys": []string{"A"}, "action": "copy", "targetEnv": "dev", "targetPath": "/"})
	e.want(c, 400, b, "copy onto itself")
	c, b = e.do("alice", "POST", "/v1/secrets/bulk", copyReq)
	e.want(c, 200, b, "copy")
	if b["applied"] != float64(1) || len(b["failed"].([]any)) != 2 {
		t.Fatalf("copy = %v", b)
	}
	_, d := e.do("alice", "GET", "/v1/secrets/detail"+q("project", "pay", "env", "staging", "path", "/", "key", "A"), nil)
	if len(d["tags"].([]any)) != 1 {
		t.Fatalf("copied tags = %v", d["tags"])
	}
	copyReq["overwrite"] = true
	copyReq["keys"] = []string{"B"}
	c, b = e.do("alice", "POST", "/v1/secrets/bulk", copyReq)
	e.want(c, 200, b, "copy overwrite")
	if _, r := e.do("alice", "GET", "/v1/secrets/value"+q("project", "pay", "env", "staging", "path", "/", "key", "B"), nil); r["value"] != "b1" {
		t.Fatalf("overwritten value = %v", r["value"])
	}

	// Into an approval environment: change requests instead.
	e.do("carol", "POST", "/v1/change-requests/policies", map[string]any{"project": "pay", "env": "prod", "approvalsRequired": 1})
	c, b = e.do("alice", "POST", "/v1/secrets/bulk", map[string]any{"project": "pay", "env": "dev", "path": "/", "keys": []string{"A", "B"}, "action": "copy", "targetEnv": "prod", "targetPath": "/"})
	e.want(c, 200, b, "copy into approval env")
	if b["applied"] != float64(0) || len(b["changeRequests"].([]any)) != 2 {
		t.Fatalf("copy into approval env = %v", b)
	}

	// Move keeps history.
	e.put("alice", "dev", "/", "A", "a2")
	c, b = e.do("alice", "POST", "/v1/secrets/bulk", map[string]any{"project": "pay", "env": "dev", "path": "/", "keys": []string{"A"}, "action": "move", "targetPath": "/moved"})
	e.want(c, 200, b, "move")
	if b["applied"] != float64(1) {
		t.Fatalf("move = %v", b)
	}
	_, r := e.do("alice", "GET", "/v1/secrets/versions"+q("project", "pay", "env", "dev", "path", "/moved", "key", "A"), nil)
	if len(r["versions"].([]any)) != 2 {
		t.Fatalf("history after move = %v", r)
	}
	// Cross-account: B moving A's key finds nothing.
	c, b = e.do("mallory", "POST", "/v1/secrets/bulk", map[string]any{"project": "pay", "env": "dev", "path": "/", "keys": []string{"B"}, "action": "move", "targetPath": "/stolen"})
	e.want(c, 200, b, "account B move")
	if b["applied"] != float64(0) {
		t.Fatal("account B moved account A's secret")
	}
}

func TestParameterEditEndpoints(t *testing.T) {
	e := newSecretsTestEnv(t)
	c, b := e.do("alice", "POST", "/v1/parameters", map[string]any{"name": "/app/url", "type": "String", "value": "http://a"})
	e.want(c, 200, b, "create")
	c, b = e.do("alice", "POST", "/v1/parameters", map[string]any{"name": "/app/key", "type": "SecureString", "value": "topsecret"})
	e.want(c, 200, b, "create secure")

	c, b = e.do("victor", "GET", "/v1/parameters", nil)
	e.want(c, 200, b, "list")
	for _, raw := range b["parameters"].([]any) {
		p := raw.(map[string]any)
		switch p["name"] {
		case "/app/url":
			if p["value"] != "http://a" {
				t.Fatalf("String value not listed: %v", p)
			}
		case "/app/key":
			if _, ok := p["value"]; ok {
				t.Fatal("SecureString value listed")
			}
		}
	}

	upd := map[string]any{"name": "/app/url", "expectedVersion": 1, "value": "http://b", "description": "d"}
	c, b = e.do("victor", "POST", "/v1/parameters/update", upd)
	e.want(c, 403, b, "viewer update")
	c, b = e.do("alice", "POST", "/v1/parameters/update", map[string]any{"name": "/app/url"})
	e.want(c, 400, b, "missing expectedVersion")
	c, b = e.do("alice", "POST", "/v1/parameters/update", upd)
	e.want(c, 200, b, "update")
	if b["parameter"].(map[string]any)["version"] != float64(2) {
		t.Fatalf("update = %v", b)
	}
	c, b = e.do("bob", "POST", "/v1/parameters/update", upd)
	e.want(c, 409, b, "stale update")
	if b["error"] != "version_conflict" {
		t.Fatalf("error = %v", b["error"])
	}
	c, b = e.do("mallory", "POST", "/v1/parameters/update", upd)
	e.want(c, 404, b, "cross-account update")

	// Type change without value keeps (and encrypts) the current value.
	c, b = e.do("alice", "POST", "/v1/parameters/update", map[string]any{"name": "/app/url", "expectedVersion": 2, "type": "SecureString"})
	e.want(c, 200, b, "type change")
	c, b = e.do("alice", "GET", "/v1/parameters/value"+q("name", "/app/url"), nil)
	e.want(c, 200, b, "reveal latest")
	if b["value"] != "http://b" {
		t.Fatalf("value after type change = %v", b["value"])
	}
	c, b = e.do("victor", "GET", "/v1/parameters/value"+q("name", "/app/url"), nil)
	e.want(c, 403, b, "viewer reveals SecureString")
	c, b = e.do("victor", "GET", "/v1/parameters/value"+q("name", "/app/url", "version", "1"), nil)
	e.want(c, 200, b, "viewer reveals old String version")
	if b["value"] != "http://a" {
		t.Fatalf("version 1 value = %v", b["value"])
	}
	c, b = e.do("alice", "GET", "/v1/parameters/value"+q("name", "/app/url", "version", "9"), nil)
	e.want(c, 404, b, "missing version")
	c, b = e.do("alice", "GET", "/v1/parameters/value"+q("name", "/app/url", "version", "x"), nil)
	e.want(c, 400, b, "bad version")

	e.do("alice", "POST", "/v1/parameters/label", map[string]any{"name": "/app/url", "version": 1, "labels": []string{"stable", "old"}})
	c, b = e.do("victor", "DELETE", "/v1/parameters/label"+q("name", "/app/url", "version", "1", "labels", "old"), nil)
	e.want(c, 403, b, "viewer unlabel")
	c, b = e.do("alice", "DELETE", "/v1/parameters/label"+q("name", "/app/url", "version", "1"), nil)
	e.want(c, 400, b, "unlabel without labels")
	c, b = e.do("alice", "DELETE", "/v1/parameters/label"+q("name", "/app/url", "version", "1", "labels", "old,nope"), nil)
	e.want(c, 200, b, "unlabel")
	if r := b["removed"].([]any); len(r) != 1 || r[0] != "old" {
		t.Fatalf("removed = %v", b["removed"])
	}
	c, b = e.do("mallory", "DELETE", "/v1/parameters/label"+q("name", "/app/url", "version", "1", "labels", "stable"), nil)
	e.want(c, 404, b, "cross-account unlabel")
}

func TestAWSWritesRespectApprovalPolicy(t *testing.T) {
	e := newSecretsTestEnv(t)
	e.put("alice", "prod", "/", "DB", "v1")
	ctxA := store.WithCallerAccount(t.Context(), tAcctA)
	if err := e.st.PutApprovalPolicy(ctxA, store.ApprovalPolicy{Project: "pay", Env: "prod", ApprovalsRequired: 1}); err != nil {
		t.Fatal(err)
	}
	if !e.s.awsWriteNeedsApproval(ctxA, "pay/prod/DB") {
		t.Fatal("pay/prod/DB should need approval")
	}
	if e.s.awsWriteNeedsApproval(ctxA, "pay/dev/DB") || e.s.awsWriteNeedsApproval(ctxA, "not-a-native-name") {
		t.Fatal("ungated names reported as gated")
	}
	if e.s.awsWriteNeedsApproval(store.WithCallerAccount(t.Context(), tAcctB), "pay/prod/DB") {
		t.Fatal("account A's policy gates account B")
	}
}

func TestPurgeExpiredSecretsJob(t *testing.T) {
	e := newSecretsTestEnv(t)
	e.put("alice", "dev", "/", "OLD", "x")
	e.put("alice", "dev", "/", "KEEP", "y")
	c, b := e.do("alice", "DELETE", "/v1/secrets"+q("project", "pay", "env", "dev", "path", "/", "key", "OLD", "recoveryWindowDays", "7"), nil)
	e.want(c, 200, b, "schedule deletion")
	if n := e.s.purgeExpiredSecrets(t.Context(), time.Now().UTC()); n != 0 {
		t.Fatalf("purged %d before the deletion date", n)
	}
	if n := e.s.purgeExpiredSecrets(t.Context(), time.Now().UTC().Add(8*24*time.Hour)); n != 1 {
		t.Fatalf("purged %d, want 1", n)
	}
	_, b = e.do("alice", "GET", "/v1/secrets"+q("project", "pay", "env", "dev", "path", "/"), nil)
	if items := b["items"].([]any); len(items) != 1 || items[0].(map[string]any)["key"] != "KEEP" {
		t.Fatalf("items after purge = %v", items)
	}
	if err := e.s.purgeExpiredSecretsJob(t.Context()); err != nil {
		t.Fatal(err)
	}
}
