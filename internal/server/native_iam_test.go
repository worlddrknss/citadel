package server

import (
	"net/http"
	"testing"
)

func TestNativeIAMProviderLifecycle(t *testing.T) {
	e := newAuthEnv(t)
	alice := e.session("alice", e.acctA) // admin
	bob := e.session("bob", e.acctA)     // editor

	create := func(c *http.Cookie, url string, ids ...string) int {
		return e.do("POST", "/v1/iam/oidc-providers", map[string]any{"url": url, "clientIds": ids}, c).Code
	}
	if got := create(bob, "https://idp.example.com", "sts"); got != http.StatusForbidden {
		t.Fatalf("editor create: %d", got)
	}
	for _, bad := range []string{"foo", "http://idp.example.com", "https://", "https://u:p@idp.example.com", "https://idp.example.com?x=1"} {
		if got := create(alice, bad, "sts"); got != http.StatusBadRequest {
			t.Errorf("create %q: %d, want 400", bad, got)
		}
	}
	if got := create(alice, "https://idp.example.com", "sts"); got != http.StatusOK {
		t.Fatalf("create: %d", got)
	}
	if got := create(alice, "https://idp.example.com/", "other"); got != http.StatusConflict {
		t.Fatalf("duplicate create: %d, want 409", got)
	}
	arn := "arn:aws:iam::" + e.acctA + ":oidc-provider/idp.example.com"

	rec := e.do("POST", "/v1/iam/oidc-providers/update", map[string]any{"providerArn": arn, "clientIds": []string{"sts", "ci"}}, alice)
	wantStatus(t, rec, http.StatusOK)
	if !e.audited("citadel.UpdateOIDCProvider", "ok") {
		t.Fatal("update not audited")
	}
	body := decode(t, e.do("GET", "/v1/iam/oidc-providers", nil, alice))
	ids := body["providers"].([]any)[0].(map[string]any)["clientIds"].([]any)
	if len(ids) != 2 {
		t.Fatalf("clientIds after update: %v", ids)
	}
	wantStatus(t, e.do("POST", "/v1/iam/oidc-providers/update", map[string]any{"providerArn": arn + "x", "clientIds": []string{"a"}}, alice), http.StatusNotFound)
	wantStatus(t, e.do("POST", "/v1/iam/oidc-providers/update", map[string]any{"providerArn": arn, "clientIds": []string{}}, alice), http.StatusBadRequest)
	wantStatus(t, e.do("POST", "/v1/iam/oidc-providers/update", map[string]any{"providerArn": arn, "clientIds": []string{"a"}}, bob), http.StatusForbidden)

	wantStatus(t, e.do("DELETE", "/v1/iam/oidc-providers?providerArn="+arn, nil, alice), http.StatusOK)
	wantStatus(t, e.do("DELETE", "/v1/iam/oidc-providers?providerArn="+arn, nil, alice), http.StatusNotFound)
}

func TestNativeIAMRoleLifecycle(t *testing.T) {
	e := newAuthEnv(t)
	alice := e.session("alice", e.acctA)
	wantStatus(t, e.do("POST", "/v1/iam/oidc-providers", map[string]any{"url": "https://idp.example.com", "clientIds": []string{"sts"}}, alice), http.StatusOK)

	role := func(name string, trust map[string]any) map[string]any {
		return map[string]any{"roleName": name, "description": "d", "trust": trust, "maxSessionSeconds": 3600}
	}
	oidc := func(aud string, subs ...string) map[string]any {
		return map[string]any{"type": "oidc", "providerUrl": "https://idp.example.com", "audiences": []string{aud}, "subjects": subs}
	}
	wantStatus(t, e.do("POST", "/v1/iam/roles", role("deploy", oidc("sts", "repo:acme/*")), alice), http.StatusOK)
	wantStatus(t, e.do("POST", "/v1/iam/roles", role("deploy", oidc("sts", "repo:acme/*")), alice), http.StatusConflict)

	// Trust rules the console applies are enforced here too.
	for name, trust := range map[string]map[string]any{
		"bare wildcard":    oidc("sts", "*"),
		"inner wildcard":   oidc("sts", "repo:*/main"),
		"unknown audience": oidc("nope", "repo:acme/x"),
		"bad principal":    {"type": "account", "principals": []string{"12345"}},
		"oidc principals":  {"type": "oidc", "providerUrl": "https://idp.example.com", "audiences": []string{"sts"}, "subjects": []string{"a"}, "principals": []string{e.acctB}},
	} {
		if rec := e.do("POST", "/v1/iam/roles", role("r-"+name[:3], trust), alice); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, rec.Code)
		}
	}
	long := make([]byte, 65)
	for i := range long {
		long[i] = 'a'
	}
	wantStatus(t, e.do("POST", "/v1/iam/roles", role(string(long), oidc("sts", "x")), alice), http.StatusBadRequest)

	upd := role("deploy", map[string]any{"type": "account", "principals": []string{e.acctB}})
	upd["description"] = "changed"
	wantStatus(t, e.do("POST", "/v1/iam/roles/update", upd, alice), http.StatusOK)
	if !e.audited("citadel.UpdateRole", "ok") {
		t.Fatal("update not audited")
	}
	roles := decode(t, e.do("GET", "/v1/iam/roles", nil, alice))["roles"].([]any)
	if got := roles[0].(map[string]any)["description"]; got != "changed" {
		t.Fatalf("description after update: %v", got)
	}
	wantStatus(t, e.do("POST", "/v1/iam/roles/update", role("missing", oidc("sts", "x")), alice), http.StatusNotFound)

	wantStatus(t, e.do("DELETE", "/v1/iam/roles?roleName=deploy", nil, alice), http.StatusOK)
	wantStatus(t, e.do("DELETE", "/v1/iam/roles?roleName=deploy", nil, alice), http.StatusNotFound)
}
