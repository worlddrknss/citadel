package server

import (
	"testing"

	"github.com/worlddrknss/citadel/internal/store"
)

func TestOrgApprovalDefaults(t *testing.T) {
	e := newSecretsTestEnv(t)
	e.put("alice", "prod", "/", "DB", "v1")
	if err := e.st.PutOrgSettings(t.Context(), store.OrgSettings{ApprovalEnvironments: []string{"prod"}, ApprovalMinApprovers: 2, AllowSelfApproval: true}); err != nil {
		t.Fatal(err)
	}
	e.s.invalidateOrgSettings()
	c, b := e.put("alice", "prod", "/", "DB", "v2")
	e.want(c, 409, b, "write into org approval env")
	c, b = e.do("victor", "GET", "/v1/change-requests/policies", nil)
	e.want(c, 200, b, "policies")
	pol := b["policies"].([]any)
	if len(pol) != 1 || pol[0].(map[string]any)["source"] != "organization" || pol[0].(map[string]any)["approvalsRequired"] != float64(2) {
		t.Fatalf("policies = %v", pol)
	}
	// allowSelfApproval is ignored: the requester still cannot approve.
	_, b = e.do("carol", "POST", "/v1/change-requests", map[string]any{"project": "pay", "env": "prod", "path": "/", "key": "DB", "value": "v2"})
	id := b["id"]
	c, b = e.do("carol", "POST", "/v1/change-requests/approve", map[string]any{"id": id})
	e.want(c, 403, b, "self approval with allowSelfApproval set")
	// A project policy overrides the org default.
	e.do("carol", "POST", "/v1/change-requests/policies", map[string]any{"project": "pay", "env": "prod", "approvalsRequired": 1, "approverRoles": []string{"editor"}})
	c, b = e.do("bob", "POST", "/v1/change-requests/approve", map[string]any{"id": id})
	e.want(c, 200, b, "editor approves under project policy")
	if b["applied"] != true {
		t.Fatalf("approve = %v", b)
	}
	c, b = e.put("alice", "dev", "/", "DB", "x")
	e.want(c, 200, b, "write to dev")
}
