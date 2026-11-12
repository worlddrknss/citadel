package server

import (
	"testing"

	"github.com/worlddrknss/citadel/internal/store"
)

func TestApprovalBlockerUsesThePersonBehindTokens(t *testing.T) {
	cr := store.ChangeRequestRecord{Status: store.ChangeRequestPending, Requester: "alice"}
	policy := store.ApprovalPolicy{ApprovalsRequired: 2, ApproverRoles: []string{"admin"}}

	// Alice's own access key: its Username is the key ID, but it is still Alice.
	token := &uiSession{Username: "AKIAALICEKEY00000000", Owner: "alice", Role: "admin", ViaToken: true}
	if got := token.Principal(); got != "alice" {
		t.Fatalf("token principal = %q, want alice", got)
	}
	if approvalBlocker(token, cr, policy) == "" {
		t.Fatal("a requester's own access key was allowed to approve")
	}

	// Any access key is refused: approvals are a human control.
	other := &uiSession{Username: "AKIABOBKEY0000000000", Owner: "bob", Role: "admin", ViaToken: true}
	if approvalBlocker(other, cr, policy) == "" {
		t.Fatal("an access key was allowed to approve")
	}

	// Bob signed in can approve once; a second approval from Bob doesn't count.
	bob := &uiSession{Username: "bob", Role: "admin"}
	if reason := approvalBlocker(bob, cr, policy); reason != "" {
		t.Fatalf("bob blocked: %s", reason)
	}
	cr.Approvals = []store.ChangeRequestApproval{{Username: "bob"}}
	if approvalBlocker(bob, cr, policy) == "" {
		t.Fatal("bob approved twice")
	}
}
