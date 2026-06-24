package main

import (
	"context"
	"testing"
)

// TestSecretReferenceResolution verifies P8 ${KEY} and ${/abs/path/KEY}
// expansion at reveal time, including a nested reference.
func TestSecretReferenceResolution(t *testing.T) {
	store := newTenantTestStore()
	svc := newSecretsService(store)
	ctx := withCallerAccount(context.Background(), "111111111111")

	put := func(folder []string, key, val string) {
		if _, err := svc.PutItem(ctx, itemCoord{Project: "app", Env: "prod", Folder: folder, Key: key}, val, ""); err != nil {
			t.Fatalf("PutItem %s: %v", key, err)
		}
	}
	put(nil, "HOST", "db.internal")
	put([]string{"db"}, "PORT", "5432")
	// Same-folder ref (${HOST}) and absolute ref (${/db/PORT}).
	put(nil, "URL", "postgres://${HOST}:${/db/PORT}/main")

	// Without resolution, the raw template is returned.
	raw, err := svc.RevealItem(ctx, itemCoord{Project: "app", Env: "prod", Key: "URL"}, "", "")
	if err != nil {
		t.Fatalf("RevealItem: %v", err)
	}
	if raw.SecretString == nil || *raw.SecretString != "postgres://${HOST}:${/db/PORT}/main" {
		t.Fatalf("unexpected raw value: %v", raw.SecretString)
	}

	// With resolution, both references expand.
	resolved, err := svc.RevealItemResolved(ctx, itemCoord{Project: "app", Env: "prod", Key: "URL"}, "", "")
	if err != nil {
		t.Fatalf("RevealItemResolved: %v", err)
	}
	if resolved.SecretString == nil || *resolved.SecretString != "postgres://db.internal:5432/main" {
		t.Fatalf("unexpected resolved value: %v", resolved.SecretString)
	}

	// Unresolvable references are left intact rather than erroring.
	put(nil, "DANGLING", "x=${MISSING}")
	d, err := svc.RevealItemResolved(ctx, itemCoord{Project: "app", Env: "prod", Key: "DANGLING"}, "", "")
	if err != nil {
		t.Fatalf("RevealItemResolved dangling: %v", err)
	}
	if d.SecretString == nil || *d.SecretString != "x=${MISSING}" {
		t.Fatalf("unexpected dangling value: %v", d.SecretString)
	}
}

// TestApprovalWorkflow verifies the P8 change-request lifecycle: a pending
// request does not change the value until approved, and approval applies it.
func TestApprovalWorkflow(t *testing.T) {
	store := newTenantTestStore()
	svc := newSecretsService(store)
	ctx := withCallerAccount(context.Background(), "111111111111")
	coord := itemCoord{Project: "app", Env: "prod", Key: "API_KEY"}

	if _, err := svc.PutItem(ctx, coord, "old", ""); err != nil {
		t.Fatalf("seed PutItem: %v", err)
	}

	cr, err := svc.CreateChangeRequest(ctx, coord, "new", "", "alice")
	if err != nil {
		t.Fatalf("CreateChangeRequest: %v", err)
	}
	if cr.Status != changeRequestPending {
		t.Fatalf("expected pending, got %s", cr.Status)
	}

	// Value unchanged while pending.
	cur, _ := svc.RevealItem(ctx, coord, "", "")
	if cur.SecretString == nil || *cur.SecretString != "old" {
		t.Fatalf("value changed before approval: %v", cur.SecretString)
	}

	// Listing shows the pending request for this account.
	if reqs := svc.ListChangeRequests(ctx); len(reqs) != 1 || reqs[0].Status != changeRequestPending {
		t.Fatalf("unexpected list: %+v", reqs)
	}

	if err := svc.ApproveChangeRequest(ctx, cr.ID, "bob"); err != nil {
		t.Fatalf("ApproveChangeRequest: %v", err)
	}

	// Value now applied.
	after, _ := svc.RevealItem(ctx, coord, "", "")
	if after.SecretString == nil || *after.SecretString != "new" {
		t.Fatalf("value not applied after approval: %v", after.SecretString)
	}

	// Re-approving a decided request fails.
	if err := svc.ApproveChangeRequest(ctx, cr.ID, "bob"); err == nil {
		t.Fatalf("expected error approving decided request")
	}

	// Another account cannot see or decide this request.
	otherCtx := withCallerAccount(context.Background(), "222222222222")
	if reqs := svc.ListChangeRequests(otherCtx); len(reqs) != 0 {
		t.Fatalf("cross-account leak: %+v", reqs)
	}
	if err := svc.RejectChangeRequest(otherCtx, cr.ID, "eve"); err != errChangeRequestNotFound {
		t.Fatalf("expected not-found for cross-account reject, got %v", err)
	}
}
