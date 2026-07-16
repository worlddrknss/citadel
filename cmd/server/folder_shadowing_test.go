package main

import (
	"context"
	"testing"
)

// A folder and an item share one namespace: "payments/prod/db/PASSWORD" is an
// item, and "payments/prod/db" is the JSON projection of everything in that
// folder. GetSecretValue only computes the projection when no stored secret
// answers to that name, so a stored object at a folder's name replaces a live
// view with a frozen copy — and until now the console couldn't show it, because
// listings enumerate a folder's children and this thing IS the folder's name.
//
// That is not hypothetical. d76riders/prod held such an object. ESO extracted it
// and got a copy of the environment as it stood on 2026-07-13, so
// EMERGENCY_MASTER_KEY — added later, present in the folder — never reached the
// cluster, and emergency cards refused every request for five days behind a green
// Ready=True.

func TestListFolderSurfacesShadowingObject(t *testing.T) {
	store := newTenantTestStore()
	svc := newSecretsService(store)
	ctx := withCallerAccount(context.Background(), "111111111111")

	if _, err := svc.PutItem(ctx, itemCoord{Project: "payments", Env: "prod", Key: "DATABASE_URL"}, "postgres://", ""); err != nil {
		t.Fatalf("PutItem: %v", err)
	}

	// Nothing is shadowing payments/prod yet.
	_, items, shadowed, err := svc.ListFolder(ctx, "payments", "prod", nil)
	if err != nil {
		t.Fatalf("ListFolder: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if len(shadowed) != 0 {
		t.Fatalf("expected nothing shadowing, got %+v", shadowed)
	}

	// Create the object at the folder's own name, the way the legacy blob exists.
	if _, _, err := store.CreateSecret(ctx, createSecretRequest{
		Name:         "payments/prod",
		SecretString: `{"DATABASE_URL":"stale"}`,
	}); err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}

	_, items, shadowed, err = svc.ListFolder(ctx, "payments", "prod", nil)
	if err != nil {
		t.Fatalf("ListFolder: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("items should be unchanged, got %d", len(items))
	}
	if len(shadowed) != 1 {
		t.Fatalf("the shadowing object must be visible, got %+v", shadowed)
	}
	if shadowed[0].Key != "" {
		t.Fatalf("a shadowing object has no key, got %q", shadowed[0].Key)
	}
	if shadowed[0].Path != "/" {
		t.Fatalf("path = %q, want /", shadowed[0].Path)
	}
}

func TestNameShadowsFolderRejectsFolderNames(t *testing.T) {
	store := newTenantTestStore()
	svc := newSecretsService(store)
	ctx := withCallerAccount(context.Background(), "111111111111")

	if _, err := svc.PutItem(ctx, itemCoord{Project: "payments", Env: "prod", Folder: []string{"db"}, Key: "PASSWORD"}, "s3cr3t", ""); err != nil {
		t.Fatalf("PutItem: %v", err)
	}

	cases := []struct {
		name string
		want bool
	}{
		// Holds items, so storing here would shadow the projection.
		{"payments/prod/db", true},
		// A leaf key, not a folder.
		{"payments/prod/db/PASSWORD", false},
		// An empty folder shadows nothing: there is no projection to lose.
		{"payments/prod/cache", false},
		// Not a project/env shape at all.
		{"payments", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := svc.NameShadowsFolder(ctx, tc.name)
			if err != nil {
				t.Fatalf("NameShadowsFolder: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

// The projection is only served when no stored secret answers to the name, so a
// shadowing object silently freezes the folder. This is the failure d76riders hit.
func TestShadowingObjectHidesTheLiveProjection(t *testing.T) {
	store := newTenantTestStore()
	svc := newSecretsService(store)
	ctx := withCallerAccount(context.Background(), "111111111111")

	if _, err := svc.PutItem(ctx, itemCoord{Project: "payments", Env: "prod", Key: "DATABASE_URL"}, "postgres://", ""); err != nil {
		t.Fatalf("PutItem: %v", err)
	}
	if _, err := svc.PutItem(ctx, itemCoord{Project: "payments", Env: "prod", Key: "EMERGENCY_MASTER_KEY"}, "kek", ""); err != nil {
		t.Fatalf("PutItem: %v", err)
	}

	values, ok, err := svc.FolderJSONByName(ctx, "payments/prod")
	if err != nil || !ok {
		t.Fatalf("FolderJSONByName: ok=%v err=%v", ok, err)
	}
	if len(values) != 2 {
		t.Fatalf("the live projection should hold both keys, got %v", values)
	}

	// DeleteShadowing must clear the object that no item coordinate can name.
	if _, _, err := store.CreateSecret(ctx, createSecretRequest{
		Name:         "payments/prod",
		SecretString: `{"DATABASE_URL":"stale"}`,
	}); err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	if err := svc.DeleteShadowing(ctx, "payments", "prod", nil, 0, true); err != nil {
		t.Fatalf("DeleteShadowing: %v", err)
	}
	_, _, shadowed, err := svc.ListFolder(ctx, "payments", "prod", nil)
	if err != nil {
		t.Fatalf("ListFolder: %v", err)
	}
	if len(shadowed) != 0 {
		t.Fatalf("the shadowing object should be gone, got %+v", shadowed)
	}
}
