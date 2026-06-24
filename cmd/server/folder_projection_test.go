package main

import (
	"context"
	"encoding/json"
	"testing"
)

// TestFolderJSONProjection verifies the P4 dual projection: a folder coordinate
// resolves to a JSON object of every key directly within it, while individual
// keys remain independently retrievable.
func TestFolderJSONProjection(t *testing.T) {
	store := newTenantTestStore()
	svc := newSecretsService(store)
	ctx := withCallerAccount(context.Background(), "111111111111")

	put := func(folder []string, key, val string) {
		if _, err := svc.PutItem(ctx, itemCoord{Project: "payments", Env: "prod", Folder: folder, Key: key}, val, ""); err != nil {
			t.Fatalf("PutItem %s: %v", key, err)
		}
	}
	put([]string{"db"}, "USERNAME", "admin")
	put([]string{"db"}, "PASSWORD", "s3cr3t")
	put([]string{"db", "replica"}, "PASSWORD", "nested")

	// Folder projection returns only the keys directly in payments/prod/db.
	values, ok, err := svc.FolderJSONByName(ctx, "payments/prod/db")
	if err != nil || !ok {
		t.Fatalf("FolderJSONByName: ok=%v err=%v", ok, err)
	}
	if len(values) != 2 || values["USERNAME"] != "admin" || values["PASSWORD"] != "s3cr3t" {
		t.Fatalf("unexpected folder JSON: %+v", values)
	}

	// It must serialize to a stable JSON object usable by AWS-shaped clients.
	if _, err := json.Marshal(values); err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Individual key projection still works.
	rec, err := svc.RevealItem(ctx, itemCoord{Project: "payments", Env: "prod", Folder: []string{"db"}, Key: "PASSWORD"}, "", "")
	if err != nil {
		t.Fatalf("RevealItem: %v", err)
	}
	if rec.SecretString == nil || *rec.SecretString != "s3cr3t" {
		t.Fatalf("unexpected key value: %+v", rec.SecretString)
	}

	// A non-folder name returns ok=false (no items directly within).
	if _, ok, _ := svc.FolderJSONByName(ctx, "payments/prod/db/PASSWORD"); ok {
		t.Fatalf("expected leaf-key name to not be a folder")
	}
}
