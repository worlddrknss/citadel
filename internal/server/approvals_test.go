package server

import (
	"context"
	"testing"

	"github.com/worlddrknss/citadel/internal/store"
)

// TestSecretReferenceResolution verifies P8 ${KEY} and ${/abs/path/KEY}
// expansion at reveal time, including a nested reference.
func TestSecretReferenceResolution(t *testing.T) {
	st := newTenantTestStore()
	svc := newSecretsService(st)
	ctx := store.WithCallerAccount(context.Background(), "111111111111")

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
