package main

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

// newTenantTestStore returns an in-memory store wired with a usable default KMS
// key so secret values can be envelope-encrypted during the test.
func newTenantTestStore() *inMemoryStore {
	k := kmsKey{
		ID:           "go-kms-default-key",
		ARN:          "arn:aws:kms:local:000000000000:key/go-kms-default-key",
		MasterKeyRaw: bytes.Repeat([]byte{7}, 32),
		Description:  "tenant test key",
		CreatedAt:    time.Unix(1, 0).UTC(),
		Enabled:      true,
	}
	return &inMemoryStore{k: k, accountID: "000000000000"}
}

// TestSecretsPerAccountIsolation asserts the P1 multi-tenant guarantee: two
// distinct accounts can hold a secret with the identical name without
// colliding, and neither account can read, overwrite, or delete the other's
// value.
func TestSecretsPerAccountIsolation(t *testing.T) {
	store := newTenantTestStore()

	const acctA = "111111111111"
	const acctB = "222222222222"
	ctxA := withCallerAccount(context.Background(), acctA)
	ctxB := withCallerAccount(context.Background(), acctB)

	const name = "payments/prod/db/PASSWORD"

	// Both accounts create the same logical name — no collision.
	if _, _, err := store.CreateSecret(ctxA, createSecretRequest{Name: name, SecretString: "secret-A"}); err != nil {
		t.Fatalf("account A create: %v", err)
	}
	if _, _, err := store.CreateSecret(ctxB, createSecretRequest{Name: name, SecretString: "secret-B"}); err != nil {
		t.Fatalf("account B create (same name must not collide): %v", err)
	}

	// Each account reads back exactly its own value.
	valA, err := store.GetSecretValue(ctxA, name, "", "")
	if err != nil {
		t.Fatalf("account A get: %v", err)
	}
	if valA.SecretString == nil || *valA.SecretString != "secret-A" {
		t.Fatalf("account A read wrong value: %+v", valA.SecretString)
	}
	valB, err := store.GetSecretValue(ctxB, name, "", "")
	if err != nil {
		t.Fatalf("account B get: %v", err)
	}
	if valB.SecretString == nil || *valB.SecretString != "secret-B" {
		t.Fatalf("account B read wrong value: %+v", valB.SecretString)
	}

	// ARNs must differ by account so resources stay globally distinct.
	if valA.ARN == valB.ARN {
		t.Fatalf("expected distinct ARNs per account, both = %s", valA.ARN)
	}

	// ListSecrets is account-scoped: each account sees exactly one secret.
	listA, err := store.ListSecrets(ctxA)
	if err != nil {
		t.Fatalf("account A list: %v", err)
	}
	if len(listA) != 1 || listA[0].Name != name {
		t.Fatalf("account A list expected exactly its own secret, got %+v", listA)
	}

	// Account B overwriting "its" secret must not affect account A's value.
	if _, err := store.PutSecretValue(ctxB, putSecretValueRequest{SecretID: name, SecretString: "secret-B2"}); err != nil {
		t.Fatalf("account B put: %v", err)
	}
	valA2, err := store.GetSecretValue(ctxA, name, "", "")
	if err != nil {
		t.Fatalf("account A re-get: %v", err)
	}
	if valA2.SecretString == nil || *valA2.SecretString != "secret-A" {
		t.Fatalf("account A value leaked/changed after B wrote: %+v", valA2.SecretString)
	}

	// Account B deleting "its" secret must leave account A's intact.
	if _, err := store.DeleteSecret(ctxB, name, 0, true); err != nil {
		t.Fatalf("account B delete: %v", err)
	}
	if _, err := store.GetSecretValue(ctxA, name, "", ""); err != nil {
		t.Fatalf("account A secret must survive account B deletion: %v", err)
	}
}

// TestSecretsDeploymentFallbackAccount verifies that requests without an
// authenticated caller account fall back to the deployment account, preserving
// single-tenant behaviour for the admin UI and non-strict callers.
func TestSecretsDeploymentFallbackAccount(t *testing.T) {
	store := newTenantTestStore()
	ctx := context.Background() // no caller account attached

	const name = "shared/dev/app/TOKEN"
	if _, _, err := store.CreateSecret(ctx, createSecretRequest{Name: name, SecretString: "v1"}); err != nil {
		t.Fatalf("create without caller account: %v", err)
	}

	// A second create of the same name under the same (deployment) account must
	// collide, proving both requests resolved to the same tenant.
	if _, _, err := store.CreateSecret(ctx, createSecretRequest{Name: name, SecretString: "v2"}); !errors.Is(err, errSecretExists) {
		t.Fatalf("expected errSecretExists on duplicate create, got %v", err)
	}

	// The deployment-account caller can read it back.
	val, err := store.GetSecretValue(ctx, name, "", "")
	if err != nil {
		t.Fatalf("get without caller account: %v", err)
	}
	if val.SecretString == nil || *val.SecretString != "v1" {
		t.Fatalf("unexpected value: %+v", val.SecretString)
	}
}
