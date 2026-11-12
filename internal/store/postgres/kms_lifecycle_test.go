package postgres

import (
	"bytes"
	"context"
	"testing"

	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/storetest"
)

func TestKMSLifecycle(t *testing.T) {
	db := testDB(t)
	st, err := Open(context.Background(), db, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	storetest.KMSLifecycle(t, st)
}

// TestDestroyKeyReferencedBySecret: deletion proceeds (as in AWS) even
// though a secret's foreign key references the key; the row stays as a
// tombstone with its material wiped.
func TestDestroyKeyReferencedBySecret(t *testing.T) {
	db := testDB(t)
	st, err := Open(context.Background(), db, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	ctx := store.WithCallerAccount(context.Background(), storetest.AccountA)
	k, err := st.CreateKey(ctx, "", store.KeyUsageEncryptDecrypt, store.KeySpecSymmetricDefault)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.CreateSecret(ctx, store.CreateSecretRequest{Name: "uses/key", SecretString: "v", KMSKeyID: k.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RotateKeyMaterial(ctx, k.ID, store.RotationKindOnDemand, k.CreatedAt); err != nil {
		t.Fatal(err)
	}
	if err := st.DestroyKey(ctx, k.ID); err != nil {
		t.Fatalf("DestroyKey: %v", err)
	}
	var wrapped, public string
	var deleted bool
	if err := db.QueryRow(`SELECT wrapped_key_b64, public_key_b64, deleted_at IS NOT NULL FROM kms_keys WHERE id = $1`, k.ID).Scan(&wrapped, &public, &deleted); err != nil {
		t.Fatal(err)
	}
	if wrapped != "" || public != "" || !deleted {
		t.Fatalf("tombstone not wiped: wrapped=%q deleted=%v", wrapped, deleted)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM kms_key_materials WHERE key_id = $1`, k.ID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("materials left: %d %v", n, err)
	}
	if _, err := st.GetSecretValue(ctx, "uses/key", "", ""); err == nil {
		t.Fatal("secret under a destroyed key still decrypts")
	}
}

// TestRewrapAfterWrappingKeyRotation rotates the wrapping key: the store
// opened with the new key and the old one as "previous" still reads
// everything, RewrapAll moves every row onto the new key, and afterwards a
// store without the previous key reads it all.
func TestRewrapAfterWrappingKeyRotation(t *testing.T) {
	db := testDB(t)
	bg := context.Background()
	oldOpts := testOptions()
	old, err := Open(bg, db, oldOpts)
	if err != nil {
		t.Fatal(err)
	}
	ctx := store.WithCallerAccount(bg, storetest.AccountA)
	k, err := old.CreateKey(ctx, "", store.KeyUsageEncryptDecrypt, store.KeySpecSymmetricDefault)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.RotateKeyMaterial(ctx, k.ID, store.RotationKindOnDemand, k.CreatedAt); err != nil {
		t.Fatal(err)
	}
	k, _ = old.ResolveByID(ctx, k.ID)
	blob, err := k.EncryptBlob([]byte("payload"), nil)
	if err != nil {
		t.Fatal(err)
	}

	newKey := bytes.Repeat([]byte{0x77}, 32)
	rotated := oldOpts
	rotated.WrappingKey = newKey
	rotated.PreviousWrappingKeys = [][]byte{oldOpts.WrappingKey}
	st := New(db, rotated)
	got, err := st.ResolveByID(ctx, k.ID)
	if err != nil {
		t.Fatalf("resolve with previous wrapping key: %v", err)
	}
	if pt, err := got.DecryptBlob(blob, nil); err != nil || string(pt) != "payload" {
		t.Fatalf("decrypt: %q %v", pt, err)
	}
	report, err := st.RewrapAll(bg)
	if err != nil {
		t.Fatal(err)
	}
	if report.Rewrapped < 2 || report.Failed != 0 {
		t.Fatalf("report %+v", report)
	}
	if again, _ := st.RewrapAll(bg); again.Rewrapped != 0 {
		t.Fatalf("second pass rewrapped %d", again.Rewrapped)
	}

	only := oldOpts
	only.WrappingKey = newKey
	fresh := New(db, only)
	got, err = fresh.ResolveByID(ctx, k.ID)
	if err != nil {
		t.Fatalf("resolve without previous key after rewrap: %v", err)
	}
	if pt, err := got.DecryptBlob(blob, nil); err != nil || string(pt) != "payload" {
		t.Fatalf("decrypt after rewrap: %q %v", pt, err)
	}
	// The old key alone no longer opens anything.
	if _, err := New(db, oldOpts).ResolveByID(ctx, k.ID); err == nil {
		t.Fatal("old wrapping key still opens re-wrapped material")
	}
}

// TestKMSTenancyBackfill: grants and policies written before 0401 have no
// account; re-running the backfill assigns the owning key's account.
func TestKMSTenancyBackfill(t *testing.T) {
	db := testDB(t)
	st, err := Open(context.Background(), db, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	ctx := store.WithCallerAccount(context.Background(), storetest.AccountA)
	k, err := st.CreateKey(ctx, "", store.KeyUsageEncryptDecrypt, store.KeySpecSymmetricDefault)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO kms_grants (grant_id, grant_token, key_id, grantee_principal, operations_json) VALUES ('g-old', 't-old', $1, 'arn:aws:iam::111111111111:user/a', '["Encrypt"]')`, k.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO kms_key_policies (key_id, policy_name, policy_document) VALUES ($1, 'default', '{}')`, k.ID); err != nil {
		t.Fatal(err)
	}
	ms, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		if m.version == 401 {
			if _, err := db.Exec(m.sql); err != nil {
				t.Fatalf("re-run 0401: %v", err)
			}
		}
	}
	gs, err := st.ListGrants(ctx, k.ID)
	if err != nil || len(gs) != 1 {
		t.Fatalf("backfilled grant not visible to its account: %+v %v", gs, err)
	}
	other := store.WithCallerAccount(context.Background(), storetest.AccountB)
	if gs, _ := st.ListGrants(other, k.ID); len(gs) != 0 {
		t.Fatalf("backfilled grant visible to another account: %+v", gs)
	}
	if doc, err := st.GetKeyPolicy(ctx, k.ID, "default"); err != nil || doc != "{}" {
		t.Fatalf("backfilled policy: %q %v", doc, err)
	}
}
