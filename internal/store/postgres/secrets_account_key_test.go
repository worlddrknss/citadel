package postgres

import (
	"context"
	"testing"

	"github.com/worlddrknss/citadel/internal/store"
)

// TestSecretAccountKeyMigration builds the schema as it was before 0300 (name
// as sm_secrets' primary key), stores a secret with a version, tag, stage and
// policy the way that schema did, then migrates and checks the secret is
// intact and now keyed per account.
func TestSecretAccountKeyMigration(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	ms, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		if m.version >= 300 {
			break
		}
		if _, err := db.ExecContext(ctx, m.sql); err != nil {
			t.Fatalf("apply %04d: %v", m.version, err)
		}
	}
	const acct = "333333333333"
	actx := store.WithCallerAccount(ctx, acct)
	legacy := New(db, testOptions())
	key, err := legacy.CreateKey(actx, "legacy", store.KeyUsageEncryptDecrypt, store.KeySpecSymmetricDefault)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	_, blob, _, err := store.BuildSecretCiphertext(actx, legacy.ResolveByID, legacy.ResolveDefault, key.ID, "legacy-value", "")
	if err != nil {
		t.Fatal(err)
	}
	const name = "app/prod/LEGACY"
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO sm_secrets (name, arn, kms_key_id, current_version_id, account_id) VALUES ($1, $2, $3, 'v1', $4)`, []any{name, "arn:aws:secretsmanager:us-west-2:" + acct + ":secret:" + name, key.ID, acct}},
		{`INSERT INTO sm_secret_versions (secret_name, version_id, client_request_token, encrypted_payload_b64) VALUES ($1, 'v1', 'v1', $2)`, []any{name, blob}},
		{`INSERT INTO sm_secret_tags (secret_name, tag_key, tag_value) VALUES ($1, 'team', 'core')`, []any{name}},
		{`INSERT INTO sm_secret_version_stages (secret_name, version_id, stage_label) VALUES ($1, 'v1', 'AWSCURRENT')`, []any{name}},
		{`INSERT INTO sm_secret_policies (secret_name, policy_document) VALUES ($1, '{}')`, []any{name}},
	} {
		if _, err := db.ExecContext(ctx, q.sql, q.args...); err != nil {
			t.Fatalf("seed %q: %v", q.sql, err)
		}
	}

	st, err := Open(ctx, db, testOptions())
	if err != nil {
		t.Fatalf("Open (migrate): %v", err)
	}
	wantAllMigrations(t, db)
	meta, err := st.DescribeSecret(actx, name)
	if err != nil {
		t.Fatalf("DescribeSecret after migration: %v", err)
	}
	if len(meta.Tags) != 1 || meta.Tags[0].Value != "core" || meta.PolicyDocument != "{}" || meta.VersionCount != 1 {
		t.Fatalf("decorations lost: %+v", meta)
	}
	v, err := st.GetSecretValue(actx, name, "", "")
	if err != nil || v.SecretString == nil || *v.SecretString != "legacy-value" {
		t.Fatalf("GetSecretValue after migration = %v, %v", v.SecretString, err)
	}
	// Re-running the migration body is a no-op.
	for _, m := range ms {
		if m.version == 300 {
			if _, err := db.ExecContext(ctx, m.sql); err != nil {
				t.Fatalf("re-run 0300: %v", err)
			}
		}
	}
	// The same name is now free in another account.
	bctx := store.WithCallerAccount(ctx, "444444444444")
	keyB, err := st.CreateKey(bctx, "b", store.KeyUsageEncryptDecrypt, store.KeySpecSymmetricDefault)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.CreateSecret(bctx, store.CreateSecretRequest{Name: name, KMSKeyID: keyB.ID, SecretString: "b"}); err != nil {
		t.Fatalf("CreateSecret in other account: %v", err)
	}
}
