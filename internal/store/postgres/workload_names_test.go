package postgres

import (
	"context"
	"testing"
)

// TestMigrationRenamesDuplicateWorkloadClientNames: databases from before
// 0900 may hold clients sharing a name in one account. The migration keeps
// the oldest name, suffixes the others, and then enforces uniqueness.
func TestMigrationRenamesDuplicateWorkloadClientNames(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	// Roll back to before 0900.
	for _, q := range []string{
		`DROP INDEX workload_clients_account_name_uniq`,
		`DELETE FROM schema_migrations WHERE version = 900`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	insert := func(id, acct, name string, age int) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `INSERT INTO workload_clients (client_id, account_id, name, token_ttl_seconds, subject_format, auth_method, created_at, updated_at)
VALUES ($1, $2, $3, 900, 'x', 'access-key', NOW() - make_interval(hours => $4), NOW())`, id, acct, name, age); err != nil {
			t.Fatal(err)
		}
	}
	insert("wic-aaaaaaaaaaaaaaaa0001", "111111111111", "deploy", 3)
	insert("wic-aaaaaaaaaaaaaaaa0002", "111111111111", "Deploy", 2)
	insert("wic-aaaaaaaaaaaaaaaa0003", "111111111111", "deploy", 1)
	insert("wic-aaaaaaaaaaaaaaaa0004", "222222222222", "deploy", 1)

	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	want := map[string]string{
		"wic-aaaaaaaaaaaaaaaa0001": "deploy",
		"wic-aaaaaaaaaaaaaaaa0002": "Deploy-aaaa0002",
		"wic-aaaaaaaaaaaaaaaa0003": "deploy-aaaa0003",
		"wic-aaaaaaaaaaaaaaaa0004": "deploy",
	}
	for id, name := range want {
		var got string
		if err := db.QueryRowContext(ctx, `SELECT name FROM workload_clients WHERE client_id = $1`, id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != name {
			t.Errorf("%s name = %q, want %q", id, got, name)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO workload_clients (client_id, account_id, name, token_ttl_seconds, subject_format, auth_method, created_at, updated_at)
VALUES ('wic-new', '111111111111', 'DEPLOY', 900, 'x', 'access-key', NOW(), NOW())`); err == nil {
		t.Fatal("duplicate name accepted after the migration")
	}
}
