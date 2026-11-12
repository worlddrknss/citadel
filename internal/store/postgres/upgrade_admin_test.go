package postgres

import (
	"context"
	"testing"
)

// TestUpgradeKeepsExistingAdminsAsPlatformAdmins: before 2.0 every admin
// managed the whole deployment. After upgrading, those admins must be
// platform admins, or nobody could create accounts or change org settings.
func TestUpgradeKeepsExistingAdminsAsPlatformAdmins(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	ms, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	// A 1.x database: only the original schema, with an admin and an editor.
	if _, err := db.ExecContext(ctx, ms[0].sql); err != nil {
		t.Fatalf("legacy DDL: %v", err)
	}
	for _, u := range []struct{ name, role string }{{"ops-admin", "admin"}, {"dev", "editor"}} {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO ui_users (username, password_hash, role, display_name, accounts_json) VALUES ($1, 'x', $2, $1, '[]')`,
			u.name, u.role); err != nil {
			t.Fatalf("insert %s: %v", u.name, err)
		}
	}

	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	var adminFlag, editorFlag bool
	if err := db.QueryRowContext(ctx, `SELECT platform_admin FROM ui_users WHERE username = 'ops-admin'`).Scan(&adminFlag); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT platform_admin FROM ui_users WHERE username = 'dev'`).Scan(&editorFlag); err != nil {
		t.Fatal(err)
	}
	if !adminFlag || editorFlag {
		t.Fatalf("platform_admin after upgrade: admin=%v editor=%v, want true/false", adminFlag, editorFlag)
	}

	// Re-running migrations must not promote admins created later.
	if _, err := db.ExecContext(ctx, `INSERT INTO ui_users (username, password_hash, role, display_name, accounts_json) VALUES ('acct-admin', 'x', 'admin', 'a', '[]')`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	var later bool
	if err := db.QueryRowContext(ctx, `SELECT platform_admin FROM ui_users WHERE username = 'acct-admin'`).Scan(&later); err != nil {
		t.Fatal(err)
	}
	if later {
		t.Fatal("an admin created after the upgrade was promoted to platform admin")
	}
}
