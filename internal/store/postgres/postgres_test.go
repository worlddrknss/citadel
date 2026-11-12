package postgres

// Tests against a real PostgreSQL server. They run only when
// CITADEL_TEST_DB_URL is set, e.g.
//
//	docker run -d --rm -p 55432:5432 -e POSTGRES_PASSWORD=citadel-test-password-0123 postgres:17
//	CITADEL_TEST_DB_URL='postgres://postgres:citadel-test-password-0123@localhost:55432/postgres?sslmode=disable' \
//	    go test ./internal/store/postgres/
//
// Use a password of at least 14 bytes: SCRAM-SHA-256 keys HMAC with the
// password, and GODEBUG=fips140=only rejects HMAC keys under 112 bits.
//
// Each test works in its own freshly created schema (dropped afterwards),
// selected through the connection's search_path. The tests do not run in
// parallel: 0001_initial's information_schema lookups are not schema-qualified,
// so two Citadel schemas in one database can see each other's tables.

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"sync"
	"testing"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// testDB returns a handle whose connections all use a new, empty schema.
func testDB(t *testing.T) *sql.DB {
	t.Helper()
	raw := os.Getenv("CITADEL_TEST_DB_URL")
	if raw == "" {
		t.Skip("CITADEL_TEST_DB_URL not set; skipping PostgreSQL tests")
	}
	admin, err := sql.Open("postgres", raw)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	schema := "t_" + cryptoutil.RandomHex(8)
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		admin.Close()
		t.Fatalf("create schema: %v", err)
	}

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse CITADEL_TEST_DB_URL: %v", err)
	}
	q := u.Query()
	q.Set("search_path", schema) // lib/pq passes unknown keys as run-time parameters
	u.RawQuery = q.Encode()
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatalf("open schema db: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
		if _, err := admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); err != nil {
			t.Errorf("drop schema %s: %v", schema, err)
		}
		admin.Close()
	})

	var got string
	if err := db.QueryRow(`SELECT current_schema()`).Scan(&got); err != nil || got != schema {
		t.Fatalf("search_path not applied: current_schema=%q err=%v", got, err)
	}
	return db
}

func testOptions() Options {
	return Options{
		WrappingKey:  bytes.Repeat([]byte{0x42}, 32),
		AuditHMACKey: bytes.Repeat([]byte{0x24}, 32),
		Region:       "us-west-2",
		AccountID:    "123456789012",
	}
}

func appliedVersions(t *testing.T, db *sql.DB) []int64 {
	t.Helper()
	rows, err := db.Query(`SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatalf("read schema_migrations: %v", err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	return out
}

func wantAllMigrations(t *testing.T, db *sql.DB) {
	t.Helper()
	ms, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	got := appliedVersions(t, db)
	if len(got) != len(ms) {
		t.Fatalf("applied versions = %v, want %d migrations", got, len(ms))
	}
	for i, m := range ms {
		if got[i] != m.version {
			t.Fatalf("applied versions = %v, want %v at %d", got, m.version, i)
		}
	}
}

func TestMigrationsLoad(t *testing.T) {
	ms, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) == 0 || ms[0].version != 1 || ms[0].name != "initial" {
		t.Fatalf("unexpected migrations: %+v", ms)
	}
}

// TestMigrateTwice applies the migrations to an empty schema, then again, and
// then runs the full Open path (identity resolution and data migrations) twice.
func TestMigrateTwice(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := Migrate(ctx, db); err != nil {
			t.Fatalf("Migrate #%d: %v", i+1, err)
		}
	}
	wantAllMigrations(t, db)
	for i := 0; i < 2; i++ {
		if _, err := Open(ctx, db, testOptions()); err != nil {
			t.Fatalf("Open #%d: %v", i+1, err)
		}
	}
	wantAllMigrations(t, db)
}

// TestMigrateAdoptsPreMigrationDatabase builds the schema the way releases
// before versioned migrations did (the startup DDL, no schema_migrations
// table), adds data, and checks Migrate records 0001 without disturbing it.
func TestMigrateAdoptsPreMigrationDatabase(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	ms, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, ms[0].sql); err != nil {
		t.Fatalf("legacy DDL: %v", err)
	}
	legacy, err := Open(ctx, db, testOptions())
	if err != nil {
		t.Fatalf("Open legacy: %v", err)
	}
	// Open already migrated; simulate the pre-migration state by forgetting it.
	if _, err := db.ExecContext(ctx, `DROP TABLE schema_migrations`); err != nil {
		t.Fatal(err)
	}
	actx := store.WithCallerAccount(ctx, "123456789012")
	key, err := legacy.CreateKey(actx, "pre-migration key", store.KeyUsageEncryptDecrypt, store.KeySpecSymmetricDefault)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("Migrate on pre-migration database: %v", err)
	}
	wantAllMigrations(t, db)
	st, err := Open(ctx, db, testOptions())
	if err != nil {
		t.Fatalf("Open after adoption: %v", err)
	}
	if _, err := st.ResolveByID(actx, key.ID); err != nil {
		t.Fatalf("key created before adoption is gone: %v", err)
	}
}

// TestMigrateConcurrent starts several migrators at once; the advisory lock
// must serialize them so each migration is applied exactly once.
func TestMigrateConcurrent(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	const n = 4
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = Migrate(ctx, db)
		}(i)
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		t.Fatalf("concurrent Migrate: %v", err)
	}
	wantAllMigrations(t, db)
}

// TestTenantIsolation checks that keys and secrets created by one account are
// neither listed nor readable by another.
func TestTenantIsolation(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	st, err := Open(ctx, db, testOptions())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	const acctA, acctB = "111111111111", "222222222222"
	ctxA := store.WithCallerAccount(ctx, acctA)
	ctxB := store.WithCallerAccount(ctx, acctB)

	keyA, err := st.CreateKey(ctxA, "account A key", store.KeyUsageEncryptDecrypt, store.KeySpecSymmetricDefault)
	if err != nil {
		t.Fatalf("CreateKey(A): %v", err)
	}
	keyB, err := st.CreateKey(ctxB, "account B key", store.KeyUsageEncryptDecrypt, store.KeySpecSymmetricDefault)
	if err != nil {
		t.Fatalf("CreateKey(B): %v", err)
	}
	const name = "payments/prod/db/PASSWORD"
	if _, _, err := st.CreateSecret(ctxA, store.CreateSecretRequest{Name: name, KMSKeyID: keyA.ID, SecretString: "a-secret"}); err != nil {
		t.Fatalf("CreateSecret(A): %v", err)
	}

	t.Run("ListKeys", func(t *testing.T) {
		keys, err := st.ListKeys(ctxB)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range keys {
			if k.ID == keyA.ID {
				t.Fatalf("account B lists account A's key %s", keyA.ID)
			}
		}
	})
	t.Run("ListSecrets", func(t *testing.T) {
		secrets, err := st.ListSecrets(ctxB)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range secrets {
			if s.Name == name {
				t.Fatalf("account B lists account A's secret %q", name)
			}
		}
	})
	t.Run("DescribeSecret", func(t *testing.T) {
		// Control: the owner can describe it, so a failure for B is isolation
		// rather than a broken query.
		_, err := st.DescribeSecret(ctxA, name)
		if err != nil {
			t.Fatalf("DescribeSecret(A): %v", err)
		}
		if meta, err := st.DescribeSecret(ctxB, name); err == nil {
			t.Fatalf("account B can describe account A's secret: %+v", meta)
		}
	})
	t.Run("GetSecretValue", func(t *testing.T) {
		v, err := st.GetSecretValue(ctxA, name, "", "")
		if err != nil || v.SecretString == nil || *v.SecretString != "a-secret" {
			t.Fatalf("GetSecretValue(A) = %v, %v", v.SecretString, err)
		}
		if v, err := st.GetSecretValue(ctxB, name, "", ""); err == nil {
			t.Fatalf("account B can read account A's secret value (version %s)", v.VersionID)
		}
	})
	t.Run("ResolveByID", func(t *testing.T) {
		if _, err := st.ResolveByID(ctxA, keyA.ID); err != nil {
			t.Fatalf("ResolveByID(A): %v", err)
		}
		if _, err := st.ResolveByID(ctxB, keyA.ID); err == nil {
			t.Fatalf("account B can resolve account A's key %s", keyA.ID)
		}
	})
	t.Run("SameSecretNameInOtherAccount", func(t *testing.T) {
		_, _, err := st.CreateSecret(ctxB, store.CreateSecretRequest{Name: name, KMSKeyID: keyB.ID, SecretString: "b-secret"})
		if err != nil {
			t.Fatalf("CreateSecret(B): %v", err)
		}
		v, err := st.GetSecretValue(ctxA, name, "", "")
		if err != nil || v.SecretString == nil || *v.SecretString != "a-secret" {
			t.Fatalf("account A's value after B's create = %v, %v", v.SecretString, err)
		}
		vb, err := st.GetSecretValue(ctxB, name, "", "")
		if err != nil || vb.SecretString == nil || *vb.SecretString != "b-secret" {
			t.Fatalf("account B's value = %v, %v", vb.SecretString, err)
		}
		// Every per-secret write must touch only the caller's row.
		if _, err := st.PutSecretValue(ctxB, store.PutSecretValueRequest{SecretID: name, SecretString: "b-2"}); err != nil {
			t.Fatalf("PutSecretValue(B): %v", err)
		}
		if err := st.TagSecret(ctxB, name, []store.SecretTag{{Key: "owner", Value: "b"}}); err != nil {
			t.Fatalf("TagSecret(B): %v", err)
		}
		if err := st.PutSecretResourcePolicy(ctxB, name, `{"Version":"2012-10-17","Statement":[]}`); err != nil {
			t.Fatalf("PutSecretResourcePolicy(B): %v", err)
		}
		if _, err := st.DeleteSecret(ctxB, name, 0, true); err != nil {
			t.Fatalf("DeleteSecret(B, force): %v", err)
		}
		metaA, err := st.DescribeSecret(ctxA, name)
		if err != nil {
			t.Fatalf("account A's secret gone after B's force delete: %v", err)
		}
		if len(metaA.Tags) != 0 || metaA.VersionCount != 1 {
			t.Fatalf("account A's secret changed by B's writes: tags=%v versions=%d", metaA.Tags, metaA.VersionCount)
		}
		v, err = st.GetSecretValue(ctxA, name, "", "")
		if err != nil || v.SecretString == nil || *v.SecretString != "a-secret" {
			t.Fatalf("account A's value after B's writes = %v, %v", v.SecretString, err)
		}
		// A duplicate within one account is still refused.
		if _, _, err := st.CreateSecret(ctxA, store.CreateSecretRequest{Name: name, KMSKeyID: keyA.ID, SecretString: "x"}); !errors.Is(err, store.ErrSecretExists) {
			t.Fatalf("duplicate CreateSecret(A) err = %v, want ErrSecretExists", err)
		}
	})
}
