package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/lib/pq"
	"github.com/worlddrknss/citadel/internal/config"
	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/postgres"
)

// pgTwoStores opens two independent stores (two replicas) on one fresh
// schema.
func pgTwoStores(t *testing.T) (*postgres.Store, *postgres.Store) {
	t.Helper()
	first := pgTestStore(t)
	raw := os.Getenv("CITADEL_TEST_DB_URL")
	var schema string
	if err := first.DB().QueryRow(`SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	second, err := postgres.Open(context.Background(), db, postgres.Options{
		WrappingKey: bytes.Repeat([]byte{0x42}, 32), AuditHMACKey: bytes.Repeat([]byte{0x24}, 32),
		Region: "us-west-2", AccountID: "123456789012",
	})
	if err != nil {
		t.Fatal(err)
	}
	return first, second
}

func TestRotationNoDoubleRotationPostgres(t *testing.T) {
	a, b := pgTwoStores(t)
	cfg := config.Config{WrappingKey: bytes.Repeat([]byte{3}, 32)}
	runNoDoubleRotation(t, &Server{cfg: cfg, store: a}, &Server{cfg: cfg, store: b})
}

// pgAdmin connects to the test database server as its superuser.
func pgAdmin(t *testing.T) (*sql.DB, *url.URL) {
	t.Helper()
	raw := os.Getenv("CITADEL_TEST_DB_URL")
	if raw == "" {
		t.Skip("CITADEL_TEST_DB_URL not set; skipping PostgreSQL tests")
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("postgres", raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, u
}

func pgLoginWorks(u *url.URL, user, password string) error {
	c := *u
	c.User = url.UserPassword(user, password)
	db, err := sql.Open("postgres", c.String())
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Ping()
}

func pgSecretJSON(t *testing.T, u *url.URL, user, password string, extra map[string]any) string {
	t.Helper()
	port := 5432
	if p := u.Port(); p != "" {
		fmt.Sscan(p, &port)
	}
	m := map[string]any{"engine": "postgres", "host": u.Hostname(), "port": port, "username": user, "password": password, "dbname": strings.TrimPrefix(u.Path, "/"), "sslmode": "disable"}
	for k, v := range extra {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// TestRotationPostgresRotator rotates real database users: single-user (the
// user's own credentials) and alternating-users (an admin secret), checking
// the new password signs in and the old one doesn't.
func TestRotationPostgresRotator(t *testing.T) {
	admin, u := pgAdmin(t)
	st := pgTestStore(t)
	s := &Server{cfg: config.Config{WrappingKey: bytes.Repeat([]byte{3}, 32)}, store: st}
	s.rot.allowLoopback = true
	ctx := store.WithActor(rotationCtxA(), "alice")
	if _, err := st.EnsureAccountDefaultKey(ctx, tAcctA); err != nil {
		t.Fatal(err)
	}
	role := "rot_" + cryptoutil.RandomHex(4)
	oldPW := "Old-" + cryptoutil.RandomHex(10)
	if _, err := admin.Exec(`CREATE ROLE ` + pq.QuoteIdentifier(role) + ` WITH LOGIN PASSWORD ` + pq.QuoteLiteral(oldPW)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(`DROP ROLE IF EXISTS ` + pq.QuoteIdentifier(role+pgCloneSuffix))
		_, _ = admin.Exec(`DROP ROLE IF EXISTS ` + pq.QuoteIdentifier(role))
	})

	t.Run("single user", func(t *testing.T) {
		if _, _, err := st.CreateSecret(ctx, store.CreateSecretRequest{Name: "db/app", SecretString: pgSecretJSON(t, u, role, oldPW, nil)}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.configureRotation(ctx, secretRotationRequest{SecretID: "db/app", LambdaARN: "arn:citadel:rotator:us-west-2:" + tAcctA + ":postgresql"}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.startRotation(context.Background(), tAcctA, "db/app", "immediate", "", false); err != nil {
			t.Fatal(err)
		}
		rot, _ := st.GetSecretRotation(ctx, "db/app")
		if rot.Status != store.RotationStatusSucceeded {
			t.Fatalf("rotation = %s at %s: %s", rot.Status, rot.LastStep, rot.LastError)
		}
		v, _ := st.GetSecretValue(ctx, "db/app", "", "")
		p, err := parsePGSecret(v, "new")
		if err != nil {
			t.Fatal(err)
		}
		if p.Username != role || p.Password == oldPW || strings.ContainsAny(p.Password, pgExcludeCharacters) {
			t.Fatalf("new secret = %s / %q", p.Username, p.Password)
		}
		if err := pgLoginWorks(u, role, p.Password); err != nil {
			t.Fatalf("new password doesn't sign in: %v", err)
		}
		if err := pgLoginWorks(u, role, oldPW); err == nil {
			t.Fatal("old password still signs in")
		}
		prev, _ := st.GetSecretValue(ctx, "db/app", "", store.PreviousVersionStage)
		if pp, _ := parsePGSecret(prev, "previous"); pp.Password != oldPW {
			t.Fatal("AWSPREVIOUS doesn't hold the old credentials")
		}
	})

	t.Run("alternating users", func(t *testing.T) {
		adminSecret := pgSecretJSON(t, u, u.User.Username(), func() string { p, _ := u.User.Password(); return p }(), nil)
		am, _, err := st.CreateSecret(ctx, store.CreateSecretRequest{Name: "db/master", SecretString: adminSecret})
		if err != nil {
			t.Fatal(err)
		}
		cur, _ := st.GetSecretValue(ctx, "db/app", "", "")
		var obj map[string]any
		_ = json.Unmarshal([]byte(*cur.SecretString), &obj)
		obj["masterarn"] = am.ARN
		b, _ := json.Marshal(obj)
		if _, _, err := st.CreateSecret(ctx, store.CreateSecretRequest{Name: "db/alt", SecretString: string(b)}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.configureRotation(ctx, secretRotationRequest{SecretID: "db/alt", RotatorType: store.RotatorPostgreSQL}); err != nil {
			t.Fatal(err)
		}
		for i, wantUser := range []string{role + pgCloneSuffix, role} {
			if _, err := s.startRotation(context.Background(), tAcctA, "db/alt", "immediate", "", false); err != nil {
				t.Fatal(err)
			}
			rot, _ := st.GetSecretRotation(ctx, "db/alt")
			if rot.Status != store.RotationStatusSucceeded {
				t.Fatalf("rotation %d = %s at %s: %s", i, rot.Status, rot.LastStep, rot.LastError)
			}
			v, _ := st.GetSecretValue(ctx, "db/alt", "", "")
			p, _ := parsePGSecret(v, "new")
			if p.Username != wantUser {
				t.Fatalf("rotation %d user = %s, want %s", i, p.Username, wantUser)
			}
			if err := pgLoginWorks(u, p.Username, p.Password); err != nil {
				t.Fatalf("rotation %d: new credentials don't sign in: %v", i, err)
			}
		}
		var member bool
		if err := admin.QueryRow(`SELECT pg_has_role($1, $2, 'MEMBER')`, role+pgCloneSuffix, role).Scan(&member); err != nil || !member {
			t.Fatalf("clone is not a member of the original role: %v %v", member, err)
		}
	})

	t.Run("loopback refused by default", func(t *testing.T) {
		s2 := &Server{cfg: s.cfg, store: st}
		if _, err := s2.startRotation(context.Background(), tAcctA, "db/app", "immediate", "", false); err != nil {
			t.Fatal(err)
		}
		rot, _ := st.GetSecretRotation(ctx, "db/app")
		if rot.Status != store.RotationStatusRetrying || !strings.Contains(rot.LastError, "not allowed") {
			t.Fatalf("rotation to loopback = %s: %s", rot.Status, rot.LastError)
		}
		// The pending version is kept for the retry.
		meta, _ := st.DescribeSecret(ctx, "db/app")
		if store.PendingRotationToken(meta) == "" {
			t.Fatal("AWSPENDING dropped after a failed setSecret")
		}
	})
}
