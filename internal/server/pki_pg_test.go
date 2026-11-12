package server

import (
	"bytes"
	"context"
	"database/sql"
	"net/url"
	"os"
	"testing"

	"github.com/worlddrknss/citadel/internal/acme"
	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store/postgres"
)

// pgTestStore opens a migrated PostgreSQL store in a fresh schema when
// CITADEL_TEST_DB_URL is set.
func pgTestStore(t *testing.T) *postgres.Store {
	t.Helper()
	raw := os.Getenv("CITADEL_TEST_DB_URL")
	if raw == "" {
		t.Skip("CITADEL_TEST_DB_URL not set; skipping PostgreSQL tests")
	}
	admin, err := sql.Open("postgres", raw)
	if err != nil {
		t.Fatal(err)
	}
	schema := "t_" + cryptoutil.RandomHex(8)
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
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
	t.Cleanup(func() {
		db.Close()
		_, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
		admin.Close()
	})
	st, err := postgres.Open(context.Background(), db, postgres.Options{
		WrappingKey: bytes.Repeat([]byte{0x42}, 32), AuditHMACKey: bytes.Repeat([]byte{0x24}, 32),
		Region: "us-west-2", AccountID: "123456789012",
	})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// TestACMEEndToEndPostgres runs the ACME flow against the SQL acme.Store,
// PKI tables and EAB keys.
func TestACMEEndToEndPostgres(t *testing.T) {
	e := newPKIEnvOn(t, pgTestStore(t), func(s *Server) {
		s.pki.validators = map[string]acme.Validator{acme.ChallengeDNS01: acme.ValidatorFunc(func(context.Context, acme.Identifier, string, string) error { return nil })}
	})
	runACMEEndToEnd(t, e)
}

func TestPKIIsolationPostgres(t *testing.T) {
	e := newPKIEnvOn(t, pgTestStore(t), nil)
	root := e.createCA("admin", map[string]any{"commonName": "Root", "keyAlgorithm": "EC_prime256v1"})
	sub := e.createCA("admin", map[string]any{"caType": "SUBORDINATE", "commonName": "Sub", "keyAlgorithm": "EC_prime256v1", "parentCaId": root})
	rec := e.do("editor", "POST", "/v1/certificates/issue/generate", map[string]any{"caId": sub, "commonName": "a.example.com", "keyAlgorithm": "RSA_2048"})
	wantStatus(t, rec, 200)
	if got := parsePEMChain(t, decode(t, rec)["chainPem"].(string)); len(got) != 2 {
		t.Fatalf("chain length %d", len(got))
	}
	wantStatus(t, e.do("other", "POST", "/v1/certificates/issue/generate", map[string]any{"caId": sub, "commonName": "a.example.com", "keyAlgorithm": "RSA_2048"}), 404)
}
