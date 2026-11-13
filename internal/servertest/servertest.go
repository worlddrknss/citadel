// Package servertest runs the real Citadel HTTP server, over the in-memory
// store, behind an httptest.Server. Tests of API clients (the Go SDK) use it
// to exercise real handler behaviour rather than a mock.
package servertest

import (
	"bytes"
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/config"
	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/server"
	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/memory"
)

// Env is a running server with one account and an access key per role.
type Env struct {
	// URL is the server's base URL, e.g. "http://127.0.0.1:41234".
	URL string
	// AccountID is the account the users belong to.
	AccountID string
	// Admin, Editor and Viewer are access keys whose owners hold that role
	// in the account.
	Admin, Editor, Viewer Key
	// Store is the backing store, for assertions.
	Store *memory.Store
	// HTTP is the underlying test server.
	HTTP *httptest.Server
}

// Key is an access key.
type Key struct {
	ID, Secret string
}

// Token is the bearer token for the key: "<accessKeyId>:<secret>".
func (k Key) Token() string { return k.ID + ":" + k.Secret }

// New starts a server and registers its shutdown with t.Cleanup.
func New(t testing.TB) *Env {
	t.Helper()
	ctx := context.Background()
	st := &memory.Store{
		DefaultKey: store.KMSKey{
			ID:           "servertest-default",
			ARN:          "arn:aws:kms:local:000000000000:key/servertest-default",
			MasterKeyRaw: bytes.Repeat([]byte{7}, 32),
			Description:  "servertest default key",
			CreatedAt:    time.Now().UTC(),
			Enabled:      true,
			KeyUsage:     store.KeyUsageEncryptDecrypt,
			KeySpec:      store.KeySpecSymmetricDefault,
		},
		AccountID: "000000000000",
		Region:    "local",
	}
	acct, err := st.CreateUIAccount(ctx, "servertest")
	if err != nil {
		t.Fatalf("servertest: create account: %v", err)
	}
	// Users authenticate here only by access key, so no password is needed;
	// a random one keeps the configuration well-formed.
	users := map[string]store.UIUser{}
	env := &Env{AccountID: acct, Store: st}
	for _, u := range []struct {
		name, role string
		key        *Key
	}{{"admin", "admin", &env.Admin}, {"editor", "editor", &env.Editor}, {"viewer", "viewer", &env.Viewer}} {
		user := store.UIUser{Username: u.name, Role: u.role, DisplayName: u.name, PasswordHash: "unused-" + cryptoutil.RandomHex(8)}
		if err := st.UpsertUIUser(ctx, user); err != nil {
			t.Fatalf("servertest: upsert user: %v", err)
		}
		if err := st.AddUserAccount(ctx, u.name, acct, u.role); err != nil {
			t.Fatalf("servertest: add membership: %v", err)
		}
		k, err := st.CreateAccessKey(ctx, u.name, acct)
		if err != nil {
			t.Fatalf("servertest: create access key: %v", err)
		}
		*u.key = Key{ID: k.AccessKeyID, Secret: k.SecretKey}
		users[u.name] = user
	}
	ts := httptest.NewUnstartedServer(nil)
	base := "http://" + ts.Listener.Addr().String()
	cfg := config.Config{
		PublicURL:         base,
		ExpectedAccessKey: "AKIASERVERTEST000001",
		SecretAccessKey:   "servertest-secret-access-key-0123456789ab",
		UIUsers:           users,
		SessionIdleTTL:    30 * time.Minute,
		SessionAbsTTL:     12 * time.Hour,
	}
	s, err := server.New(ctx, cfg, st, nil)
	if err != nil {
		t.Fatalf("servertest: new server: %v", err)
	}
	ts.Config.Handler = s.Handler()
	ts.Start()
	env.HTTP, env.URL = ts, base
	t.Cleanup(ts.Close)
	return env
}
