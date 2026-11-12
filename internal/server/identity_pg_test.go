package server

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/config"
	"github.com/worlddrknss/citadel/internal/jose"
	"github.com/worlddrknss/citadel/internal/oidclogin"
	"github.com/worlddrknss/citadel/internal/store"
)

// TestWorkloadSignerPostgres signs with KMS keys stored (wrapped) in
// PostgreSQL across a rotation and checks the published set.
func TestWorkloadSignerPostgres(t *testing.T) {
	st := pgTestStore(t)
	s := &Server{cfg: config.Config{PublicURL: "https://citadel.test", WrappingKey: bytes.Repeat([]byte{1}, 32)}, store: st}
	ctx := context.Background()
	set := s.workloadSigners()
	first, err := set.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tok1, err := jose.SignJWT(ctx, first, map[string]any{"sub": "a"})
	if err != nil {
		t.Fatal(err)
	}
	cur, _, _ := s.currentWorkloadKey(ctx)
	if _, err := s.rotateWorkloadKey(ctx, cur.KID); err != nil {
		t.Fatal(err)
	}
	// A stale expectation (another replica already rotated) is a conflict
	// and leaves the keys alone.
	if _, err := s.rotateWorkloadKey(ctx, cur.KID); err == nil {
		t.Fatal("stale rotation succeeded")
	}
	second, err := set.Current(ctx)
	if err != nil || second.KeyID() == first.KeyID() {
		t.Fatalf("current after rotation = %v, %v", second, err)
	}
	pub, _ := set.Published(ctx)
	if len(pub) != 2 {
		t.Fatalf("published %d keys, want 2", len(pub))
	}
	jwks := &jose.JWKSet{}
	for _, p := range pub {
		jwks.Keys = append(jwks.Keys, jose.NewJWK(p))
	}
	if _, err := jose.Verify(ctx, tok1, jwks); err != nil {
		t.Fatalf("token signed before rotation no longer verifies: %v", err)
	}
}

// TestSSOProvisioningPostgres links an external identity to a JIT user and
// consumes sign-in states once in PostgreSQL.
func TestSSOProvisioningPostgres(t *testing.T) {
	st := pgTestStore(t)
	s := &Server{cfg: config.Config{PublicURL: "https://citadel.test", WrappingKey: bytes.Repeat([]byte{1}, 32)}, store: st}
	ctx := context.Background()
	acct, err := st.CreateUIAccount(ctx, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	p := store.SSOProvider{ID: "sso-1", Name: "IdP", Issuer: "https://idp.example.com", ClientID: "c", AccountID: acct,
		RoleMappings: []store.SSORoleMapping{{Group: "eng", AccountID: acct, Role: "editor"}}, DefaultRole: "none", Enabled: true,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if err := st.CreateSSOProvider(ctx, p, nil); err != nil {
		t.Fatal(err)
	}
	ident := oidclogin.Identity{Provider: p.ID, Subject: "sub-1", Email: "dana@example.com", Username: "dana"}
	ms, err := s.ssoMemberships(ctx, p, []string{"eng"})
	if err != nil || len(ms) != 1 || ms[0].Account != acct {
		t.Fatalf("memberships = %v, %v", ms, err)
	}
	u1, err := s.ssoProvisionUser(ctx, p, ident)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.syncSSOMemberships(ctx, u1, ms); err != nil {
		t.Fatal(err)
	}
	ident.Email = "other@example.com"
	if u2, err := s.ssoProvisionUser(ctx, p, ident); err != nil || u2 != u1 {
		t.Fatalf("second sign-in = %q, %v; want %q", u2, err, u1)
	}
	if role, ok := accountRole(s.userMemberships(ctx, mustUser(t, s, u1)), acct); !ok || role != "editor" {
		t.Fatalf("membership = %q %v", role, ok)
	}
	r := storeReplay{st}
	exp := time.Now().Add(time.Minute)
	if ok, err := r.Consume(ctx, "x", exp); !ok || err != nil {
		t.Fatalf("first consume = %v, %v", ok, err)
	}
	if ok, err := r.Consume(ctx, "x", exp); ok || err != nil {
		t.Fatalf("replay consume = %v, %v", ok, err)
	}
}

func mustUser(t *testing.T, s *Server, name string) store.UIUser {
	t.Helper()
	u, ok := s.lookupUser(context.Background(), name)
	if !ok {
		t.Fatalf("user %s missing", name)
	}
	return u
}
