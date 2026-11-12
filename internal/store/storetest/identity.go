package storetest

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// IdentityStore exercises store.IdentityStore against fresh stores.
func IdentityStore(t *testing.T, newStore func(t *testing.T) store.Store) {
	t.Run("SSOProviders", func(t *testing.T) { testSSOProviders(t, newStore(t)) })
	t.Run("ExternalIdentities", func(t *testing.T) { testExternalIdentities(t, newStore(t)) })
	t.Run("ConsumeOnce", func(t *testing.T) { testConsumeOnce(t, newStore(t)) })
	t.Run("SigningKeys", func(t *testing.T) { testSigningKeys(t, newStore(t)) })
	t.Run("IssuerSettings", func(t *testing.T) { testIssuerSettings(t, newStore(t)) })
	t.Run("WorkloadClients", func(t *testing.T) { testWorkloadClients(t, newStore(t)) })
}

func ts(sec int64) time.Time { return time.Unix(1_800_000_000+sec, 0).UTC() }

func testSSOProviders(t *testing.T, st store.Store) {
	ctx := context.Background()
	p := store.SSOProvider{
		ID: "okta", Name: "Okta", Issuer: "https://idp.example.com", ClientID: "cid", Scopes: []string{"openid", "email"},
		GroupClaim: "groups", RoleMappings: []store.SSORoleMapping{{Group: "eng", AccountID: "111111111111", Role: "editor"}},
		DefaultRole: "viewer", Enabled: true, CreatedAt: ts(0), UpdatedAt: ts(0), AccountID: "111111111111",
		AllowedEmailDomains: []string{"example.com"},
	}
	if err := st.CreateSSOProvider(ctx, p, []byte("sealed-1")); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.CreateSSOProvider(ctx, p, nil); !errors.Is(err, store.ErrSSOProviderExists) {
		t.Fatalf("duplicate create err = %v", err)
	}
	disabled := store.SSOProvider{ID: "aaa", Name: "Disabled", Issuer: "https://x.example.com", ClientID: "c", CreatedAt: ts(0), UpdatedAt: ts(0), DefaultRole: "none"}
	if err := st.CreateSSOProvider(ctx, disabled, nil); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetSSOProvider(ctx, "okta")
	if err != nil || got.Name != "Okta" || !got.ClientSecretSet || got.AccountID != "111111111111" ||
		len(got.AllowedEmailDomains) != 1 || len(got.RoleMappings) != 1 || got.RoleMappings[0].Role != "editor" || len(got.Scopes) != 2 {
		t.Fatalf("get = %+v, %v", got, err)
	}
	if sec, err := st.GetSSOProviderSecret(ctx, "okta"); err != nil || !bytes.Equal(sec, []byte("sealed-1")) {
		t.Fatalf("secret = %q, %v", sec, err)
	}
	if sec, err := st.GetSSOProviderSecret(ctx, "aaa"); err != nil || len(sec) != 0 {
		t.Fatalf("empty secret = %q, %v", sec, err)
	}
	if _, err := st.GetSSOProvider(ctx, "nope"); !errors.Is(err, store.ErrSSOProviderNotFound) {
		t.Fatalf("get unknown err = %v", err)
	}
	all, _ := st.ListSSOProviders(ctx, false)
	enabled, _ := st.ListSSOProviders(ctx, true)
	if len(all) != 2 || len(enabled) != 1 || enabled[0].ID != "okta" || all[0].ID != "aaa" {
		t.Fatalf("list all=%+v enabled=%+v", all, enabled)
	}
	// Update keeping the secret, then replacing it.
	p.Name, p.Enabled, p.UpdatedAt, p.CreatedAt = "Okta 2", false, ts(10), ts(99)
	if err := st.UpdateSSOProvider(ctx, p, nil); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetSSOProvider(ctx, "okta")
	if got.Name != "Okta 2" || got.Enabled || !got.CreatedAt.Equal(ts(0)) || !got.UpdatedAt.Equal(ts(10)) || !got.ClientSecretSet {
		t.Fatalf("after update = %+v", got)
	}
	if sec, _ := st.GetSSOProviderSecret(ctx, "okta"); !bytes.Equal(sec, []byte("sealed-1")) {
		t.Fatalf("secret changed on keep: %q", sec)
	}
	if err := st.UpdateSSOProvider(ctx, p, []byte("sealed-2")); err != nil {
		t.Fatal(err)
	}
	if sec, _ := st.GetSSOProviderSecret(ctx, "okta"); !bytes.Equal(sec, []byte("sealed-2")) {
		t.Fatalf("secret not replaced: %q", sec)
	}
	if err := st.UpdateSSOProvider(ctx, store.SSOProvider{ID: "nope"}, nil); !errors.Is(err, store.ErrSSOProviderNotFound) {
		t.Fatalf("update unknown err = %v", err)
	}
	if err := st.DeleteSSOProvider(ctx, "okta"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteSSOProvider(ctx, "okta"); !errors.Is(err, store.ErrSSOProviderNotFound) {
		t.Fatalf("delete twice err = %v", err)
	}
}

func testExternalIdentities(t *testing.T, st store.Store) {
	ctx := context.Background()
	if err := st.UpsertUIUser(ctx, store.UIUser{Username: "sso-user", PasswordHash: testHash, Role: "viewer"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSSOProvider(ctx, store.SSOProvider{ID: "p1", Name: "P1", Issuer: "https://i", ClientID: "c", CreatedAt: ts(0), UpdatedAt: ts(0), DefaultRole: "none"}, nil); err != nil {
		t.Fatal(err)
	}
	id := store.ExternalIdentity{ProviderID: "p1", Subject: "sub-1", Username: "sso-user", Email: "a@example.com", CreatedAt: ts(0), LastLoginAt: ts(0)}
	if err := st.CreateExternalIdentity(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateExternalIdentity(ctx, id); !errors.Is(err, store.ErrExternalIdentityExists) {
		t.Fatalf("duplicate err = %v", err)
	}
	if err := st.CreateExternalIdentity(ctx, store.ExternalIdentity{ProviderID: "zz", Subject: "s", Username: "sso-user", CreatedAt: ts(0), LastLoginAt: ts(0)}); err == nil {
		t.Fatal("identity for unknown provider accepted")
	}
	if _, err := st.GetExternalIdentity(ctx, "p1", "sub-2"); !errors.Is(err, store.ErrExternalIdentityNotFound) {
		t.Fatalf("unknown subject err = %v", err)
	}
	if err := st.TouchExternalIdentity(ctx, "p1", "sub-1", "b@example.com", ts(5)); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetExternalIdentity(ctx, "p1", "sub-1")
	if err != nil || got.Username != "sso-user" || got.Email != "b@example.com" || !got.LastLoginAt.Equal(ts(5)) {
		t.Fatalf("got %+v, %v", got, err)
	}
	if err := st.DeleteSSOProvider(ctx, "p1"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetExternalIdentity(ctx, "p1", "sub-1"); !errors.Is(err, store.ErrExternalIdentityNotFound) {
		t.Fatalf("identity survived provider delete: %v", err)
	}
}

func testConsumeOnce(t *testing.T, st store.Store) {
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)
	var fresh atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := st.ConsumeOnce(ctx, "state-1", exp)
			if err != nil {
				t.Error(err)
			}
			if ok {
				fresh.Add(1)
			}
		}()
	}
	wg.Wait()
	if fresh.Load() != 1 {
		t.Fatalf("%d concurrent consumers succeeded, want 1", fresh.Load())
	}
	// An expired entry may be reused.
	if ok, err := st.ConsumeOnce(ctx, "old", time.Now().Add(-time.Minute)); !ok || err != nil {
		t.Fatalf("first consume = %v, %v", ok, err)
	}
	if ok, err := st.ConsumeOnce(ctx, "old", exp); !ok || err != nil {
		t.Fatalf("consume after expiry = %v, %v", ok, err)
	}
	if _, err := st.ConsumeOnce(ctx, "gone", time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n, err := st.PurgeConsumed(ctx, time.Now()); err != nil || n != 1 {
		t.Fatalf("purge = %d, %v", n, err)
	}
}

func testSigningKeys(t *testing.T, st store.Store) {
	ctx := context.Background()
	if ks, err := st.ListWorkloadSigningKeys(ctx); err != nil || len(ks) != 0 {
		t.Fatalf("initial keys = %v, %v", ks, err)
	}
	k1 := store.WorkloadSigningKey{KID: "k1", KMSKeyID: "kms-1", Algorithm: "ES256", ActivatedAt: ts(0)}
	if err := st.RotateWorkloadSigningKey(ctx, k1, "x", ts(0), ts(0)); !errors.Is(err, store.ErrWorkloadRotationConflict) {
		t.Fatalf("wrong expectation err = %v", err)
	}
	if err := st.RotateWorkloadSigningKey(ctx, k1, "", time.Time{}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	k2 := store.WorkloadSigningKey{KID: "k2", KMSKeyID: "kms-2", Algorithm: "ES384", ActivatedAt: ts(10)}
	if err := st.RotateWorkloadSigningKey(ctx, k2, "", ts(10), ts(20)); !errors.Is(err, store.ErrWorkloadRotationConflict) {
		t.Fatalf("stale rotation err = %v", err)
	}
	if err := st.RotateWorkloadSigningKey(ctx, k2, "k1", ts(10), ts(20)); err != nil {
		t.Fatal(err)
	}
	ks, err := st.ListWorkloadSigningKeys(ctx)
	if err != nil || len(ks) != 2 || ks[0].KID != "k2" || !ks[0].RetiredAt.IsZero() || ks[1].KID != "k1" ||
		!ks[1].RetiredAt.Equal(ts(10)) || !ks[1].UnpublishAt.Equal(ts(20)) || ks[0].Algorithm != "ES384" || ks[1].KMSKeyID != "kms-1" {
		t.Fatalf("keys = %+v, %v", ks, err)
	}
	gone, err := st.DeleteUnpublishedWorkloadSigningKeys(ctx, ts(15))
	if err != nil || len(gone) != 0 {
		t.Fatalf("early purge = %v, %v", gone, err)
	}
	gone, err = st.DeleteUnpublishedWorkloadSigningKeys(ctx, ts(21))
	if err != nil || len(gone) != 1 || gone[0].KID != "k1" {
		t.Fatalf("purge = %v, %v", gone, err)
	}
	if ks, _ := st.ListWorkloadSigningKeys(ctx); len(ks) != 1 || ks[0].KID != "k2" {
		t.Fatalf("after purge = %+v", ks)
	}
}

func testIssuerSettings(t *testing.T, st store.Store) {
	ctx := context.Background()
	if s, err := st.GetWorkloadIssuerSettings(ctx); err != nil || s.Algorithm != "" || s.RotationDays != 0 {
		t.Fatalf("defaults = %+v, %v", s, err)
	}
	want := store.WorkloadIssuerSettings{Algorithm: "PS256", RotationDays: 30, UpdatedAt: ts(1), UpdatedBy: "root"}
	if err := st.PutWorkloadIssuerSettings(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetWorkloadIssuerSettings(ctx)
	if err != nil || got.Algorithm != "PS256" || got.RotationDays != 30 || !got.UpdatedAt.Equal(ts(1)) || got.UpdatedBy != "root" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func testWorkloadClients(t *testing.T, st store.Store) {
	ctx := context.Background()
	c := store.WorkloadClient{
		ClientID: "wic-1", AccountID: "111111111111", Name: "ci", Audiences: []string{"sts.amazonaws.com"}, TokenTTLSeconds: 900,
		SubjectFormat: "client:{clientId}", AuthMethod: store.WorkloadAuthAccessKey, AllowedUsers: []string{"bob"}, CreatedAt: ts(0), UpdatedAt: ts(0),
	}
	if err := st.CreateWorkloadClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateWorkloadClient(ctx, c); !errors.Is(err, store.ErrWorkloadClientExists) {
		t.Fatalf("duplicate err = %v", err)
	}
	k := store.WorkloadClient{
		ClientID: "wic-2", AccountID: "222222222222", Name: "k8s", Audiences: []string{"a", "b"}, TokenTTLSeconds: 300,
		SubjectFormat: "x", AuthMethod: store.WorkloadAuthK8s, APIServer: "https://k8s", CAPEM: "pem", ServiceAccounts: []string{"ns:sa"},
		ReviewAudience: "citadel", CreatedAt: ts(0), UpdatedAt: ts(0),
	}
	if err := st.CreateWorkloadClient(ctx, k); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetWorkloadClient(ctx, "wic-2")
	if err != nil || got.AccountID != "222222222222" || got.APIServer != "https://k8s" || got.CAPEM != "pem" || len(got.ServiceAccounts) != 1 ||
		got.ReviewAudience != "citadel" || len(got.Audiences) != 2 || !got.LastIssuedAt.IsZero() {
		t.Fatalf("get = %+v, %v", got, err)
	}
	if l, _ := st.ListWorkloadClients(ctx, "111111111111"); len(l) != 1 || l[0].ClientID != "wic-1" || l[0].AllowedUsers[0] != "bob" {
		t.Fatalf("list A = %+v", l)
	}
	if l, _ := st.ListWorkloadClients(ctx, "333333333333"); l == nil || len(l) != 0 {
		t.Fatalf("list empty account = %#v", l)
	}
	// Cross-account update and delete are refused.
	cross := c
	cross.AccountID = "222222222222"
	if err := st.UpdateWorkloadClient(ctx, cross); !errors.Is(err, store.ErrWorkloadClientNotFound) {
		t.Fatalf("cross-account update err = %v", err)
	}
	if err := st.DeleteWorkloadClient(ctx, "222222222222", "wic-1"); !errors.Is(err, store.ErrWorkloadClientNotFound) {
		t.Fatalf("cross-account delete err = %v", err)
	}
	if err := st.TouchWorkloadClientIssued(ctx, "wic-1", ts(7)); err != nil {
		t.Fatal(err)
	}
	c.Name, c.UpdatedAt, c.CreatedAt = "ci-2", ts(9), ts(99)
	if err := st.UpdateWorkloadClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetWorkloadClient(ctx, "wic-1")
	if got.Name != "ci-2" || !got.CreatedAt.Equal(ts(0)) || !got.UpdatedAt.Equal(ts(9)) || !got.LastIssuedAt.Equal(ts(7)) {
		t.Fatalf("after update = %+v", got)
	}
	if err := st.DeleteWorkloadClient(ctx, "111111111111", "wic-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetWorkloadClient(ctx, "wic-1"); !errors.Is(err, store.ErrWorkloadClientNotFound) {
		t.Fatalf("get deleted err = %v", err)
	}
}
