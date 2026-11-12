package memory

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/storetest"
)

func TestAWSPageStore(t *testing.T) {
	st := &Store{DefaultKey: store.KMSKey{ID: "boot", ARN: "arn:aws:kms:us-east-1:000000000000:key/boot", MasterKeyRaw: bytes.Repeat([]byte{1}, 32), Enabled: true}}
	storetest.AWSPageStore(t, st, false)
}

func TestKMSWritesAreTenantScoped(t *testing.T) {
	st := &Store{}
	ctxA := store.WithCallerAccount(context.Background(), storetest.AccountA)
	ctxB := store.WithCallerAccount(context.Background(), storetest.AccountB)
	k, err := st.CreateKey(ctxA, "a", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateAlias(ctxA, "alias/x", k.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateAlias(ctxA, "alias/x", k.ID); !errors.Is(err, store.ErrAliasExists) {
		t.Fatalf("duplicate alias: %v", err)
	}
	if got, err := st.ResolveByID(ctxA, "alias/x"); err != nil || got.ID != k.ID {
		t.Fatalf("alias resolve: %v %v", got.ID, err)
	}
	for name, err := range map[string]error{
		"resolve":  func() error { _, err := st.ResolveByID(ctxB, k.ID); return err }(),
		"alias":    func() error { _, err := st.ResolveByID(ctxB, "alias/x"); return err }(),
		"disable":  st.SetKeyEnabled(ctxB, k.ID, false),
		"policy":   st.PutKeyPolicy(ctxB, k.ID, "default", "{}"),
		"delete":   func() error { _, err := st.ScheduleKeyDeletion(ctxB, k.ID, 7); return err }(),
		"realias":  st.UpdateAlias(ctxB, "alias/x", k.ID),
		"unalias":  st.DeleteAlias(ctxB, "alias/x"),
		"cancel":   st.CancelKeyDeletion(ctxB, k.ID),
		"ownalias": st.CreateAlias(ctxB, "alias/y", k.ID),
	} {
		if !errors.Is(err, sql.ErrNoRows) {
			t.Errorf("%s across accounts: err=%v, want sql.ErrNoRows", name, err)
		}
	}
	when, err := st.ScheduleKeyDeletion(ctxA, k.ID, 7)
	if err != nil || time.Until(when) < 6*24*time.Hour {
		t.Fatalf("ScheduleKeyDeletion: %v %v", when, err)
	}
	if got, _ := st.ResolveByID(ctxA, k.ID); got.DeletionDate == nil {
		t.Fatal("deletion date not stored")
	}
}

func TestFederationAndSTSSessions(t *testing.T) {
	st := &Store{}
	ctx := context.Background()
	if err := st.CreateOIDCProvider(ctx, store.OIDCProvider{ProviderARN: "p", AccountID: storetest.AccountA, URL: "https://issuer/"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetOIDCProviderByURL(ctx, storetest.AccountA, "https://issuer"); err != nil {
		t.Fatalf("provider by normalized URL: %v", err)
	}
	if _, err := st.GetOIDCProviderByURL(ctx, storetest.AccountB, "https://issuer"); !errors.Is(err, store.ErrOIDCProviderNotFound) {
		t.Fatalf("provider across accounts: %v", err)
	}
	if err := st.CreateIAMRole(ctx, store.IAMRole{RoleARN: "arn:r", AccountID: storetest.AccountA, RoleName: "r"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetIAMRoleByARN(ctx, "arn:r"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteIAMRole(ctx, storetest.AccountB, "r"); !errors.Is(err, store.ErrIAMRoleNotFound) {
		t.Fatalf("delete role across accounts: %v", err)
	}
	if err := st.CreateSTSSession(ctx, store.STSSession{AccessKeyID: "ASIA1", AccountID: storetest.AccountA, ExpiresAt: time.Now().Add(time.Hour)}, "sec", "tok"); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSTSSession(ctx, store.STSSession{AccessKeyID: "ASIA2", AccountID: storetest.AccountA, ExpiresAt: time.Now().Add(-time.Minute)}, "sec", "tok"); err != nil {
		t.Fatal(err)
	}
	if acct, sec, tok, _, err := st.GetSTSSessionSecret(ctx, "ASIA1"); err != nil || acct != storetest.AccountA || sec != "sec" || tok != "tok" {
		t.Fatalf("session: %s %s %s %v", acct, sec, tok, err)
	}
	if _, _, _, _, err := st.GetSTSSessionSecret(ctx, "ASIA2"); !errors.Is(err, store.ErrSTSSessionExpired) {
		t.Fatalf("expired session: %v", err)
	}
	if n, _ := st.DeleteExpiredSTSSessions(ctx); n != 1 {
		t.Fatalf("expired sessions deleted = %d", n)
	}
}
