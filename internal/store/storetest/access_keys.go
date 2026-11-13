package storetest

import (
	"context"
	"errors"
	"testing"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// AccessKeys checks the access-key contract shared by the stores: creation
// (at most two active keys per user and account), lookup with the secret,
// listing, status changes, last-used stamping and deletion. It creates its
// own user and account, so it can run against a shared database.
func AccessKeys(t *testing.T, st store.Store) {
	t.Helper()
	ctx := context.Background()
	acct, err := st.CreateUIAccount(ctx, "ak-"+cryptoutil.RandomHex(4))
	if err != nil {
		t.Fatal(err)
	}
	user := "ak-" + cryptoutil.RandomHex(6)
	if err := st.UpsertUIUser(ctx, store.UIUser{Username: user, Role: "viewer", PasswordHash: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddUserAccount(ctx, user, acct, "editor"); err != nil {
		t.Fatal(err)
	}

	k1, err := st.CreateAccessKey(ctx, user, acct)
	if err != nil {
		t.Fatal(err)
	}
	if k1.AccessKeyID == "" || len(k1.SecretKey) < 20 {
		t.Fatalf("key = %+v", k1)
	}
	owner, gotAcct, secret, status, err := st.GetAccessKeyByID(ctx, k1.AccessKeyID)
	if err != nil || owner != user || gotAcct != acct || secret != k1.SecretKey || status != "Active" {
		t.Fatalf("lookup = %q %q %q %q %v", owner, gotAcct, secret, status, err)
	}
	if _, _, _, _, err := st.GetAccessKeyByID(ctx, "AKIANOSUCHKEY0000000"); !errors.Is(err, store.ErrAccessKeyNotFound) {
		t.Fatalf("unknown key: %v", err)
	}
	k2, err := st.CreateAccessKey(ctx, user, acct)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateAccessKey(ctx, user, acct); !errors.Is(err, store.ErrMaxAccessKeys) {
		t.Fatalf("third active key: %v", err)
	}
	if err := st.SetAccessKeyStatus(ctx, k2.AccessKeyID, "Inactive"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, status, _ := st.GetAccessKeyByID(ctx, k2.AccessKeyID); status != "Inactive" {
		t.Fatalf("status after deactivate = %q", status)
	}
	if err := st.TouchAccessKeyLastUsed(ctx, k1.AccessKeyID); err != nil {
		t.Fatal(err)
	}
	keys, err := st.ListAccessKeys(ctx, user, acct)
	if err != nil || len(keys) != 2 {
		t.Fatalf("list = %+v %v", keys, err)
	}
	for _, k := range keys {
		if k.AccessKeyID == k1.AccessKeyID && k.LastUsedAt == nil {
			t.Fatal("last used not recorded")
		}
	}
	if err := st.DeleteAccessKey(ctx, k2.AccessKeyID); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteAccessKey(ctx, k2.AccessKeyID); !errors.Is(err, store.ErrAccessKeyNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	if keys, _ := st.ListAccessKeys(ctx, user, acct); len(keys) != 1 {
		t.Fatalf("list after delete = %+v", keys)
	}
}
