package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/storetest"
)

func TestAWSPageStore(t *testing.T) {
	db := testDB(t)
	st, err := Open(context.Background(), db, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	storetest.AWSPageStore(t, st, true)
}

// TestUpdateAliasIsAccountScoped: alias names are unique per account, so
// re-pointing one account's alias must not touch another's of the same name.
func TestUpdateAliasIsAccountScoped(t *testing.T) {
	db := testDB(t)
	st, err := Open(context.Background(), db, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	ctxA := store.WithCallerAccount(context.Background(), storetest.AccountA)
	ctxB := store.WithCallerAccount(context.Background(), storetest.AccountB)
	ka, err := st.CreateKey(ctxA, "a", "", "")
	if err != nil {
		t.Fatal(err)
	}
	ka2, err := st.CreateKey(ctxA, "a2", "", "")
	if err != nil {
		t.Fatal(err)
	}
	kb, err := st.CreateKey(ctxB, "b", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateAlias(ctxA, "alias/shared", ka.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateAlias(ctxB, "alias/shared", kb.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateAlias(ctxA, "alias/shared", ka2.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := st.ResolveByID(ctxB, "alias/shared"); err != nil || got.ID != kb.ID {
		t.Fatalf("account B alias now resolves to %q (%v), want %q", got.ID, err, kb.ID)
	}
	if err := st.UpdateAlias(ctxB, "alias/missing", kb.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing alias: %v", err)
	}
}
