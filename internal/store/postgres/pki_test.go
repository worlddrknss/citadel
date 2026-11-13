package postgres

import (
	"context"
	"testing"

	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/storetest"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(context.Background(), testDB(t), testOptions())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return st
}

func TestPKIStoreContract(t *testing.T) {
	st := openTestStore(t)
	storetest.RunPKI(t, storetest.PKIEnv{
		Store: st,
		NewCAKey: func(ctx context.Context) string {
			k, err := st.CreateKey(ctx, "ca key", store.KeyUsageSignVerify, store.KeySpecECCP256)
			if err != nil {
				t.Fatalf("create CA key: %v", err)
			}
			return k.ID
		},
	})
}

func TestPKIParityStoreContract(t *testing.T) {
	st := openTestStore(t)
	storetest.RunPKIParity(t, storetest.PKIEnv{
		Store: st,
		NewCAKey: func(ctx context.Context) string {
			k, err := st.CreateKey(ctx, "ca key", store.KeyUsageSignVerify, store.KeySpecECCP256)
			if err != nil {
				t.Fatalf("create CA key: %v", err)
			}
			return k.ID
		},
	})
}

func TestACMEServerStoreContract(t *testing.T) {
	storetest.RunACMEStore(t, openTestStore(t).ACMEServerStore())
}
