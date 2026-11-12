package postgres

import (
	"context"
	"testing"

	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/storetest"
)

func TestSecretsExtensions(t *testing.T) {
	db := testDB(t)
	st, err := Open(context.Background(), db, testOptions())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	storetest.RunSecretsExtensions(t, st, func(t *testing.T, ctx context.Context) string {
		k, err := st.CreateKey(ctx, "test", store.KeyUsageEncryptDecrypt, store.KeySpecSymmetricDefault)
		if err != nil {
			t.Fatal(err)
		}
		return k.ID
	})
}
