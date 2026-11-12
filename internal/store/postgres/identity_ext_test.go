package postgres

import (
	"context"
	"testing"

	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/storetest"
)

func TestIdentityStore(t *testing.T) {
	storetest.IdentityStore(t, func(t *testing.T) store.Store {
		st, err := Open(context.Background(), testDB(t), testOptions())
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		return st
	})
}
