package postgres

import (
	"context"
	"testing"

	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/storetest"
)

func TestAgentMintedStore(t *testing.T) {
	storetest.AgentMintedStore(t, func(t *testing.T) store.Store {
		st, err := Open(context.Background(), testDB(t), testOptions())
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		return st
	})
}
