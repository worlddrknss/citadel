package server

import (
	"context"

	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/postgres"
)

// ensureManagedDefaultKeys provisions the immutable per-account default key for
// every known account at startup. It is idempotent and only operates on
// DB-backed deployments.
func ensureManagedDefaultKeys(ctx context.Context, store store.Store) error {
	db, ok := store.(*postgres.Store)
	if !ok {
		return nil
	}
	return db.EnsureManagedDefaultKeys(ctx)
}
