package memory

import (
	"testing"

	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/storetest"
)

func TestIdentityStore(t *testing.T) {
	storetest.IdentityStore(t, func(*testing.T) store.Store { return &Store{} })
}
