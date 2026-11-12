package memory

import (
	"testing"

	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/storetest"
)

func TestAuthStore(t *testing.T) {
	storetest.AuthStore(t, func(*testing.T) store.Store { return &Store{} })
}
