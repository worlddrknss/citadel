package memory

import (
	"testing"

	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/storetest"
)

func TestMFAStore(t *testing.T) {
	storetest.MFAStore(t, func(*testing.T) store.Store { return &Store{} })
}
