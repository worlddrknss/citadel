package storetest

import (
	"testing"

	"github.com/worlddrknss/citadel/internal/acme"
)

// The reference implementation must satisfy the same contract the SQL store
// is held to.
func TestMemoryACMEStoreContract(t *testing.T) {
	RunACMEStore(t, acme.NewMemoryStore())
}
