package memory

import (
	"testing"

	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/storetest"
)

func TestAgentStore(t *testing.T) {
	storetest.AgentStore(t, func(*testing.T) store.Store {
		return &Store{AuditHMACKey: []byte("0123456789abcdef0123456789abcdef")}
	})
}
