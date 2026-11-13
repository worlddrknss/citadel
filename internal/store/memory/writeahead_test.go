package memory

import (
	"testing"

	"github.com/worlddrknss/citadel/internal/store/storetest"
)

func TestWriteAheadAudit(t *testing.T) {
	storetest.WriteAheadAudit(t, &Store{AccountID: "000000000000"}, "000000000000")
}
