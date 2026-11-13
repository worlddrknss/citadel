package memory

import (
	"testing"

	"github.com/worlddrknss/citadel/internal/store/storetest"
)

func TestAccessKeysContract(t *testing.T) {
	storetest.AccessKeys(t, &Store{})
}
