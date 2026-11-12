package memory

import (
	"context"
	"fmt"
	"testing"

	"github.com/worlddrknss/citadel/internal/store/storetest"
)

func TestPKIStoreContract(t *testing.T) {
	n := 0
	storetest.RunPKI(t, storetest.PKIEnv{
		Store: &Store{},
		NewCAKey: func(context.Context) string {
			n++
			return fmt.Sprintf("key-%d", n)
		},
	})
}
