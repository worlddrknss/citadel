package memory

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/storetest"
)

func TestKMSLifecycle(t *testing.T) {
	storetest.KMSLifecycle(t, &Store{AccountID: "000000000000"})
}

func TestBootstrapKeyCannotBeDestroyed(t *testing.T) {
	st := &Store{DefaultKey: store.KMSKey{ID: "boot", MasterKeyRaw: bytes.Repeat([]byte{1}, 32), Enabled: true}}
	if err := st.DestroyKey(context.Background(), "boot"); !errors.Is(err, store.ErrImmutableManagedKey) {
		t.Fatalf("DestroyKey(bootstrap): %v", err)
	}
}
