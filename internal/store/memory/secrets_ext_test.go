package memory

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/storetest"
)

func TestSecretsExtensions(t *testing.T) {
	key := store.KMSKey{ID: "memkey", MasterKeyRaw: bytes.Repeat([]byte{7}, 32), Enabled: true, CreatedAt: time.Now(), KeyUsage: store.KeyUsageEncryptDecrypt, KeySpec: store.KeySpecSymmetricDefault}
	st := &Store{DefaultKey: key, Keys: []store.KMSKey{key}, AccountID: "999999999999"}
	storetest.RunSecretsExtensions(t, st, func(*testing.T, context.Context) string { return key.ID })
}
