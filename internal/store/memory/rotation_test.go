package memory

import (
	"bytes"
	"testing"

	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/storetest"
)

func TestSecretRotationStore(t *testing.T) {
	st := &Store{DefaultKey: store.KMSKey{ID: "boot", ARN: "arn:aws:kms:us-east-1:000000000000:key/boot", MasterKeyRaw: bytes.Repeat([]byte{1}, 32), Enabled: true}}
	storetest.SecretRotationStore(t, st)
}
