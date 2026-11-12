package postgres

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/worlddrknss/citadel/internal/store"
)

// TestWrappingKeyRotationKeepsDerivedKeys walks the documented rotation:
// run on key 1, restart with key 2 plus key 1 as previous, re-wrap, restart
// with key 2 alone. The root secret, and so the audit chain key and every
// other derived key, must not change, and the existing chain must verify.
func TestWrappingKeyRotationKeepsDerivedKeys(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	key1 := bytes.Repeat([]byte{1}, 32)
	key2 := bytes.Repeat([]byte{2}, 32)
	const acct = "111111111111"
	actx := store.WithCallerAccount(ctx, acct)

	s1, err := Open(ctx, db, Options{WrappingKey: key1, AccountID: acct})
	if err != nil {
		t.Fatalf("open with key 1: %v", err)
	}
	if !bytes.Equal(s1.ServiceRoot(), key1) {
		t.Fatal("a new root secret must start as the current wrapping key, so existing derived keys keep their values")
	}
	for i := 0; i < 3; i++ {
		if err := s1.RecordAudit(actx, store.AuditEvent{Action: "test.Event", Result: "success", AuditOrigin: store.AuditOrigin{AccountID: acct, Actor: "alice"}}); err != nil {
			t.Fatalf("record audit: %v", err)
		}
	}
	root := append([]byte(nil), s1.ServiceRoot()...)
	chainKey := append([]byte(nil), s1.auditHMACKey...)

	// Rotate: key 2 is current, key 1 is kept to unwrap.
	s2, err := Open(ctx, db, Options{WrappingKey: key2, PreviousWrappingKeys: [][]byte{key1}, AccountID: acct})
	if err != nil {
		t.Fatalf("open after rotation: %v", err)
	}
	if !bytes.Equal(s2.ServiceRoot(), root) || !bytes.Equal(s2.auditHMACKey, chainKey) {
		t.Fatal("rotating the wrapping key changed the root secret or the audit chain key")
	}
	report, err := s2.RewrapAll(ctx)
	if err != nil {
		t.Fatalf("rewrap: %v", err)
	}
	if report.ServiceKeys != 1 {
		t.Fatalf("rewrap re-wrapped %d service keys, want 1", report.ServiceKeys)
	}

	// Key 1 retired entirely.
	s3, err := Open(ctx, db, Options{WrappingKey: key2, AccountID: acct})
	if err != nil {
		t.Fatalf("open with key 2 only: %v", err)
	}
	if !bytes.Equal(s3.ServiceRoot(), root) {
		t.Fatal("root secret changed after retiring the old wrapping key")
	}
	v, err := s3.VerifyAuditChain(ctx, acct, true)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.Status != store.AuditChainVerified {
		t.Fatalf("audit chain status after rotation = %q, want verified", v.Status)
	}
}

func TestRootSecretNotCreatedDuringRotation(t *testing.T) {
	db := testDB(t)
	_, err := Open(context.Background(), db, Options{
		WrappingKey:          bytes.Repeat([]byte{2}, 32),
		PreviousWrappingKeys: [][]byte{bytes.Repeat([]byte{1}, 32)},
	})
	if err == nil || !strings.Contains(err.Error(), "KMS_PREVIOUS_WRAPPING_KEYS_B64") {
		t.Fatalf("expected a refusal to create the root secret mid-rotation, got %v", err)
	}
}
