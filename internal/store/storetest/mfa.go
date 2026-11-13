package storetest

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// MFAStore exercises store.MFAStore against a fresh, empty store.
func MFAStore(t *testing.T, newStore func(t *testing.T) store.Store) {
	t.Run("Lifecycle", func(t *testing.T) { testMFALifecycle(t, newStore(t)) })
	t.Run("RecoveryCodes", func(t *testing.T) { testMFARecoveryCodes(t, newStore(t)) })
	t.Run("StepReplayRace", func(t *testing.T) { testMFAStepRace(t, newStore(t)) })
	t.Run("LoginTokens", func(t *testing.T) { testMFALoginTokens(t, newStore(t)) })
	t.Run("UserDeleteCascades", func(t *testing.T) { testMFAUserDelete(t, newStore(t)) })
}

func testMFALifecycle(t *testing.T, st store.Store) {
	ctx := context.Background()
	addUser(t, st, "alice")
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := st.GetMFA(ctx, "alice"); !errors.Is(err, store.ErrMFANotFound) {
		t.Fatalf("GetMFA before enrolment err = %v", err)
	}
	if err := st.PutPendingMFA(ctx, "alice", []byte("sealed-1"), now); err != nil {
		t.Fatalf("PutPendingMFA: %v", err)
	}
	// A second start replaces the pending secret.
	if err := st.PutPendingMFA(ctx, "alice", []byte("sealed-2"), now); err != nil {
		t.Fatalf("PutPendingMFA again: %v", err)
	}
	e, err := st.GetMFA(ctx, "alice")
	if err != nil || e.Enabled || string(e.SecretEnc) != "sealed-2" || !e.EnabledAt.IsZero() {
		t.Fatalf("pending = %+v, %v", e, err)
	}
	if users, _ := st.ListMFAEnabledUsers(ctx); len(users) != 0 {
		t.Fatalf("enabled users while pending = %v", users)
	}
	// Confirming the replaced secret fails.
	if err := st.EnableMFA(ctx, "alice", []byte("sealed-1"), 10, []string{"h1"}, now); !errors.Is(err, store.ErrMFANotFound) {
		t.Fatalf("EnableMFA(stale secret) err = %v", err)
	}
	if err := st.ReplaceMFARecoveryCodes(ctx, "alice", []string{"x"}); !errors.Is(err, store.ErrMFANotFound) {
		t.Fatalf("ReplaceMFARecoveryCodes while pending err = %v", err)
	}
	if err := st.EnableMFA(ctx, "alice", []byte("sealed-2"), 10, []string{"h1", "h2"}, now); err != nil {
		t.Fatalf("EnableMFA: %v", err)
	}
	e, err = st.GetMFA(ctx, "alice")
	if err != nil || !e.Enabled || e.LastStep != 10 || !e.EnabledAt.Equal(now) || e.RecoveryCodesLeft != 2 {
		t.Fatalf("enabled = %+v, %v", e, err)
	}
	if err := st.EnableMFA(ctx, "alice", []byte("sealed-2"), 11, nil, now); !errors.Is(err, store.ErrMFANotFound) {
		t.Fatalf("EnableMFA twice err = %v", err)
	}
	if err := st.PutPendingMFA(ctx, "alice", []byte("sealed-3"), now); !errors.Is(err, store.ErrMFAAlreadyEnabled) {
		t.Fatalf("PutPendingMFA while enabled err = %v", err)
	}
	if users, _ := st.ListMFAEnabledUsers(ctx); len(users) != 1 || users[0] != "alice" {
		t.Fatalf("enabled users = %v", users)
	}
	// Steps only move forward.
	for _, tc := range []struct {
		step int64
		want bool
	}{{10, false}, {9, false}, {11, true}, {11, false}, {13, true}} {
		ok, err := st.AdvanceMFAStep(ctx, "alice", tc.step)
		if err != nil || ok != tc.want {
			t.Fatalf("AdvanceMFAStep(%d) = %v, %v; want %v", tc.step, ok, err, tc.want)
		}
	}
	existed, err := st.DeleteMFA(ctx, "alice")
	if err != nil || !existed {
		t.Fatalf("DeleteMFA = %v, %v", existed, err)
	}
	if existed, _ := st.DeleteMFA(ctx, "alice"); existed {
		t.Fatal("DeleteMFA reported a second deletion")
	}
	if _, err := st.GetMFA(ctx, "alice"); !errors.Is(err, store.ErrMFANotFound) {
		t.Fatalf("GetMFA after delete err = %v", err)
	}
	if hs, _ := st.ListMFARecoveryCodeHashes(ctx, "alice"); len(hs) != 0 {
		t.Fatalf("recovery codes after delete = %v", hs)
	}
}

func testMFARecoveryCodes(t *testing.T, st store.Store) {
	ctx := context.Background()
	addUser(t, st, "bob")
	now := time.Now().UTC()
	if err := st.PutPendingMFA(ctx, "bob", []byte("s"), now); err != nil {
		t.Fatal(err)
	}
	if err := st.EnableMFA(ctx, "bob", []byte("s"), 1, []string{"a", "b", "c"}, now); err != nil {
		t.Fatal(err)
	}
	// Concurrent consumers of one code: exactly one wins.
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, err := st.ConsumeMFARecoveryCode(ctx, "bob", "b"); err == nil && ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d concurrent consumers of one code succeeded", wins.Load())
	}
	if ok, _ := st.ConsumeMFARecoveryCode(ctx, "bob", "nope"); ok {
		t.Fatal("unknown code consumed")
	}
	hs, err := st.ListMFARecoveryCodeHashes(ctx, "bob")
	if err != nil || len(hs) != 2 || hs[0] != "a" || hs[1] != "c" {
		t.Fatalf("unused codes = %v, %v", hs, err)
	}
	if e, _ := st.GetMFA(ctx, "bob"); e.RecoveryCodesLeft != 2 {
		t.Fatalf("RecoveryCodesLeft = %d", e.RecoveryCodesLeft)
	}
	if err := st.ReplaceMFARecoveryCodes(ctx, "bob", []string{"x", "y"}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := st.ConsumeMFARecoveryCode(ctx, "bob", "a"); ok {
		t.Fatal("replaced code still usable")
	}
	if hs, _ := st.ListMFARecoveryCodeHashes(ctx, "bob"); len(hs) != 2 || hs[0] != "x" {
		t.Fatalf("codes after replace = %v", hs)
	}
}

func testMFAStepRace(t *testing.T, st store.Store) {
	ctx := context.Background()
	addUser(t, st, "carol")
	now := time.Now().UTC()
	if err := st.PutPendingMFA(ctx, "carol", []byte("s"), now); err != nil {
		t.Fatal(err)
	}
	if err := st.EnableMFA(ctx, "carol", []byte("s"), 100, nil, now); err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, err := st.AdvanceMFAStep(ctx, "carol", 101); err == nil && ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d concurrent uses of one step succeeded", wins.Load())
	}
}

func testMFALoginTokens(t *testing.T, st store.Store) {
	ctx := context.Background()
	now := time.Now().UTC()
	ok, err := st.UseMFALoginToken(ctx, "tok-1", now.Add(5*time.Minute), now)
	if err != nil || !ok {
		t.Fatalf("first use = %v, %v", ok, err)
	}
	if ok, _ := st.UseMFALoginToken(ctx, "tok-1", now.Add(5*time.Minute), now); ok {
		t.Fatal("token used twice")
	}
	if ok, _ := st.UseMFALoginToken(ctx, "tok-2", now.Add(5*time.Minute), now); !ok {
		t.Fatal("independent token refused")
	}
	// After expiry the record may be purged; the server rejects expired
	// tokens before ever calling the store.
	if _, err := st.UseMFALoginToken(ctx, "tok-3", now.Add(time.Minute), now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
}

func testMFAUserDelete(t *testing.T, st store.Store) {
	ctx := context.Background()
	addUser(t, st, "dave")
	now := time.Now().UTC()
	if err := st.PutPendingMFA(ctx, "dave", []byte("s"), now); err != nil {
		t.Fatal(err)
	}
	if err := st.EnableMFA(ctx, "dave", []byte("s"), 1, []string{"a"}, now); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteUIUser(ctx, "dave"); err != nil {
		t.Fatal(err)
	}
	addUser(t, st, "dave")
	if _, err := st.GetMFA(ctx, "dave"); !errors.Is(err, store.ErrMFANotFound) {
		t.Fatalf("recreated user inherited MFA: %v", err)
	}
}
