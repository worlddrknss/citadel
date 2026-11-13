package storetest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// SecretRotationStore checks store.SecretRotationStore: configuration,
// pending versions and the finishSecret label moves, the lease (exactly one
// claimant wins, even concurrently), due listing, history and tenancy.
func SecretRotationStore(t *testing.T, st store.Store) {
	ctxA := store.WithActor(store.WithCallerAccount(context.Background(), AccountA), "system:rotation")
	ctxB := store.WithCallerAccount(context.Background(), AccountB)
	now := time.Now().UTC()

	// Backends that provision per-account keys need one for account A; the
	// memory store falls back to its default key.
	if _, err := st.EnsureAccountDefaultKey(ctxA, AccountA); err != nil && !errors.Is(err, store.ErrUnsupported) {
		t.Fatal(err)
	}
	created, _, err := st.CreateSecret(ctxA, store.CreateSecretRequest{Name: "rot/db", SecretString: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	v1 := created.CurrentVersionID

	if _, err := st.GetSecretRotation(ctxA, "rot/db"); !errors.Is(err, store.ErrRotationNotConfigured) {
		t.Fatalf("GetSecretRotation before configuring = %v", err)
	}
	past := now.Add(-time.Minute)
	meta, err := st.ConfigureSecretRotation(ctxA, store.SecretRotationConfig{
		SecretID: "rot/db", LambdaARN: "arn:citadel:rotator:us-west-2:" + AccountA + ":random", AfterDays: 30,
		NextRotationDate: &past, RotatorType: store.RotatorRandom, Config: `{"length":16}`, SigningKeySealed: []byte{1, 2, 3},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !meta.RotationEnabled || meta.RotationDays != 30 {
		t.Fatalf("metadata after configure = %+v", meta)
	}
	r, err := st.GetSecretRotation(ctxA, created.ARN)
	if err != nil || r.RotatorType != store.RotatorRandom || r.Config != `{"length":16}` || len(r.SigningKeySealed) != 3 {
		t.Fatalf("GetSecretRotation = %+v %v", r, err)
	}
	// Reconfiguring without a key keeps it; ClearSigningKey drops it.
	if _, err := st.ConfigureSecretRotation(ctxA, store.SecretRotationConfig{SecretID: "rot/db", AfterDays: 30, NextRotationDate: &past, RotatorType: store.RotatorRandom}); err != nil {
		t.Fatal(err)
	}
	if r, _ := st.GetSecretRotation(ctxA, "rot/db"); len(r.SigningKeySealed) != 3 {
		t.Fatal("signing key not kept")
	}
	if _, err := st.ConfigureSecretRotation(ctxA, store.SecretRotationConfig{SecretID: "rot/db", AfterDays: 30, NextRotationDate: &past, RotatorType: store.RotatorRandom, ClearSigningKey: true}); err != nil {
		t.Fatal(err)
	}
	if r, _ := st.GetSecretRotation(ctxA, "rot/db"); r.SigningKeySealed != nil {
		t.Fatal("signing key not cleared")
	}
	if _, err := st.GetSecretRotation(ctxB, "rot/db"); err == nil {
		t.Fatal("account B reads account A's rotation")
	}

	t.Run("Due", func(t *testing.T) {
		due, err := st.ListDueSecretRotations(context.Background(), now, 10)
		if err != nil || len(due) != 1 || due[0].AccountID != AccountA || due[0].SecretName != "rot/db" {
			t.Fatalf("ListDueSecretRotations = %+v %v", due, err)
		}
		if due, _ := st.ListDueSecretRotations(context.Background(), now.Add(-time.Hour), 10); len(due) != 0 {
			t.Fatalf("due before the window: %+v", due)
		}
	})

	t.Run("Lease", func(t *testing.T) {
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for i := range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ok, err := st.ClaimSecretRotation(ctxA, "rot/db", "owner-"+string(rune('a'+i)), time.Minute)
				if err != nil {
					t.Error(err)
				}
				if ok {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("lease claimed %d times", wins)
		}
		if due, _ := st.ListDueSecretRotations(context.Background(), now, 10); len(due) != 0 {
			t.Fatalf("leased rotation listed as due: %+v", due)
		}
		if err := st.SaveSecretRotationState(ctxA, "rot/db", "someone-else", store.SecretRotationStateUpdate{Status: store.RotationStatusFailed, LastAttemptAt: now}); !errors.Is(err, store.ErrRotationLeaseLost) {
			t.Fatalf("save by a non-owner = %v", err)
		}
	})

	t.Run("PendingAndFinish", func(t *testing.T) {
		p, err := st.PutPendingSecretVersion(ctxA, "rot/db", "tok-1", "v2", "")
		if err != nil || p.VersionID != "tok-1" {
			t.Fatalf("PutPendingSecretVersion = %+v %v", p, err)
		}
		// Idempotent on the token.
		if again, err := st.PutPendingSecretVersion(ctxA, "rot/db", "tok-1", "other", ""); err != nil || *again.SecretString != "v2" {
			t.Fatalf("second PutPendingSecretVersion = %+v %v", again, err)
		}
		cur, _ := st.GetSecretValue(ctxA, "rot/db", "", "")
		if *cur.SecretString != "v1" {
			t.Fatalf("AWSCURRENT moved by a pending version: %q", *cur.SecretString)
		}
		pend, err := st.GetSecretValue(ctxA, "rot/db", "", store.PendingVersionStage)
		if err != nil || *pend.SecretString != "v2" {
			t.Fatalf("AWSPENDING = %+v %v", pend, err)
		}
		m, _ := st.DescribeSecret(ctxA, "rot/db")
		if store.PendingRotationToken(m) != "tok-1" {
			t.Fatalf("PendingRotationToken = %q", store.PendingRotationToken(m))
		}
		m, err = st.FinishSecretRotation(ctxA, "rot/db", "tok-1")
		if err != nil {
			t.Fatal(err)
		}
		m, _ = st.DescribeSecret(ctxA, "rot/db")
		if m.CurrentVersionID != "tok-1" || m.PreviousVersionID != v1 {
			t.Fatalf("after finish current=%s previous=%s", m.CurrentVersionID, m.PreviousVersionID)
		}
		if got := m.VersionStages["tok-1"]; len(got) != 1 || got[0] != store.CurrentVersionStage {
			t.Fatalf("stages of the new version = %v", got)
		}
		if got := m.VersionStages[v1]; len(got) != 1 || got[0] != store.PreviousVersionStage {
			t.Fatalf("stages of the old version = %v", got)
		}
		if store.PendingRotationToken(m) != "" {
			t.Fatal("AWSPENDING left after finish")
		}
		// Finishing again is a no-op.
		if _, err := st.FinishSecretRotation(ctxA, "rot/db", "tok-1"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.FinishSecretRotation(ctxA, "rot/db", "nope"); err == nil {
			t.Fatal("finish with an unknown token succeeded")
		}
	})

	t.Run("StateAndHistory", func(t *testing.T) {
		// The Lease subtest left a lease with an unknown owner; take a fresh
		// one by saving as each candidate owner.
		var owner string
		for i := range 8 {
			o := "owner-" + string(rune('a'+i))
			if err := st.SaveSecretRotationState(ctxA, "rot/db", o, store.SecretRotationStateUpdate{Status: store.RotationStatusRunning, LastAttemptAt: now, KeepLease: true}); err == nil {
				owner = o
				break
			}
		}
		if owner == "" {
			t.Fatal("no candidate owns the lease")
		}
		next := now.Add(30 * 24 * time.Hour).Truncate(time.Second)
		rotated := now.Truncate(time.Second)
		if err := st.SaveSecretRotationState(ctxA, "rot/db", owner, store.SecretRotationStateUpdate{
			Status: store.RotationStatusSucceeded, LastStep: "finishSecret", LastAttemptAt: now, LastRotatedAt: &rotated, NextRotationDate: &next,
		}); err != nil {
			t.Fatal(err)
		}
		r, _ := st.GetSecretRotation(ctxA, "rot/db")
		if r.Status != store.RotationStatusSucceeded || r.LastRotatedAt == nil || !r.LastRotatedAt.Equal(rotated) || r.LeaseOwner != "" || r.LeaseUntil != nil {
			t.Fatalf("state = %+v", r)
		}
		m, _ := st.DescribeSecret(ctxA, "rot/db")
		if m.NextRotationDate == nil || !m.NextRotationDate.Equal(next) {
			t.Fatalf("NextRotationDate = %v", m.NextRotationDate)
		}
		if ok, _ := st.ClaimSecretRotation(ctxA, "rot/db", "again", time.Minute); !ok {
			t.Fatal("released lease cannot be claimed")
		}
		retry := now.Add(-time.Second)
		if err := st.SaveSecretRotationState(ctxA, "rot/db", "again", store.SecretRotationStateUpdate{Status: store.RotationStatusRetrying, Attempts: 1, LastAttemptAt: now, NextAttemptAt: &retry}); err != nil {
			t.Fatal(err)
		}
		if due, _ := st.ListDueSecretRotations(context.Background(), now, 10); len(due) != 1 {
			t.Fatalf("retry not due: %+v", due)
		}
		for i := range store.MaxRotationHistory + 3 {
			if err := st.AppendSecretRotationHistory(ctxA, "rot/db", store.SecretRotationEvent{
				Token: "t", RotatorType: store.RotatorRandom, Trigger: "schedule", Status: store.RotationStatusSucceeded,
				Step: "finishSecret", StartedAt: now.Add(time.Duration(i) * time.Second), FinishedAt: now.Add(time.Duration(i) * time.Second),
			}); err != nil {
				t.Fatal(err)
			}
		}
		h, err := st.ListSecretRotationHistory(ctxA, "rot/db", 0)
		if err != nil || len(h) != store.MaxRotationHistory || !h[0].StartedAt.After(h[1].StartedAt) {
			t.Fatalf("history = %d events, %v", len(h), err)
		}
		sum, err := st.ListSecretRotationSummaries(ctxA)
		if err != nil || sum["rot/db"].Status != store.RotationStatusRetrying {
			t.Fatalf("summaries = %+v %v", sum, err)
		}
		if sum, _ := st.ListSecretRotationSummaries(ctxB); len(sum) != 0 {
			t.Fatalf("account B summaries = %+v", sum)
		}
	})

	t.Run("CancelKeepsPending", func(t *testing.T) {
		if _, err := st.PutPendingSecretVersion(ctxA, "rot/db", "tok-2", "v3", ""); err != nil {
			t.Fatal(err)
		}
		if _, err := st.CancelRotateSecret(ctxA, "rot/db"); err != nil {
			t.Fatal(err)
		}
		m, _ := st.DescribeSecret(ctxA, "rot/db")
		if m.RotationEnabled || store.PendingRotationToken(m) != "tok-2" {
			t.Fatalf("after cancel enabled=%v pending=%q", m.RotationEnabled, store.PendingRotationToken(m))
		}
		if due, _ := st.ListDueSecretRotations(context.Background(), now, 10); len(due) != 0 {
			t.Fatalf("cancelled rotation is due: %+v", due)
		}
	})

	t.Run("RenameAndDelete", func(t *testing.T) {
		if _, err := st.RenameSecret(ctxA, "rot/db", "rot/db2"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.GetSecretRotation(ctxA, "rot/db2"); err != nil {
			t.Fatalf("rotation lost on rename: %v", err)
		}
		if h, _ := st.ListSecretRotationHistory(ctxA, "rot/db2", 1); len(h) != 1 {
			t.Fatal("history lost on rename")
		}
		if _, err := st.DeleteSecret(ctxA, "rot/db2", 0, true); err != nil {
			t.Fatal(err)
		}
		if sum, _ := st.ListSecretRotationSummaries(ctxA); len(sum) != 0 {
			t.Fatalf("rotation outlived its secret: %+v", sum)
		}
	})
}
