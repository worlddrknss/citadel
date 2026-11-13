package storetest

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// AgentAccessStore exercises store.AgentAccessStore (2.3) against a fresh,
// empty store.
func AgentAccessStore(t *testing.T, newStore func(t *testing.T) store.Store) {
	t.Run("RequireFederation", func(t *testing.T) { testAgentRequireFederation(t, newStore(t)) })
	t.Run("Requests", func(t *testing.T) { testAgentAccessRequests(t, newStore(t)) })
	t.Run("ConcurrentOpen", func(t *testing.T) { testAgentAccessConcurrentOpen(t, newStore(t)) })
	t.Run("Leases", func(t *testing.T) { testAgentLeases(t, newStore(t)) })
	t.Run("OnceLeaseConcurrency", func(t *testing.T) { testAgentOnceLeaseConcurrency(t, newStore(t)) })
	t.Run("ConcurrentDecisions", func(t *testing.T) { testAgentConcurrentDecisions(t, newStore(t)) })
	t.Run("DeleteCascades", func(t *testing.T) { testAgentAccessCascade(t, newStore(t)) })
}

func testAgentRequireFederation(t *testing.T, st store.Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	a := mustCreateAgent(t, st, newTestAgent(AccountA, "ci", now))
	if got, _ := st.GetAgent(ctx, AccountA, a.AgentID); got.RequireFederation {
		t.Fatal("new agent requires federation")
	}
	a.RequireFederation = true
	if err := st.UpdateAgent(ctx, a); err != nil {
		t.Fatalf("UpdateAgent: %v", err)
	}
	if got, _ := st.LookupAgent(ctx, a.AgentID); !got.RequireFederation {
		t.Fatal("RequireFederation not stored")
	}
	b := newTestAgent(AccountA, "ci2", now)
	b.RequireFederation = true
	mustCreateAgent(t, st, b)
	if got, _ := st.GetAgent(ctx, AccountA, b.AgentID); !got.RequireFederation {
		t.Fatal("RequireFederation not stored on create")
	}
}

func newAccessRequest(a store.Agent, cred string, actions []string, task string, now time.Time) store.AgentAccessRequest {
	return store.AgentAccessRequest{
		AccountID: a.AccountID, RequestID: store.NewAgentAccessRequestID(), AgentID: a.AgentID, Credential: cred, Actions: actions,
		Reason: "deploy", TaskID: task, DurationSeconds: 600, Origin: store.AgentRequestOriginAgent, Status: store.AgentRequestPending,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
}

func testAgentAccessRequests(t *testing.T, st store.Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	a := mustCreateAgent(t, st, newTestAgent(AccountA, "coder", now))
	r1, created, err := st.OpenAgentAccessRequest(ctx, newAccessRequest(a, "gh", []string{"use", "reveal"}, "t1", now), now)
	if err != nil || !created || !slices.Equal(r1.Actions, []string{"reveal", "use"}) || r1.Status != store.AgentRequestPending {
		t.Fatalf("Open = %+v, %v, %v", r1, created, err)
	}
	// Same key (actions in another order) returns the open request.
	r2, created, err := st.OpenAgentAccessRequest(ctx, newAccessRequest(a, "gh", []string{"reveal", "use"}, "t1", now), now)
	if err != nil || created || r2.RequestID != r1.RequestID {
		t.Fatalf("reopen = %+v, %v, %v", r2, created, err)
	}
	// Another task is another request.
	r3, created, _ := st.OpenAgentAccessRequest(ctx, newAccessRequest(a, "gh", []string{"use", "reveal"}, "t2", now), now)
	if !created || r3.RequestID == r1.RequestID {
		t.Fatal("another task reused the request")
	}
	if _, _, err := st.OpenAgentAccessRequest(ctx, newAccessRequest(store.Agent{AccountID: AccountB, AgentID: a.AgentID}, "gh", []string{"use"}, "", now), now); !errors.Is(err, store.ErrAgentNotFound) {
		t.Fatalf("open in another account err = %v", err)
	}
	got, err := st.GetAgentAccessRequest(ctx, AccountA, r1.RequestID)
	if err != nil || got.Reason != "deploy" || got.DurationSeconds != 600 || got.TaskID != "t1" || got.Origin != store.AgentRequestOriginAgent || !got.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	if _, err := st.GetAgentAccessRequest(ctx, AccountB, r1.RequestID); !errors.Is(err, store.ErrAgentAccessRequestNotFound) {
		t.Fatalf("Get from another account err = %v", err)
	}
	if n, _ := st.CountPendingAgentAccessRequests(ctx, AccountA, a.AgentID, now); n != 2 {
		t.Fatalf("pending = %d", n)
	}
	list, _ := st.ListAgentAccessRequests(ctx, AccountA, store.AgentAccessRequestFilter{AgentID: a.AgentID, Pending: true, Now: now})
	if len(list) != 2 {
		t.Fatalf("list = %+v", list)
	}

	// Approve r1 with a lease; deciding again fails.
	lease := store.AgentLease{
		AccountID: AccountA, LeaseID: store.NewAgentLeaseID(), AgentID: a.AgentID, Credential: "gh", Actions: []string{"use"},
		Scope: store.AgentLeaseOnce, UsesLeft: ptrInt(1), ExpiresAt: now.Add(time.Hour), CreatedAt: now, CreatedBy: "alice",
	}
	dec, err := st.DecideAgentAccessRequest(ctx, AccountA, r1.RequestID, store.AgentAccessDecision{Status: store.AgentRequestApproved, By: "alice", Comment: "ok", At: now, Lease: &lease})
	if err != nil || dec.Status != store.AgentRequestApproved || dec.LeaseID != lease.LeaseID || dec.Scope != store.AgentLeaseOnce || dec.DecidedBy != "alice" || dec.DecidedAt == nil {
		t.Fatalf("Decide = %+v, %v", dec, err)
	}
	if l, err := st.GetAgentLease(ctx, AccountA, lease.LeaseID); err != nil || l.RequestID != r1.RequestID || *l.UsesLeft != 1 {
		t.Fatalf("lease = %+v, %v", l, err)
	}
	if _, err := st.DecideAgentAccessRequest(ctx, AccountA, r1.RequestID, store.AgentAccessDecision{Status: store.AgentRequestDenied, By: "bob", At: now}); !errors.Is(err, store.ErrAgentAccessRequestDecided) {
		t.Fatalf("second decision err = %v", err)
	}
	if _, err := st.DecideAgentAccessRequest(ctx, AccountB, r3.RequestID, store.AgentAccessDecision{Status: store.AgentRequestDenied, By: "bob", At: now}); !errors.Is(err, store.ErrAgentAccessRequestNotFound) {
		t.Fatalf("decision from another account err = %v", err)
	}
	// After approval, asking again opens a new request.
	r4, created, _ := st.OpenAgentAccessRequest(ctx, newAccessRequest(a, "gh", []string{"use", "reveal"}, "t1", now), now)
	if !created || r4.RequestID == r1.RequestID {
		t.Fatal("decided request was reused")
	}

	// Expired requests can't be decided, and stop holding the key.
	later := now.Add(2 * time.Hour)
	if _, err := st.DecideAgentAccessRequest(ctx, AccountA, r3.RequestID, store.AgentAccessDecision{Status: store.AgentRequestDenied, By: "bob", At: later}); !errors.Is(err, store.ErrAgentAccessRequestDecided) {
		t.Fatalf("decide expired err = %v", err)
	}
	if got, _ := st.GetAgentAccessRequest(ctx, AccountA, r3.RequestID); got.EffectiveStatus(later) != store.AgentRequestExpired {
		t.Fatalf("expired status = %s", got.EffectiveStatus(later))
	}
	r5, created, _ := st.OpenAgentAccessRequest(ctx, newAccessRequest(a, "gh", []string{"use", "reveal"}, "t2", later), later)
	if !created || r5.RequestID == r3.RequestID {
		t.Fatal("expired request was reused")
	}
	if n, _ := st.CountPendingAgentAccessRequests(ctx, AccountA, a.AgentID, later); n != 1 {
		t.Fatalf("pending later = %d", n)
	}

	// Cancel the agent's pending requests.
	if n, err := st.CancelAgentAccessRequests(ctx, AccountA, a.AgentID, "alice", "revoked", later); err != nil || n != 1 {
		t.Fatalf("Cancel = %d, %v", n, err)
	}
	if got, _ := st.GetAgentAccessRequest(ctx, AccountA, r5.RequestID); got.Status != store.AgentRequestCancelled || got.DecidedBy != "alice" {
		t.Fatalf("cancelled = %+v", got)
	}
	all, _ := st.ListAgentAccessRequests(ctx, AccountA, store.AgentAccessRequestFilter{})
	if len(all) != 4 {
		t.Fatalf("all = %d", len(all))
	}
	if limited, _ := st.ListAgentAccessRequests(ctx, AccountA, store.AgentAccessRequestFilter{Limit: 2}); len(limited) != 2 {
		t.Fatalf("limited = %d", len(limited))
	}
}

func ptrInt(v int) *int { return &v }

func testAgentAccessConcurrentOpen(t *testing.T, st store.Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	a := mustCreateAgent(t, st, newTestAgent(AccountA, "coder", now))
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		ids     = map[string]bool{}
		created atomic.Int32
	)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, c, err := st.OpenAgentAccessRequest(ctx, newAccessRequest(a, "gh", []string{"use"}, "", now), now)
			if err != nil {
				t.Errorf("Open: %v", err)
				return
			}
			if c {
				created.Add(1)
			}
			mu.Lock()
			ids[r.RequestID] = true
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(ids) != 1 || created.Load() != 1 {
		t.Fatalf("concurrent opens made %d requests (%d created)", len(ids), created.Load())
	}
}

func newLease(a store.Agent, cred, scope string, uses *int, task string, now time.Time, ttl time.Duration) store.AgentLease {
	return store.AgentLease{
		AccountID: a.AccountID, LeaseID: store.NewAgentLeaseID(), AgentID: a.AgentID, Credential: cred, Actions: []string{"use", "reveal"},
		Scope: scope, TaskID: task, UsesLeft: uses, ExpiresAt: now.Add(ttl), CreatedAt: now, CreatedBy: "alice",
	}
}

func testAgentLeases(t *testing.T, st store.Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	a := mustCreateAgent(t, st, newTestAgent(AccountA, "coder", now))
	b := mustCreateAgent(t, st, newTestAgent(AccountA, "other", now))
	m := func(action, task string, at time.Time) store.AgentLeaseMatch {
		return store.AgentLeaseMatch{AccountID: AccountA, AgentID: a.AgentID, Credential: "gh", Action: action, TaskID: task, Now: at}
	}
	if _, ok, err := st.ConsumeAgentLease(ctx, m("use", "", now)); ok || err != nil {
		t.Fatalf("consume with no lease = %v, %v", ok, err)
	}
	once := newLease(a, "gh", store.AgentLeaseOnce, ptrInt(1), "", now, time.Hour)
	task := newLease(a, "gh", store.AgentLeaseTask, nil, "run-1", now, 30*time.Minute)
	if err := st.CreateAgentLease(ctx, once); err != nil {
		t.Fatalf("CreateAgentLease: %v", err)
	}
	if err := st.CreateAgentLease(ctx, task); err != nil {
		t.Fatalf("CreateAgentLease: %v", err)
	}
	if err := st.CreateAgentLease(ctx, store.AgentLease{AccountID: AccountB, LeaseID: store.NewAgentLeaseID(), AgentID: a.AgentID, Credential: "gh", Actions: []string{"use"}, Scope: "duration", ExpiresAt: now.Add(time.Hour), CreatedAt: now}); !errors.Is(err, store.ErrAgentNotFound) {
		t.Fatalf("lease in another account err = %v", err)
	}
	// totp is not covered.
	if _, ok, _ := st.FindAgentLease(ctx, m("totp", "", now)); ok {
		t.Fatal("lease matched an action it doesn't cover")
	}
	// Another credential or agent doesn't match.
	if _, ok, _ := st.FindAgentLease(ctx, store.AgentLeaseMatch{AccountID: AccountA, AgentID: b.AgentID, Credential: "gh", Action: "use", Now: now}); ok {
		t.Fatal("lease matched another agent")
	}
	// Task run-1 prefers the unlimited task lease over the single use.
	l, ok, err := st.FindAgentLease(ctx, m("use", "run-1", now))
	if err != nil || !ok || l.LeaseID != task.LeaseID {
		t.Fatalf("Find(run-1) = %+v, %v, %v", l, ok, err)
	}
	for i := 0; i < 3; i++ {
		l, ok, err = st.ConsumeAgentLease(ctx, m("use", "run-1", now))
		if err != nil || !ok || l.LeaseID != task.LeaseID || l.UsesLeft != nil || l.UseCount != i+1 || l.LastUsedAt == nil {
			t.Fatalf("Consume(run-1) #%d = %+v, %v, %v", i, l, ok, err)
		}
	}
	// Without the task, only the single-use lease matches, once.
	l, ok, _ = st.ConsumeAgentLease(ctx, m("reveal", "", now))
	if !ok || l.LeaseID != once.LeaseID || *l.UsesLeft != 0 {
		t.Fatalf("Consume(once) = %+v, %v", l, ok)
	}
	if _, ok, _ := st.ConsumeAgentLease(ctx, m("use", "", now)); ok {
		t.Fatal("single-use lease used twice")
	}
	if _, ok, _ := st.ConsumeAgentLease(ctx, m("use", "run-2", now)); ok {
		t.Fatal("task lease used by another task")
	}
	// Expired leases don't match.
	if _, ok, _ := st.ConsumeAgentLease(ctx, m("use", "run-1", now.Add(31*time.Minute))); ok {
		t.Fatal("expired lease used")
	}
	active, _ := st.ListAgentLeases(ctx, AccountA, a.AgentID, true, now)
	if len(active) != 1 || active[0].LeaseID != task.LeaseID {
		t.Fatalf("active leases = %+v", active)
	}
	all, _ := st.ListAgentLeases(ctx, AccountA, "", false, now)
	if len(all) != 2 {
		t.Fatalf("all leases = %d", len(all))
	}
	// End one lease; ending again or an exhausted lease fails.
	ended, err := st.EndAgentLease(ctx, AccountA, task.LeaseID, "bob", "done", now)
	if err != nil || ended.EndedAt == nil || ended.EndedBy != "bob" || ended.EndedReason != "done" {
		t.Fatalf("EndAgentLease = %+v, %v", ended, err)
	}
	if _, err := st.EndAgentLease(ctx, AccountA, task.LeaseID, "bob", "", now); !errors.Is(err, store.ErrAgentLeaseEnded) {
		t.Fatalf("end again err = %v", err)
	}
	if _, err := st.EndAgentLease(ctx, AccountA, once.LeaseID, "bob", "", now); !errors.Is(err, store.ErrAgentLeaseEnded) {
		t.Fatalf("end exhausted err = %v", err)
	}
	if _, err := st.EndAgentLease(ctx, AccountB, task.LeaseID, "bob", "", now); !errors.Is(err, store.ErrAgentLeaseNotFound) {
		t.Fatalf("end from another account err = %v", err)
	}
	if _, ok, _ := st.ConsumeAgentLease(ctx, m("use", "run-1", now)); ok {
		t.Fatal("ended lease used")
	}
	// End every lease of an agent, or of the account.
	for _, x := range []store.AgentLease{
		newLease(a, "gh", store.AgentLeaseDuration, nil, "", now, time.Hour),
		newLease(a, "npm", store.AgentLeaseDuration, nil, "", now, time.Hour),
		newLease(b, "gh", store.AgentLeaseDuration, nil, "", now, time.Hour),
	} {
		if err := st.CreateAgentLease(ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := st.EndAgentLeases(ctx, AccountA, a.AgentID, "alice", "suspended", now); err != nil || n != 2 {
		t.Fatalf("EndAgentLeases(agent) = %d, %v", n, err)
	}
	if n, err := st.EndAgentLeases(ctx, AccountA, "", "alice", "kill switch", now); err != nil || n != 1 {
		t.Fatalf("EndAgentLeases(account) = %d, %v", n, err)
	}
	if active, _ := st.ListAgentLeases(ctx, AccountA, "", true, now); len(active) != 0 {
		t.Fatalf("active after ending = %+v", active)
	}
}

func testAgentOnceLeaseConcurrency(t *testing.T, st store.Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	a := mustCreateAgent(t, st, newTestAgent(AccountA, "coder", now))
	for round := 0; round < 5; round++ {
		once := newLease(a, "gh", store.AgentLeaseOnce, ptrInt(1), "", now, time.Hour)
		if err := st.CreateAgentLease(ctx, once); err != nil {
			t.Fatal(err)
		}
		var (
			wg   sync.WaitGroup
			wins atomic.Int32
		)
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, ok, err := st.ConsumeAgentLease(ctx, store.AgentLeaseMatch{AccountID: AccountA, AgentID: a.AgentID, Credential: "gh", Action: "use", Now: now})
				if err != nil {
					t.Errorf("Consume: %v", err)
				}
				if ok {
					wins.Add(1)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("round %d: single-use lease used %d times", round, wins.Load())
		}
	}
	// A shared unlimited lease serves every concurrent caller.
	dur := newLease(a, "gh", store.AgentLeaseDuration, nil, "", now, time.Hour)
	if err := st.CreateAgentLease(ctx, dur); err != nil {
		t.Fatal(err)
	}
	var (
		wg   sync.WaitGroup
		wins atomic.Int32
	)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok, _ := st.ConsumeAgentLease(ctx, store.AgentLeaseMatch{AccountID: AccountA, AgentID: a.AgentID, Credential: "gh", Action: "use", Now: now}); ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 10 {
		t.Fatalf("duration lease served %d of 10", wins.Load())
	}
	if l, _ := st.GetAgentLease(ctx, AccountA, dur.LeaseID); l.UseCount != 10 {
		t.Fatalf("use count = %d", l.UseCount)
	}
}

func testAgentConcurrentDecisions(t *testing.T, st store.Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	a := mustCreateAgent(t, st, newTestAgent(AccountA, "coder", now))
	r, _, err := st.OpenAgentAccessRequest(ctx, newAccessRequest(a, "gh", []string{"use"}, "", now), now)
	if err != nil {
		t.Fatal(err)
	}
	var (
		wg   sync.WaitGroup
		wins atomic.Int32
	)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d := store.AgentAccessDecision{Status: store.AgentRequestDenied, By: "bob", At: now}
			if i%2 == 0 {
				l := newLease(a, "gh", store.AgentLeaseOnce, ptrInt(1), "", now, time.Hour)
				d = store.AgentAccessDecision{Status: store.AgentRequestApproved, By: "alice", At: now, Lease: &l}
			}
			_, err := st.DecideAgentAccessRequest(ctx, AccountA, r.RequestID, d)
			switch {
			case err == nil:
				wins.Add(1)
			case !errors.Is(err, store.ErrAgentAccessRequestDecided):
				t.Errorf("Decide: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d decisions won", wins.Load())
	}
	got, _ := st.GetAgentAccessRequest(ctx, AccountA, r.RequestID)
	leases, _ := st.ListAgentLeases(ctx, AccountA, a.AgentID, false, now)
	if got.Status == store.AgentRequestApproved && len(leases) != 1 || got.Status == store.AgentRequestDenied && len(leases) != 0 {
		t.Fatalf("status %s with %d leases", got.Status, len(leases))
	}
}

func testAgentAccessCascade(t *testing.T, st store.Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	a := mustCreateAgent(t, st, newTestAgent(AccountA, "coder", now))
	r, _, _ := st.OpenAgentAccessRequest(ctx, newAccessRequest(a, "gh", []string{"use"}, "", now), now)
	l := newLease(a, "gh", store.AgentLeaseDuration, nil, "", now, time.Hour)
	if err := st.CreateAgentLease(ctx, l); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteAgent(ctx, AccountA, a.AgentID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetAgentAccessRequest(ctx, AccountA, r.RequestID); !errors.Is(err, store.ErrAgentAccessRequestNotFound) {
		t.Fatalf("request after delete err = %v", err)
	}
	if _, err := st.GetAgentLease(ctx, AccountA, l.LeaseID); !errors.Is(err, store.ErrAgentLeaseNotFound) {
		t.Fatalf("lease after delete err = %v", err)
	}
}
