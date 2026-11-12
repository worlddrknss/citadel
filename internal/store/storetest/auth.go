// Package storetest holds behaviour tests shared by every store.Store
// backend, so the memory and PostgreSQL stores are held to the same contract.
package storetest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// AuthStore exercises store.AuthStore (and the membership methods it relies
// on) against a fresh, empty store from newStore.
func AuthStore(t *testing.T, newStore func(t *testing.T) store.Store) {
	t.Run("Bootstrap", func(t *testing.T) { testBootstrap(t, newStore(t)) })
	t.Run("BootstrapRace", func(t *testing.T) { testBootstrapRace(t, newStore(t)) })
	t.Run("Sessions", func(t *testing.T) { testSessions(t, newStore(t)) })
	t.Run("OrgSettings", func(t *testing.T) { testOrgSettings(t, newStore(t)) })
	t.Run("Memberships", func(t *testing.T) { testMemberships(t, newStore(t)) })
	t.Run("SSOProvidersEmpty", func(t *testing.T) {
		ps, err := newStore(t).ListSSOProviders(context.Background(), true)
		if err != nil || ps == nil || len(ps) != 0 {
			t.Fatalf("ListSSOProviders = %v, %v; want empty non-nil", ps, err)
		}
	})
}

const testHash = "$pbkdf2-sha256$i=600000$Y0q6S1JhYRMtaRnYXtT+1g$vWWUOxgQ7EVskOU4UldrOnx5wdUEiGPel/mlNcG/O+0"

func testBootstrap(t *testing.T, st store.Store) {
	ctx := context.Background()
	if n, err := st.CountUIUsers(ctx); err != nil || n != 0 {
		t.Fatalf("CountUIUsers on empty store = %d, %v", n, err)
	}
	acct, err := st.Bootstrap(ctx, store.BootstrapRequest{
		OrganizationName: "Acme Corp", AccountName: "Production", Username: "root", PasswordHash: testHash,
	})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if len(acct) != 12 {
		t.Fatalf("account ID %q, want 12 digits", acct)
	}
	u, err := st.GetUIUser(ctx, "root")
	if err != nil {
		t.Fatalf("GetUIUser: %v", err)
	}
	if u.Role != "admin" || !u.PlatformAdmin || u.PasswordHash != testHash {
		t.Fatalf("bootstrap user = %+v", u)
	}
	if _, err := st.GetUIUser(ctx, "nobody"); !errors.Is(err, store.ErrUIUserNotFound) {
		t.Fatalf("GetUIUser(unknown) err = %v", err)
	}
	ms, err := st.ListUserAccounts(ctx, "root")
	if err != nil || len(ms) != 1 || ms[0].AccountID != acct || store.NormalizeUIRole(ms[0].Role) != "admin" {
		t.Fatalf("memberships = %+v, %v", ms, err)
	}
	info, err := st.GetUIAccount(ctx, acct)
	if err != nil || info.Name != "production" {
		t.Fatalf("GetUIAccount = %+v, %v", info, err)
	}
	org, err := st.GetOrgSettings(ctx)
	if err != nil || org.OrganizationName != "Acme Corp" {
		t.Fatalf("org settings = %+v, %v", org, err)
	}
	if n, _ := st.CountUIUsers(ctx); n != 1 {
		t.Fatalf("CountUIUsers = %d, want 1", n)
	}
	if _, err := st.Bootstrap(ctx, store.BootstrapRequest{AccountName: "x", Username: "other", PasswordHash: testHash}); !errors.Is(err, store.ErrAlreadyBootstrapped) {
		t.Fatalf("second Bootstrap err = %v, want ErrAlreadyBootstrapped", err)
	}
}

func testBootstrapRace(t *testing.T, st store.Store) {
	ctx := context.Background()
	const n = 8
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		wins int
	)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := st.Bootstrap(ctx, store.BootstrapRequest{
				AccountName: "acct" + string(rune('a'+i)), Username: "admin" + string(rune('a'+i)), PasswordHash: testHash,
			})
			if err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			} else if !errors.Is(err, store.ErrAlreadyBootstrapped) {
				t.Errorf("Bootstrap: %v", err)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d concurrent bootstraps succeeded, want exactly 1", wins)
	}
	if c, _ := st.CountUIUsers(ctx); c != 1 {
		t.Fatalf("CountUIUsers = %d after race, want 1", c)
	}
}

func addUser(t *testing.T, st store.Store, name string) {
	t.Helper()
	if err := st.UpsertUIUser(context.Background(), store.UIUser{Username: name, PasswordHash: testHash, Role: "viewer", DisplayName: name}); err != nil {
		t.Fatalf("UpsertUIUser(%s): %v", name, err)
	}
}

func testSessions(t *testing.T, st store.Store) {
	ctx := context.Background()
	addUser(t, st, "alice")
	addUser(t, st, "bob")
	now := time.Now().UTC().Truncate(time.Second)
	mk := func(id, user string, created, lastSeen, expires time.Time) store.ConsoleSession {
		return store.ConsoleSession{
			ID: id, TokenHash: "hash-" + id, Username: user, AccountID: "111111111111", Method: store.SessionMethodPassword,
			IP: "192.0.2.1", UserAgent: "test", CreatedAt: created, LastSeenAt: lastSeen, ExpiresAt: expires,
		}
	}
	sessions := []store.ConsoleSession{
		mk("a1", "alice", now.Add(-time.Hour), now.Add(-time.Minute), now.Add(time.Hour)),
		mk("a2", "alice", now.Add(-2*time.Hour), now.Add(-2*time.Minute), now.Add(time.Hour)),
		mk("a3", "alice", now.Add(-3*time.Hour), now.Add(-3*time.Hour), now.Add(time.Hour)),   // idle
		mk("a4", "alice", now.Add(-13*time.Hour), now.Add(-time.Minute), now.Add(-time.Hour)), // expired
		mk("b1", "bob", now.Add(-time.Hour), now, now.Add(time.Hour)),
	}
	for _, s := range sessions {
		if err := st.CreateConsoleSession(ctx, s); err != nil {
			t.Fatalf("CreateConsoleSession(%s): %v", s.ID, err)
		}
	}
	got, err := st.GetConsoleSessionByTokenHash(ctx, "hash-a1")
	if err != nil {
		t.Fatalf("GetConsoleSessionByTokenHash: %v", err)
	}
	if got.ID != "a1" || got.Username != "alice" || got.IP != "192.0.2.1" || !got.CreatedAt.Equal(sessions[0].CreatedAt) || !got.ExpiresAt.Equal(sessions[0].ExpiresAt) {
		t.Fatalf("session = %+v", got)
	}
	if _, err := st.GetConsoleSessionByTokenHash(ctx, "nope"); !errors.Is(err, store.ErrConsoleSessionNotFound) {
		t.Fatalf("unknown token err = %v", err)
	}
	if err := st.TouchConsoleSession(ctx, "a1", now); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	if err := st.SetConsoleSessionAccount(ctx, "a1", "222222222222"); err != nil {
		t.Fatalf("SetConsoleSessionAccount: %v", err)
	}
	got, _ = st.GetConsoleSessionByTokenHash(ctx, "hash-a1")
	if !got.LastSeenAt.Equal(now) || got.AccountID != "222222222222" {
		t.Fatalf("after touch/switch: %+v", got)
	}
	list, err := st.ListConsoleSessions(ctx, "alice")
	if err != nil || len(list) != 4 || list[0].ID != "a1" {
		t.Fatalf("ListConsoleSessions = %+v, %v", list, err)
	}
	// Bob cannot delete Alice's session.
	if err := st.DeleteConsoleSession(ctx, "bob", "a2"); !errors.Is(err, store.ErrConsoleSessionNotFound) {
		t.Fatalf("cross-user delete err = %v", err)
	}
	n, err := st.DeleteExpiredConsoleSessions(ctx, now, now.Add(-30*time.Minute))
	if err != nil || n != 2 {
		t.Fatalf("DeleteExpiredConsoleSessions = %d, %v; want 2", n, err)
	}
	if err := st.DeleteConsoleSession(ctx, "alice", "a2"); err != nil {
		t.Fatalf("DeleteConsoleSession: %v", err)
	}
	if err := st.CreateConsoleSession(ctx, mk("a5", "alice", now, now, now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	n, err = st.DeleteUserConsoleSessions(ctx, "alice", "a1")
	if err != nil || n != 1 {
		t.Fatalf("DeleteUserConsoleSessions = %d, %v; want 1", n, err)
	}
	list, _ = st.ListConsoleSessions(ctx, "alice")
	if len(list) != 1 || list[0].ID != "a1" {
		t.Fatalf("remaining = %+v", list)
	}
	// Deleting a user removes their sessions.
	if err := st.DeleteUIUser(ctx, "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetConsoleSessionByTokenHash(ctx, "hash-b1"); !errors.Is(err, store.ErrConsoleSessionNotFound) {
		t.Fatalf("deleted user's session still resolves: %v", err)
	}
}

func testOrgSettings(t *testing.T, st store.Store) {
	ctx := context.Background()
	def, err := st.GetOrgSettings(ctx)
	if err != nil || def.ApprovalMinApprovers != 1 || def.AllowSelfApproval || !def.UpdatedAt.IsZero() {
		t.Fatalf("default settings = %+v, %v", def, err)
	}
	when := time.Now().UTC().Truncate(time.Second)
	in := store.OrgSettings{
		OrganizationName: "Org", ApprovalEnvironments: []string{"prod", "staging"}, ApprovalMinApprovers: 2,
		AllowSelfApproval: true, SessionIdleMinutes: 15, SessionMaxHours: 8, UpdatedAt: when, UpdatedBy: "root",
	}
	if err := st.PutOrgSettings(ctx, in); err != nil {
		t.Fatalf("PutOrgSettings: %v", err)
	}
	got, err := st.GetOrgSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.OrganizationName != "Org" || len(got.ApprovalEnvironments) != 2 || got.ApprovalEnvironments[1] != "staging" ||
		got.ApprovalMinApprovers != 2 || !got.AllowSelfApproval || got.SessionIdleMinutes != 15 || got.SessionMaxHours != 8 ||
		!got.UpdatedAt.Equal(when) || got.UpdatedBy != "root" {
		t.Fatalf("settings round trip = %+v", got)
	}
}

func testMemberships(t *testing.T, st store.Store) {
	ctx := context.Background()
	addUser(t, st, "carol")
	a1, err := st.CreateUIAccount(ctx, "one")
	if err != nil {
		t.Fatal(err)
	}
	a2, err := st.CreateUIAccount(ctx, "two")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AddUserAccount(ctx, "carol", a1, "editor"); err != nil {
		t.Fatal(err)
	}
	if err := st.AddUserAccount(ctx, "carol", a2, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := st.AddUserAccount(ctx, "carol", a1, "viewer"); err != nil {
		t.Fatal(err)
	}
	ms, err := st.ListUserAccounts(ctx, "carol")
	if err != nil || len(ms) != 2 {
		t.Fatalf("memberships = %+v, %v", ms, err)
	}
	roles := map[string]string{}
	for _, m := range ms {
		roles[m.AccountID] = store.NormalizeUIRole(m.Role)
	}
	if roles[a1] != "viewer" || roles[a2] != "admin" {
		t.Fatalf("roles = %v", roles)
	}
	if err := st.RemoveUserAccount(ctx, "carol", a2); err != nil {
		t.Fatal(err)
	}
	ms, _ = st.ListUserAccounts(ctx, "carol")
	if len(ms) != 1 || ms[0].AccountID != a1 {
		t.Fatalf("after remove = %+v", ms)
	}
	users, err := st.ListAccountUsers(ctx, a1)
	if err != nil || len(users) != 1 || users[0].Username != "carol" {
		t.Fatalf("ListAccountUsers = %+v, %v", users, err)
	}
}
