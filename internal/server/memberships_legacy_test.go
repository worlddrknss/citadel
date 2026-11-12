package server

import (
	"context"
	"testing"

	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/memory"
)

// 1.x stored account names, not just IDs, in a user's account list. They
// must resolve to the account's ID, and unknown names must not show up as
// phantom accounts without an ID.
func TestLegacyAccountNamesResolveToIDs(t *testing.T) {
	ctx := context.Background()
	st := &memory.Store{}
	id, err := st.CreateUIAccount(ctx, "wd-infrastructure")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{store: st}
	ms := s.userMemberships(ctx, store.UIUser{Username: "ops", Role: "admin", Accounts: []string{"wd-infrastructure", "no-such-account", id}})
	if len(ms) != 1 || ms[0].AccountID != id || ms[0].Role != "admin" {
		t.Fatalf("memberships = %+v, want one admin membership in %s", ms, id)
	}
}
