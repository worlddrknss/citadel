package main

import (
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
)

func TestSessionExpired(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	idleTTL := 30 * time.Minute
	absTTL := 12 * time.Hour

	fresh := uiSession{CreatedAt: now.Add(-5 * time.Minute), LastSeenAt: now.Add(-1 * time.Minute)}
	if sessionExpired(fresh, now, idleTTL, absTTL) {
		t.Fatal("fresh session should not be expired")
	}

	idle := uiSession{CreatedAt: now.Add(-1 * time.Hour), LastSeenAt: now.Add(-31 * time.Minute)}
	if !sessionExpired(idle, now, idleTTL, absTTL) {
		t.Fatal("idle-timed-out session should be expired")
	}

	old := uiSession{CreatedAt: now.Add(-13 * time.Hour), LastSeenAt: now.Add(-1 * time.Minute)}
	if !sessionExpired(old, now, idleTTL, absTTL) {
		t.Fatal("absolute-timed-out session should be expired")
	}

	disabled := uiSession{CreatedAt: now.Add(-100 * time.Hour), LastSeenAt: now.Add(-100 * time.Hour)}
	if sessionExpired(disabled, now, 0, 0) {
		t.Fatal("zero TTLs should disable expiry")
	}
}

func TestVerifyPasswordDummyHashRejects(t *testing.T) {
	if cryptoutil.VerifyPassword(dummyPasswordHash, "anything") {
		t.Fatal("dummy hash must never verify against a real password")
	}
	if cryptoutil.NeedsRehash(dummyPasswordHash) {
		t.Fatal("dummy hash should use the current parameters")
	}
}
