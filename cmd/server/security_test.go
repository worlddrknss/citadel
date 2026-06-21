package main

import (
	"testing"
	"time"
)

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := hashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if !looksLikeArgon2Hash(hash) {
		t.Fatalf("expected argon2 hash, got %q", hash)
	}
	if !verifyPassword(hash, "correct horse battery staple") {
		t.Fatal("verifyPassword should accept the correct password")
	}
	if verifyPassword(hash, "wrong password") {
		t.Fatal("verifyPassword should reject an incorrect password")
	}
}

func TestVerifyPasswordLegacyPlaintext(t *testing.T) {
	if !verifyPassword("plaintext-secret", "plaintext-secret") {
		t.Fatal("legacy plaintext fallback should accept matching secret")
	}
	if verifyPassword("plaintext-secret", "nope") {
		t.Fatal("legacy plaintext fallback should reject mismatched secret")
	}
}

func TestHashPasswordProducesUniqueSalts(t *testing.T) {
	a, err := hashPassword("same")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	b, err := hashPassword("same")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if a == b {
		t.Fatal("two hashes of the same password must differ due to random salts")
	}
}

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
	if verifyPassword(dummyArgon2Hash, "anything") {
		t.Fatal("dummy argon2 hash must never verify against a real password")
	}
}
