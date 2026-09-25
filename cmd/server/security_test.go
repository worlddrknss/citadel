package main

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
	"time"
)

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := hashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if !looksLikePBKDF2Hash(hash) {
		t.Fatalf("expected pbkdf2 hash, got %q", hash)
	}
	if needsRehash(hash) {
		t.Fatal("a fresh hash should not need rehashing")
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
	if verifyPassword(dummyPasswordHash, "anything") {
		t.Fatal("dummy hash must never verify against a real password")
	}
	if needsRehash(dummyPasswordHash) {
		t.Fatal("dummy hash should use the current parameters")
	}
}

func TestLegacyPlaintextNeedsRehash(t *testing.T) {
	if !needsRehash("plaintext-secret") {
		t.Fatal("legacy plaintext should need rehashing")
	}
}

// Argon2id hashes are no longer accepted: every stored one was migrated.
func TestArgon2HashNoLongerVerifies(t *testing.T) {
	const argon2Hash = "$argon2id$v=19$m=65536,t=3,p=2$+Zzc6FCiVBHCPF1Llgz3pQ$ZHroDCBLTiLB04VvCEgi3y0p/p4AyUyYe3rT8HAkYvc"
	if verifyPassword(argon2Hash, "anything") {
		t.Fatal("argon2 hashes must not verify")
	}
}

func TestPBKDF2OutdatedIterationsNeedRehash(t *testing.T) {
	salt := []byte("0123456789abcdef")
	digest, err := pbkdf2.Key(sha256.New, "pw", salt, 1000, 32)
	if err != nil {
		t.Fatal(err)
	}
	old := fmt.Sprintf("$pbkdf2-sha256$i=1000$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(digest))
	if !verifyPassword(old, "pw") {
		t.Fatal("a lower-iteration pbkdf2 hash should still verify")
	}
	if !needsRehash(old) {
		t.Fatal("a lower-iteration pbkdf2 hash should need rehashing")
	}
}

func TestPBKDF2RejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"$pbkdf2-sha256$i=0$c2FsdA$aGFzaA",
		"$pbkdf2-sha256$i=99999999999$c2FsdA$aGFzaA",
		"$pbkdf2-sha256$600000$c2FsdA$aGFzaA",
		"$pbkdf2-sha256$i=600000$!!!$aGFzaA",
	} {
		if verifyPassword(bad, "x") {
			t.Fatalf("malformed hash %q verified", bad)
		}
	}
}
