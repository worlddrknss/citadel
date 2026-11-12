package cryptoutil

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
)

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if !LooksLikePBKDF2Hash(hash) {
		t.Fatalf("expected pbkdf2 hash, got %q", hash)
	}
	if NeedsRehash(hash) {
		t.Fatal("a fresh hash should not need rehashing")
	}
	if !VerifyPassword(hash, "correct horse battery staple") {
		t.Fatal("verifyPassword should accept the correct password")
	}
	if VerifyPassword(hash, "wrong password") {
		t.Fatal("verifyPassword should reject an incorrect password")
	}
}

func TestVerifyPasswordLegacyPlaintext(t *testing.T) {
	if !VerifyPassword("plaintext-secret", "plaintext-secret") {
		t.Fatal("legacy plaintext fallback should accept matching secret")
	}
	if VerifyPassword("plaintext-secret", "nope") {
		t.Fatal("legacy plaintext fallback should reject mismatched secret")
	}
}

func TestHashPasswordProducesUniqueSalts(t *testing.T) {
	a, err := HashPassword("same")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	b, err := HashPassword("same")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if a == b {
		t.Fatal("two hashes of the same password must differ due to random salts")
	}
}

func TestLegacyPlaintextNeedsRehash(t *testing.T) {
	if !NeedsRehash("plaintext-secret") {
		t.Fatal("legacy plaintext should need rehashing")
	}
}

// Argon2id hashes are no longer accepted: every stored one was migrated.
func TestArgon2HashNoLongerVerifies(t *testing.T) {
	const argon2Hash = "$argon2id$v=19$m=65536,t=3,p=2$+Zzc6FCiVBHCPF1Llgz3pQ$ZHroDCBLTiLB04VvCEgi3y0p/p4AyUyYe3rT8HAkYvc"
	if VerifyPassword(argon2Hash, "anything") {
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
	if !VerifyPassword(old, "pw") {
		t.Fatal("a lower-iteration pbkdf2 hash should still verify")
	}
	if !NeedsRehash(old) {
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
		if VerifyPassword(bad, "x") {
			t.Fatalf("malformed hash %q verified", bad)
		}
	}
}
