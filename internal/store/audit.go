package store

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

type AuditEvent struct {
	Action    string
	KeyID     string
	Result    string
	ErrorType string
	Actor     string
}

type AuditRecord struct {
	ID        int64
	Action    string
	KeyID     string
	Result    string
	ErrorType string
	Actor     string
	PrevHash  string
	EventHash string
	CreatedAt time.Time
}

// HashAuditRecord computes the chain hash for an audit record. When key is
// non-empty it produces an HMAC-SHA256 (authenticity: an attacker with DB write
// access cannot forge a valid chain without the key); otherwise it falls back to
// a plain SHA-256 chain (integrity only).
func HashAuditRecord(key []byte, prevHash string, event AuditEvent, ts string) string {
	payload := []byte(strings.Join([]string{prevHash, event.Action, event.KeyID, event.Result, event.ErrorType, event.Actor, ts}, "|"))
	if len(key) > 0 {
		mac := hmac.New(sha256.New, key)
		mac.Write(payload)
		return hex.EncodeToString(mac.Sum(nil))
	}
	h := sha256.Sum256(payload)
	return hex.EncodeToString(h[:])
}
