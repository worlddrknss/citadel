package oidclogin

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	cookieVersion = "v1"
	minKeyLen     = 32
	hkdfEncInfo   = "citadel/oidclogin/state-cookie/v1/aes-256-gcm"
	hkdfMacInfo   = "citadel/oidclogin/state-cookie/v1/hmac-sha256"
)

var b64 = base64.RawURLEncoding

// flowState is sealed into the state cookie.
type flowState struct {
	Provider string `json:"p"`
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	ReturnTo string `json:"r"`
	Expires  int64  `json:"e"`
}

type cookieKey struct {
	aead   cipher.AEAD
	macKey []byte
}

type sealer struct {
	keys []cookieKey
	name string // bound into AAD and MAC
}

func newSealer(secrets [][]byte, name string) (*sealer, error) {
	if len(secrets) == 0 {
		return nil, errors.New("oidclogin: at least one cookie key is required")
	}
	s := &sealer{name: name}
	for i, secret := range secrets {
		if len(secret) < minKeyLen {
			return nil, fmt.Errorf("oidclogin: cookie key %d is %d bytes, need at least %d", i, len(secret), minKeyLen)
		}
		encKey, err := hkdf.Key(sha256.New, secret, nil, hkdfEncInfo, 32)
		if err != nil {
			return nil, err
		}
		macKey, err := hkdf.Key(sha256.New, secret, nil, hkdfMacInfo, 32)
		if err != nil {
			return nil, err
		}
		block, err := aes.NewCipher(encKey)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCMWithRandomNonce(block)
		if err != nil {
			return nil, err
		}
		s.keys = append(s.keys, cookieKey{aead: aead, macKey: macKey})
	}
	return s, nil
}

func (s *sealer) aad() []byte { return []byte(cookieVersion + "|" + s.name) }

func (s *sealer) mac(k cookieKey, body string) []byte {
	m := hmac.New(sha256.New, k.macKey)
	m.Write(s.aad())
	m.Write([]byte{0})
	m.Write([]byte(body))
	return m.Sum(nil)
}

// seal encrypts (AES-256-GCM, random nonce) then MACs (HMAC-SHA256) the
// state: "v1.<base64url ciphertext>.<base64url mac>".
func (s *sealer) seal(st flowState) (string, error) {
	plain, err := json.Marshal(st)
	if err != nil {
		return "", err
	}
	k := s.keys[0]
	ct := k.aead.Seal(nil, nil, plain, s.aad())
	body := cookieVersion + "." + b64.EncodeToString(ct)
	return body + "." + b64.EncodeToString(s.mac(k, body)), nil
}

func (s *sealer) open(value string) (flowState, error) {
	var st flowState
	if len(value) > 4096 {
		return st, ErrStateInvalid
	}
	i := strings.LastIndexByte(value, '.')
	if i < 0 || !strings.HasPrefix(value, cookieVersion+".") {
		return st, ErrStateInvalid
	}
	body, tag := value[:i], value[i+1:]
	gotMAC, err := b64.DecodeString(tag)
	if err != nil {
		return st, ErrStateInvalid
	}
	ct, err := b64.DecodeString(body[len(cookieVersion)+1:])
	if err != nil {
		return st, ErrStateInvalid
	}
	for _, k := range s.keys {
		if !hmac.Equal(gotMAC, s.mac(k, body)) {
			continue
		}
		plain, err := k.aead.Open(nil, nil, ct, s.aad())
		if err != nil {
			return st, ErrStateInvalid
		}
		if err := json.Unmarshal(plain, &st); err != nil {
			return st, ErrStateInvalid
		}
		return st, nil
	}
	return st, ErrStateInvalid
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b64.EncodeToString(b), nil
}

// ReplayStore records consumed sign-in states so each is accepted once.
// Multi-replica deployments must back it with shared storage (for example a
// Postgres table with a unique key and an expiry column).
type ReplayStore interface {
	// Consume records id until expires. It returns true if id had not been
	// consumed before, false if it is a replay.
	Consume(ctx context.Context, id string, expires time.Time) (bool, error)
}

// MemoryReplayStore is an in-process ReplayStore.
type MemoryReplayStore struct {
	mu   sync.Mutex
	now  func() time.Time
	seen map[string]time.Time
	max  int
}

// NewMemoryReplayStore returns an in-memory store holding at most 100,000
// live entries; beyond that Consume fails closed.
func NewMemoryReplayStore(now func() time.Time) *MemoryReplayStore {
	if now == nil {
		now = time.Now
	}
	return &MemoryReplayStore{now: now, seen: map[string]time.Time{}, max: 100_000}
}

// Consume implements ReplayStore.
func (m *MemoryReplayStore) Consume(_ context.Context, id string, expires time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if exp, ok := m.seen[id]; ok && now.Before(exp) {
		return false, nil
	}
	if len(m.seen) >= m.max {
		for k, exp := range m.seen {
			if !now.Before(exp) {
				delete(m.seen, k)
			}
		}
		if len(m.seen) >= m.max {
			return false, errors.New("oidclogin: replay store full")
		}
	}
	m.seen[id] = expires
	return true, nil
}

func stateID(state string) string {
	sum := sha256.Sum256([]byte("citadel-oidc-state|" + state))
	return hex.EncodeToString(sum[:])
}
