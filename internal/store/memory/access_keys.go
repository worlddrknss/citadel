package memory

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// Access keys (machine identities) in memory, mirroring the Postgres store:
// at most two active keys per user and account, statuses Active/Inactive,
// and ASIA-prefixed IDs resolved as STS session credentials.

type memAccessKey struct {
	info   store.AccessKeyInfo
	secret string
}

type accessKeyState struct {
	mu   sync.Mutex
	keys map[string]*memAccessKey
}

// akState returns the store's access-key state, initialising it on first
// use so a zero Store works.
func (s *Store) akState() *accessKeyState {
	s.ak.mu.Lock()
	if s.ak.keys == nil {
		s.ak.keys = map[string]*memAccessKey{}
	}
	s.ak.mu.Unlock()
	return &s.ak
}

// CreateAccessKey creates an access key for username in accountID.
func (s *Store) CreateAccessKey(_ context.Context, username, accountID string) (store.AccessKeySecret, error) {
	username, accountID = strings.TrimSpace(username), strings.TrimSpace(accountID)
	if username == "" || accountID == "" {
		return store.AccessKeySecret{}, errors.New("username and accountID are required")
	}
	st := s.akState()
	st.mu.Lock()
	defer st.mu.Unlock()
	active := 0
	for _, k := range st.keys {
		if k.info.Username == username && k.info.AccountID == accountID && k.info.Status == "Active" {
			active++
		}
	}
	if active >= 2 {
		return store.AccessKeySecret{}, store.ErrMaxAccessKeys
	}
	id, secret := store.GenerateAccessKeyID(), store.GenerateAccessKeySecret()
	st.keys[id] = &memAccessKey{
		info:   store.AccessKeyInfo{AccessKeyID: id, Username: username, AccountID: accountID, Status: "Active", CreatedAt: time.Now().UTC()},
		secret: secret,
	}
	return store.AccessKeySecret{AccessKeyID: id, SecretKey: secret}, nil
}

// ListAccessKeys returns a user's keys in an account, newest first.
func (s *Store) ListAccessKeys(_ context.Context, username, accountID string) ([]store.AccessKeyInfo, error) {
	username, accountID = strings.TrimSpace(username), strings.TrimSpace(accountID)
	if username == "" || accountID == "" {
		return nil, errors.New("username and accountID are required")
	}
	st := s.akState()
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []store.AccessKeyInfo
	for _, k := range st.keys {
		if k.info.Username == username && k.info.AccountID == accountID {
			info := k.info
			if info.LastUsedAt != nil {
				t := *info.LastUsedAt
				info.LastUsedAt = &t
			}
			out = append(out, info)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// GetAccessKeyByID resolves a key (or an STS session's temporary key) for
// authentication.
func (s *Store) GetAccessKeyByID(ctx context.Context, keyID string) (username, accountID, secret string, status string, err error) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return "", "", "", "", errors.New("keyID is required")
	}
	if store.IsTempAccessKeyID(keyID) {
		acct, sec, _, _, serr := s.GetSTSSessionSecret(ctx, keyID)
		switch {
		case errors.Is(serr, store.ErrSTSSessionExpired):
			return "", "", "", "Inactive", nil
		case errors.Is(serr, store.ErrSTSSessionNotFound):
			return "", "", "", "", store.ErrAccessKeyNotFound
		case serr != nil:
			return "", "", "", "", serr
		}
		return keyID, acct, sec, "Active", nil
	}
	st := s.akState()
	st.mu.Lock()
	defer st.mu.Unlock()
	k, ok := st.keys[keyID]
	if !ok {
		return "", "", "", "", store.ErrAccessKeyNotFound
	}
	return k.info.Username, k.info.AccountID, k.secret, k.info.Status, nil
}

// SetAccessKeyStatus activates or deactivates a key.
func (s *Store) SetAccessKeyStatus(_ context.Context, keyID, newStatus string) error {
	keyID, newStatus = strings.TrimSpace(keyID), strings.TrimSpace(newStatus)
	if keyID == "" || (newStatus != "Active" && newStatus != "Inactive") {
		return errors.New("invalid keyID or status")
	}
	st := s.akState()
	st.mu.Lock()
	defer st.mu.Unlock()
	k, ok := st.keys[keyID]
	if !ok {
		return store.ErrAccessKeyNotFound
	}
	k.info.Status = newStatus
	return nil
}

// DeleteAccessKey deletes a key.
func (s *Store) DeleteAccessKey(_ context.Context, keyID string) error {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return errors.New("keyID is required")
	}
	st := s.akState()
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.keys[keyID]; !ok {
		return store.ErrAccessKeyNotFound
	}
	delete(st.keys, keyID)
	return nil
}

// TouchAccessKeyLastUsed records that a key was used.
func (s *Store) TouchAccessKeyLastUsed(_ context.Context, keyID string) error {
	st := s.akState()
	st.mu.Lock()
	defer st.mu.Unlock()
	if k, ok := st.keys[strings.TrimSpace(keyID)]; ok {
		now := time.Now().UTC()
		k.info.LastUsedAt = &now
	}
	return nil
}
