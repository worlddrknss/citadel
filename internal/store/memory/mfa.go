package memory

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// memMFA is the in-memory console MFA state.
type memMFA struct {
	enrollments map[string]store.MFAEnrollment
	codes       map[string]map[string]bool // username -> code hash -> used
	tokens      map[string]time.Time       // spent login token ID -> expiry
}

// mfaLocked returns the MFA state, creating it on first use. s.mu must be
// held.
func (s *Store) mfaLocked() *memMFA {
	if s.mfa == nil {
		s.mfa = &memMFA{enrollments: map[string]store.MFAEnrollment{}, codes: map[string]map[string]bool{}, tokens: map[string]time.Time{}}
	}
	return s.mfa
}

func (s *Store) GetMFA(_ context.Context, username string) (store.MFAEnrollment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.mfaLocked()
	username = strings.TrimSpace(username)
	e, ok := m.enrollments[username]
	if !ok {
		return store.MFAEnrollment{}, store.ErrMFANotFound
	}
	e.SecretEnc = bytes.Clone(e.SecretEnc)
	for _, used := range m.codes[username] {
		if !used {
			e.RecoveryCodesLeft++
		}
	}
	return e, nil
}

func (s *Store) PutPendingMFA(_ context.Context, username string, secretEnc []byte, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.mfaLocked()
	username = strings.TrimSpace(username)
	if e, ok := m.enrollments[username]; ok && e.Enabled {
		return store.ErrMFAAlreadyEnabled
	}
	m.enrollments[username] = store.MFAEnrollment{Username: username, SecretEnc: bytes.Clone(secretEnc), CreatedAt: now.UTC()}
	delete(m.codes, username)
	return nil
}

func (s *Store) EnableMFA(_ context.Context, username string, secretEnc []byte, step int64, recoveryHashes []string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.mfaLocked()
	username = strings.TrimSpace(username)
	e, ok := m.enrollments[username]
	if !ok || e.Enabled || !bytes.Equal(e.SecretEnc, secretEnc) {
		return store.ErrMFANotFound
	}
	e.Enabled, e.EnabledAt, e.LastStep = true, now.UTC(), step
	m.enrollments[username] = e
	m.codes[username] = codeSet(recoveryHashes)
	return nil
}

func codeSet(hashes []string) map[string]bool {
	out := make(map[string]bool, len(hashes))
	for _, h := range hashes {
		out[h] = false
	}
	return out
}

func (s *Store) AdvanceMFAStep(_ context.Context, username string, step int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.mfaLocked()
	username = strings.TrimSpace(username)
	e, ok := m.enrollments[username]
	if !ok || !e.Enabled || step <= e.LastStep {
		return false, nil
	}
	e.LastStep = step
	m.enrollments[username] = e
	return true, nil
}

func (s *Store) DeleteMFA(_ context.Context, username string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteMFALocked(strings.TrimSpace(username)), nil
}

func (s *Store) deleteMFALocked(username string) bool {
	m := s.mfaLocked()
	_, ok := m.enrollments[username]
	delete(m.enrollments, username)
	delete(m.codes, username)
	return ok
}

func (s *Store) ListMFARecoveryCodeHashes(_ context.Context, username string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []string{}
	for h, used := range s.mfaLocked().codes[strings.TrimSpace(username)] {
		if !used {
			out = append(out, h)
		}
	}
	slices.Sort(out)
	return out, nil
}

func (s *Store) ConsumeMFARecoveryCode(_ context.Context, username, codeHash string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	codes := s.mfaLocked().codes[strings.TrimSpace(username)]
	used, ok := codes[codeHash]
	if !ok || used {
		return false, nil
	}
	codes[codeHash] = true
	return true, nil
}

func (s *Store) ReplaceMFARecoveryCodes(_ context.Context, username string, hashes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.mfaLocked()
	username = strings.TrimSpace(username)
	if e, ok := m.enrollments[username]; !ok || !e.Enabled {
		return store.ErrMFANotFound
	}
	m.codes[username] = codeSet(hashes)
	return nil
}

func (s *Store) ListMFAEnabledUsers(_ context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []string{}
	for u, e := range s.mfaLocked().enrollments {
		if e.Enabled {
			out = append(out, u)
		}
	}
	slices.Sort(out)
	return out, nil
}

func (s *Store) UseMFALoginToken(_ context.Context, id string, expiresAt, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.mfaLocked()
	for k, exp := range m.tokens {
		if exp.Before(now) {
			delete(m.tokens, k)
		}
	}
	if _, used := m.tokens[id]; used {
		return false, nil
	}
	m.tokens[id] = expiresAt
	return true, nil
}
