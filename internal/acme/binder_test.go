package acme

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// singleUseEAB is an EABResolver that also implements EABBinder.
type singleUseEAB struct {
	mu    sync.Mutex
	key   []byte
	bound map[string]string
}

func (s *singleUseEAB) Lookup(_ context.Context, kid string) ([]byte, string, error) {
	if kid != "kid-1" {
		return nil, "", ErrNotFound
	}
	return s.key, "tenant-a", nil
}

func (s *singleUseEAB) Bind(_ context.Context, kid, accountID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, used := s.bound[kid]; used {
		return errors.New("already bound")
	}
	s.bound[kid] = accountID
	return nil
}

func TestEABBinderEnforcesSingleUse(t *testing.T) {
	eab := &singleUseEAB{key: []byte(strings.Repeat("k", 32)), bound: map[string]string{}}
	var (
		mu     sync.Mutex
		gotRef string
	)
	env := newEnv(t, func(cfg *Config) {
		cfg.RequireEAB = true
		cfg.EABKeys = eab
		cfg.Validators[ChallengeDNS01] = ValidatorFunc(func(ctx context.Context, _ Identifier, _, _ string) error {
			mu.Lock()
			gotRef = AccountRefFromContext(ctx)
			mu.Unlock()
			return nil
		})
	})
	c1 := env.newClient(algES256)
	resp := c1.post(c1.dir.NewAccount, map[string]any{
		"termsOfServiceAgreed":   true,
		"externalAccountBinding": eabJWS(t, "kid-1", eab.key, c1.dir.NewAccount, c1.key.Public()),
	})
	expectStatus(t, resp, http.StatusCreated)
	c1.kid = resp.header.Get("Location")
	acct, err := env.store.GetAccountByThumbprint(context.Background(), c1.thumbprint())
	eab.mu.Lock()
	boundTo := eab.bound["kid-1"]
	eab.mu.Unlock()
	mustf(t, err == nil && boundTo == acct.ID, "binding recorded %q %v", boundTo, err)

	// A second account key may not reuse the binding key.
	c2 := env.newClient(algES256)
	resp = c2.post(c2.dir.NewAccount, map[string]any{
		"termsOfServiceAgreed":   true,
		"externalAccountBinding": eabJWS(t, "kid-1", eab.key, c2.dir.NewAccount, c2.key.Public()),
	})
	expectProblem(t, resp, ProbUnauthorized)

	// The first account still works, and validators see its account ref.
	c1.obtain(ChallengeDNS01, "www.example.com")
	mu.Lock()
	defer mu.Unlock()
	mustf(t, gotRef == "tenant-a", "validator account ref %q", gotRef)
}
