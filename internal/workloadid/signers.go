// Package workloadid makes Citadel an OpenID Connect issuer for workloads:
// CI jobs, Kubernetes pods and services authenticate to Citadel and receive
// short-lived ID tokens (JWTs) that other systems — AWS IAM OIDC providers,
// GCP workload identity federation, Vault's JWT auth, and so on — can
// federate with by trusting Citadel's discovery document and JWKS.
//
// It is not an identity provider for human users and implements no browser
// flows: the only grant is a direct token request from an authenticated
// workload.
//
// Tokens are signed with jose.Signer keys (typically Citadel KMS keys) and
// verified by relying parties with the keys published at /jwks.json. A
// KeyRing publishes previous keys alongside the current one so tokens remain
// verifiable across rotation.
package workloadid

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/worlddrknss/citadel/internal/jose"
)

// SignerSet supplies the signing key and the keys published in the JWKS.
// Implementations may be backed by KMS key metadata.
type SignerSet interface {
	// Current returns the key new tokens are signed with.
	Current(ctx context.Context) (jose.Signer, error)
	// Published returns every key relying parties should accept: the current
	// key, previous keys still within their overlap window, and any staged
	// next key. Key IDs must be unique.
	Published(ctx context.Context) ([]jose.Signer, error)
}

// KeyRing is an in-memory SignerSet supporting staged rotation:
//
//	ring.Stage(next)   // publish next in the JWKS; still sign with current
//	// wait at least as long as relying parties cache the JWKS
//	ring.Promote()     // sign with next; old current becomes previous
//	// wait for the longest token TTL plus JWKS cache time
//	ring.Retire(oldKID)
//
// Rotate does Stage+Promote in one step, for when pre-publication is not
// needed (for example the very first key or an emergency rotation).
type KeyRing struct {
	mu       sync.RWMutex
	current  jose.Signer
	next     jose.Signer
	previous []jose.Signer
}

// NewKeyRing returns a ring that signs with current and also publishes
// previous.
func NewKeyRing(current jose.Signer, previous ...jose.Signer) (*KeyRing, error) {
	r := &KeyRing{current: current, previous: previous}
	if err := r.check(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *KeyRing) check() error {
	if r.current == nil {
		return errors.New("workloadid: a current signer is required")
	}
	seen := map[string]bool{}
	for _, s := range r.all() {
		if !jose.IsSupported(s.Alg()) {
			return fmt.Errorf("workloadid: signer %q: %w", s.KeyID(), jose.ErrUnsupportedAlg)
		}
		if err := jose.CheckKey(s.Alg(), s.Public()); err != nil {
			return fmt.Errorf("workloadid: signer %q: %w", s.KeyID(), err)
		}
		if s.KeyID() == "" || seen[s.KeyID()] {
			return fmt.Errorf("workloadid: signer key IDs must be unique and non-empty (%q)", s.KeyID())
		}
		seen[s.KeyID()] = true
	}
	return nil
}

func (r *KeyRing) all() []jose.Signer {
	out := []jose.Signer{r.current}
	if r.next != nil {
		out = append(out, r.next)
	}
	return append(out, r.previous...)
}

// Current implements SignerSet.
func (r *KeyRing) Current(context.Context) (jose.Signer, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.current, nil
}

// Published implements SignerSet.
func (r *KeyRing) Published(context.Context) ([]jose.Signer, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.all(), nil
}

// Stage publishes next without signing with it yet.
func (r *KeyRing) Stage(next jose.Signer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	old := r.next
	r.next = next
	if err := r.check(); err != nil {
		r.next = old
		return err
	}
	return nil
}

// Promote makes the staged key current; the old current key stays published
// as a previous key.
func (r *KeyRing) Promote() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.next == nil {
		return errors.New("workloadid: no staged key to promote")
	}
	r.previous = append([]jose.Signer{r.current}, r.previous...)
	r.current, r.next = r.next, nil
	return nil
}

// Rotate stages and immediately promotes next.
func (r *KeyRing) Rotate(next jose.Signer) error {
	if err := r.Stage(next); err != nil {
		return err
	}
	return r.Promote()
}

// Retire stops publishing a previous key.
func (r *KeyRing) Retire(kid string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, s := range r.previous {
		if s.KeyID() == kid {
			r.previous = append(r.previous[:i:i], r.previous[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("workloadid: %q is not a previous key", kid)
}
