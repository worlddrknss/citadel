package memory

import (
	"context"
	"time"
)

// SecretsDueForPurge implements store.WriteAheadStore.
func (s *Store) SecretsDueForPurge(ctx context.Context, now time.Time) (map[string]int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int{}
	for _, secret := range s.secrets {
		if d := secret.metadata.DeletedDate; d != nil && !d.After(now) {
			out[secret.account]++
		}
	}
	return out, nil
}

// CertificatesDueForExpiry implements store.WriteAheadStore, mirroring
// MarkExpiredCertificates.
func (s *Store) CertificatesDueForExpiry(ctx context.Context, now time.Time) (int64, error) {
	p := s.lockPKI()
	defer p.mu.Unlock()
	var n int64
	for _, c := range p.certs {
		if visible(ctx, c.AccountID) && c.Status == "ISSUED" && c.NotAfter.Before(now) {
			n++
		}
	}
	for _, c := range p.acm {
		if visible(ctx, c.AccountID) && c.Status == "ISSUED" && c.NotAfter.Before(now) {
			n++
		}
	}
	for _, ca := range p.cas {
		if visible(ctx, ca.AccountID) && ca.State == "ACTIVE" && ca.NotAfter.Before(now) {
			n++
		}
	}
	return n, nil
}
