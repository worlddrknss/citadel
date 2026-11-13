package memory

import (
	"context"
	"slices"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

func (s *Store) TransitionCertificateAuthority(ctx context.Context, caID string, from []string, state string, restorableUntil *time.Time) (store.PCACertificateAuthority, error) {
	p := s.lockPKI()
	defer p.mu.Unlock()
	ca, ok := p.cas[caID]
	if !ok || !visible(ctx, ca.AccountID) {
		return store.PCACertificateAuthority{}, store.ErrCANotFound
	}
	if !slices.Contains(from, ca.State) {
		return copyCA(ca), store.ErrCAStateConflict
	}
	ca.State, ca.UpdatedAt = state, time.Now().UTC()
	ca.RestorableUntil = nil
	if restorableUntil != nil {
		t := restorableUntil.UTC()
		ca.RestorableUntil = &t
	}
	p.cas[caID] = ca
	return copyCA(ca), nil
}

func (s *Store) CountOutstandingCertificates(ctx context.Context, caID string, now time.Time) (int, error) {
	p := s.lockPKI()
	defer p.mu.Unlock()
	if ca, ok := p.cas[caID]; !ok || !visible(ctx, ca.AccountID) {
		return 0, store.ErrCANotFound
	}
	n := 0
	for _, c := range p.certs {
		if c.CAID == caID && c.Status != "REVOKED" && c.RevokedAt == nil && c.NotAfter.After(now) {
			n++
		}
	}
	for _, ca := range p.cas {
		if ca.ParentCAID == caID && ca.State != store.CAStateDeleted && ca.NotAfter.After(now) {
			n++
		}
	}
	return n, nil
}

func (s *Store) ListCertificateAuthoritiesDueForPurge(ctx context.Context, now time.Time) ([]store.PCACertificateAuthority, error) {
	p := s.lockPKI()
	defer p.mu.Unlock()
	var out []store.PCACertificateAuthority
	for _, ca := range p.cas {
		if visible(ctx, ca.AccountID) && purgeDue(ca, now) {
			out = append(out, copyCA(ca))
		}
	}
	return out, nil
}

func purgeDue(ca store.PCACertificateAuthority, now time.Time) bool {
	return ca.State == store.CAStateDeleted && ca.RestorableUntil != nil && !ca.RestorableUntil.After(now)
}

func (s *Store) PurgeCertificateAuthority(ctx context.Context, caID string, now time.Time) (bool, error) {
	p := s.lockPKI()
	defer p.mu.Unlock()
	ca, ok := p.cas[caID]
	if !ok || !visible(ctx, ca.AccountID) || !purgeDue(ca, now) {
		return false, nil
	}
	delete(p.cas, caID)
	for id, c := range p.certs {
		if c.CAID == caID {
			delete(p.certs, id)
		}
	}
	return true, nil
}

func (s *Store) HideCertificate(ctx context.Context, certID string, at time.Time) error {
	p := s.lockPKI()
	defer p.mu.Unlock()
	c, ok := p.certs[certID]
	if !ok || !visible(ctx, c.AccountID) || c.DeletedAt != nil {
		return store.ErrCertificateNotFound
	}
	t := at.UTC()
	c.DeletedAt, c.UpdatedAt = &t, t
	p.certs[certID] = c
	return nil
}

// Let's Encrypt certificates need the database-backed store (see acme.go).

func (s *Store) DeleteACMELECertificate(context.Context, string) error { return store.ErrUnsupported }

func (s *Store) SetACMELEAutoRenew(context.Context, string, bool) error { return store.ErrUnsupported }

func (s *Store) ListACMELERenewalsDue(context.Context, time.Time, time.Time, int) ([]store.ACMELECertificate, error) {
	return nil, store.ErrUnsupported
}

func (s *Store) ClaimACMELERenewal(context.Context, string, time.Time, time.Time) (bool, error) {
	return false, store.ErrUnsupported
}

func (s *Store) RecordACMELERenewal(context.Context, string, store.ACMELERenewalResult) error {
	return store.ErrUnsupported
}
