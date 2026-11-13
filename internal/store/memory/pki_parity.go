package memory

import (
	"context"
	"sync"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// memPKIParity backs store.PKIParityStore. Its zero value is ready to use.
type memPKIParity struct {
	mu     sync.Mutex
	tokens map[string]store.ACMIdempotencyRecord // account|operation|token
	csrs   map[string]string                     // CA ID -> CSR (base64 PEM)
}

func idempotencyKey(account, operation, token string) string {
	return account + "|" + operation + "|" + token
}

// ClaimACMIdempotencyToken implements store.PKIParityStore.
func (s *Store) ClaimACMIdempotencyToken(ctx context.Context, rec store.ACMIdempotencyRecord, notBefore time.Time) (store.ACMIdempotencyRecord, bool, error) {
	rec.AccountID = s.accountForContext(ctx)
	p := &s.parity
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.tokens == nil {
		p.tokens = map[string]store.ACMIdempotencyRecord{}
	}
	k := idempotencyKey(rec.AccountID, rec.Operation, rec.Token)
	if prev, ok := p.tokens[k]; ok && !prev.CreatedAt.Before(notBefore) {
		return prev, false, nil
	}
	// Expired records are dropped as they are found.
	for key, r := range p.tokens {
		if r.CreatedAt.Before(notBefore) {
			delete(p.tokens, key)
		}
	}
	p.tokens[k] = rec
	return rec, true, nil
}

// ReleaseACMIdempotencyToken implements store.PKIParityStore.
func (s *Store) ReleaseACMIdempotencyToken(ctx context.Context, operation, token, arn string) error {
	p := &s.parity
	p.mu.Lock()
	defer p.mu.Unlock()
	k := idempotencyKey(s.accountForContext(ctx), operation, token)
	if r, ok := p.tokens[k]; ok && r.ARN == arn {
		delete(p.tokens, k)
	}
	return nil
}

// PutCertificateAuthorityCSR implements store.PKIParityStore.
func (s *Store) PutCertificateAuthorityCSR(ctx context.Context, caID, csrB64 string) error {
	if _, err := s.GetCertificateAuthorityByID(ctx, caID); err != nil {
		return err
	}
	p := &s.parity
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.csrs == nil {
		p.csrs = map[string]string{}
	}
	p.csrs[caID] = csrB64
	return nil
}

// GetCertificateAuthorityCSR implements store.PKIParityStore.
func (s *Store) GetCertificateAuthorityCSR(ctx context.Context, caID string) (string, error) {
	if _, err := s.GetCertificateAuthorityByID(ctx, caID); err != nil {
		return "", err
	}
	p := &s.parity
	p.mu.Lock()
	defer p.mu.Unlock()
	csr, ok := p.csrs[caID]
	if !ok {
		return "", store.ErrCANotFound
	}
	return csr, nil
}

// ActivateCertificateAuthority implements store.PKIParityStore.
func (s *Store) ActivateCertificateAuthority(ctx context.Context, ca store.PCACertificateAuthority) error {
	p := s.lockPKI()
	defer p.mu.Unlock()
	cur, ok := p.cas[ca.CAID]
	if !ok || !visible(ctx, cur.AccountID) {
		return store.ErrCANotFound
	}
	if cur.State != store.CAStatePendingCertificate {
		return store.ErrCANotPending
	}
	cur.CACertB64, cur.SubjectDN, cur.ParentCAID = ca.CACertB64, ca.SubjectDN, ca.ParentCAID
	cur.NotBefore, cur.NotAfter = ca.NotBefore, ca.NotAfter
	cur.PathLength = nil
	if ca.PathLength != nil {
		pl := *ca.PathLength
		cur.PathLength = &pl
	}
	cur.State, cur.UpdatedAt = "ACTIVE", time.Now().UTC()
	p.cas[ca.CAID] = cur
	return nil
}
