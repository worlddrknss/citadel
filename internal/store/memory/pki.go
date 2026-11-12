package memory

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// pkiState holds private CA, ACM, ACME-server and EAB records. Its zero
// value is ready to use.
type pkiState struct {
	mu       sync.Mutex
	cas      map[string]store.PCACertificateAuthority // by CA ID
	certs    map[string]store.PCACertificate          // by cert ID
	acm      map[string]store.ACMCertificate          // by ARN
	settings map[string]store.ACMEServerSettings      // by account
	eab      map[string]store.EABKey                  // by kid
}

func (p *pkiState) init() {
	if p.cas == nil {
		p.cas = map[string]store.PCACertificateAuthority{}
		p.certs = map[string]store.PCACertificate{}
		p.acm = map[string]store.ACMCertificate{}
		p.settings = map[string]store.ACMEServerSettings{}
		p.eab = map[string]store.EABKey{}
	}
}

// visible reports whether a record owned by owner may be seen by the caller:
// with a caller account only its own records, without one (internal jobs)
// everything. It mirrors store.AccountFilter in the SQL backend.
func visible(ctx context.Context, owner string) bool {
	acct, ok := store.CallerAccountFromContext(ctx)
	return !ok || acct == owner
}

func (s *Store) lockPKI() *pkiState {
	s.pki.mu.Lock()
	s.pki.init()
	return &s.pki
}

func (s *Store) CreateCertificateAuthority(ctx context.Context, ca store.PCACertificateAuthority) error {
	p := s.lockPKI()
	defer p.mu.Unlock()
	if _, dup := p.cas[ca.CAID]; dup {
		return errors.New("insert CA: duplicate ca_id")
	}
	for _, c := range p.cas {
		if c.ARN == ca.ARN {
			return errors.New("insert CA: duplicate arn")
		}
	}
	ca.AccountID = s.accountForContext(ctx)
	p.cas[ca.CAID] = ca
	return nil
}

func copyCA(ca store.PCACertificateAuthority) store.PCACertificateAuthority {
	if ca.PathLength != nil {
		pl := *ca.PathLength
		ca.PathLength = &pl
	}
	return ca
}

func (s *Store) DescribeCertificateAuthority(ctx context.Context, arn string) (store.PCACertificateAuthority, error) {
	p := s.lockPKI()
	defer p.mu.Unlock()
	for _, ca := range p.cas {
		if ca.ARN == arn && visible(ctx, ca.AccountID) {
			return copyCA(ca), nil
		}
	}
	return store.PCACertificateAuthority{}, store.ErrCANotFound
}

func (s *Store) GetCertificateAuthorityByID(ctx context.Context, caID string) (store.PCACertificateAuthority, error) {
	p := s.lockPKI()
	defer p.mu.Unlock()
	ca, ok := p.cas[caID]
	if !ok || !visible(ctx, ca.AccountID) {
		return store.PCACertificateAuthority{}, store.ErrCANotFound
	}
	return copyCA(ca), nil
}

func (s *Store) ListCertificateAuthorities(ctx context.Context) ([]store.PCACertificateAuthority, error) {
	p := s.lockPKI()
	defer p.mu.Unlock()
	var out []store.PCACertificateAuthority
	for _, ca := range p.cas {
		if visible(ctx, ca.AccountID) {
			out = append(out, copyCA(ca))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].CAID < out[j].CAID
	})
	return out, nil
}

func copyCert(c store.PCACertificate) store.PCACertificate {
	if c.RevokedAt != nil {
		t := *c.RevokedAt
		c.RevokedAt = &t
	}
	return c
}

func (s *Store) CreateCertificate(ctx context.Context, cert store.PCACertificate) error {
	p := s.lockPKI()
	defer p.mu.Unlock()
	if _, dup := p.certs[cert.CertID]; dup {
		return errors.New("insert certificate: duplicate cert_id")
	}
	for _, c := range p.certs {
		if c.CAID == cert.CAID && c.Serial == cert.Serial {
			return errors.New("insert certificate: duplicate serial")
		}
	}
	cert.AccountID = s.accountForContext(ctx)
	p.certs[cert.CertID] = copyCert(cert)
	return nil
}

func (s *Store) GetCertificate(ctx context.Context, certID string) (store.PCACertificate, error) {
	p := s.lockPKI()
	defer p.mu.Unlock()
	c, ok := p.certs[certID]
	if !ok || !visible(ctx, c.AccountID) {
		return store.PCACertificate{}, store.ErrCertificateNotFound
	}
	return copyCert(c), nil
}

func (p *pkiState) sortedCerts(ctx context.Context, keep func(store.PCACertificate) bool, newestFirst bool) []store.PCACertificate {
	var out []store.PCACertificate
	for _, c := range p.certs {
		if visible(ctx, c.AccountID) && keep(c) {
			out = append(out, copyCert(c))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt) == newestFirst
		}
		return out[i].CertID < out[j].CertID
	})
	return out
}

func (s *Store) ListCertificates(ctx context.Context, caID string) ([]store.PCACertificate, error) {
	p := s.lockPKI()
	defer p.mu.Unlock()
	return p.sortedCerts(ctx, func(c store.PCACertificate) bool { return c.CAID == caID }, true), nil
}

func (s *Store) FindCertificatesBySerial(ctx context.Context, serial string) ([]store.PCACertificate, error) {
	p := s.lockPKI()
	defer p.mu.Unlock()
	return p.sortedCerts(ctx, func(c store.PCACertificate) bool { return c.Serial == serial }, false), nil
}

func (s *Store) RevokeCertificate(ctx context.Context, certID, reason string) error {
	p := s.lockPKI()
	defer p.mu.Unlock()
	c, ok := p.certs[certID]
	if !ok || !visible(ctx, c.AccountID) {
		return store.ErrCertificateNotFound
	}
	if c.Status == "REVOKED" {
		return store.ErrCertificateAlreadyRevoked
	}
	now := time.Now().UTC()
	c.Status, c.RevokedAt, c.RevocationReason, c.UpdatedAt = "REVOKED", &now, reason, now
	p.certs[certID] = c
	return nil
}

func (s *Store) MarkExpiredCertificates(ctx context.Context, now time.Time) (int64, error) {
	p := s.lockPKI()
	defer p.mu.Unlock()
	var n int64
	for id, c := range p.certs {
		if visible(ctx, c.AccountID) && c.Status == "ISSUED" && c.NotAfter.Before(now) {
			c.Status, c.UpdatedAt = "EXPIRED", time.Now().UTC()
			p.certs[id] = c
			n++
		}
	}
	for id, c := range p.acm {
		if visible(ctx, c.AccountID) && c.Status == "ISSUED" && c.NotAfter.Before(now) {
			c.Status, c.UpdatedAt = "EXPIRED", time.Now().UTC()
			p.acm[id] = c
			n++
		}
	}
	for id, ca := range p.cas {
		if visible(ctx, ca.AccountID) && ca.State == "ACTIVE" && ca.NotAfter.Before(now) {
			ca.State, ca.UpdatedAt = "EXPIRED", time.Now().UTC()
			p.cas[id] = ca
			n++
		}
	}
	return n, nil
}

func (s *Store) GetACMEServerSettings(ctx context.Context) (store.ACMEServerSettings, error) {
	p := s.lockPKI()
	defer p.mu.Unlock()
	st, ok := p.settings[s.accountForContext(ctx)]
	if !ok {
		return store.ACMEServerSettings{}, store.ErrACMEServerSettingsNotFound
	}
	return cloneSettings(st), nil
}

func cloneSettings(st store.ACMEServerSettings) store.ACMEServerSettings {
	norm := func(v []string) []string {
		if v == nil {
			return []string{}
		}
		return slices.Clone(v)
	}
	st.AllowedDomains, st.AllowedIPRanges, st.ValidationAllowedCIDRs = norm(st.AllowedDomains), norm(st.AllowedIPRanges), norm(st.ValidationAllowedCIDRs)
	return st
}

func (s *Store) PutACMEServerSettings(ctx context.Context, in store.ACMEServerSettings) error {
	p := s.lockPKI()
	defer p.mu.Unlock()
	in.AccountID = s.accountForContext(ctx)
	if in.UpdatedAt.IsZero() {
		in.UpdatedAt = time.Now().UTC()
	}
	p.settings[in.AccountID] = cloneSettings(in)
	return nil
}

func (s *Store) CreateEABKey(ctx context.Context, k store.EABKey) error {
	p := s.lockPKI()
	defer p.mu.Unlock()
	if _, dup := p.eab[k.KID]; dup {
		return errors.New("insert eab key: duplicate kid")
	}
	k.AccountID = s.accountForContext(ctx)
	if k.Status == "" {
		k.Status = store.EABStatusUnused
	}
	k.HMACKey = slices.Clone(k.HMACKey)
	p.eab[k.KID] = k
	return nil
}

func copyEAB(k store.EABKey, withSecret bool) store.EABKey {
	if withSecret {
		k.HMACKey = slices.Clone(k.HMACKey)
	} else {
		k.HMACKey = nil
	}
	if k.BoundAt != nil {
		t := *k.BoundAt
		k.BoundAt = &t
	}
	return k
}

func (s *Store) ListEABKeys(ctx context.Context) ([]store.EABKey, error) {
	p := s.lockPKI()
	defer p.mu.Unlock()
	acct := s.accountForContext(ctx)
	var out []store.EABKey
	for _, k := range p.eab {
		if k.AccountID == acct {
			out = append(out, copyEAB(k, false))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].KID < out[j].KID
	})
	return out, nil
}

func (s *Store) GetEABKey(ctx context.Context, kid string) (store.EABKey, error) {
	p := s.lockPKI()
	defer p.mu.Unlock()
	k, ok := p.eab[kid]
	if !ok || !visible(ctx, k.AccountID) {
		return store.EABKey{}, store.ErrEABKeyNotFound
	}
	return copyEAB(k, true), nil
}

func (s *Store) RevokeEABKey(ctx context.Context, kid string) (store.EABKey, error) {
	p := s.lockPKI()
	defer p.mu.Unlock()
	k, ok := p.eab[kid]
	if !ok || k.AccountID != s.accountForContext(ctx) {
		return store.EABKey{}, store.ErrEABKeyNotFound
	}
	k.Status = store.EABStatusRevoked
	p.eab[kid] = k
	return copyEAB(k, false), nil
}

func (s *Store) BindEABKey(ctx context.Context, kid, acmeAccountID string, at time.Time) error {
	p := s.lockPKI()
	defer p.mu.Unlock()
	k, ok := p.eab[kid]
	if !ok || !visible(ctx, k.AccountID) || k.Status != store.EABStatusUnused {
		return store.ErrEABKeyUnavailable
	}
	k.Status, k.BoundAt, k.ACMEAccountID = store.EABStatusBound, &at, acmeAccountID
	p.eab[kid] = k
	return nil
}

func copyACM(c store.ACMCertificate, withKey bool) store.ACMCertificate {
	c.SANs = slices.Clone(c.SANs)
	if c.SANs == nil {
		c.SANs = []string{}
	}
	if withKey {
		c.KeyDER = slices.Clone(c.KeyDER)
	} else {
		c.KeyDER = nil
	}
	return c
}

func (s *Store) CreateACMCertificate(ctx context.Context, c store.ACMCertificate) error {
	p := s.lockPKI()
	defer p.mu.Unlock()
	if _, dup := p.acm[c.ARN]; dup {
		return store.ErrACMCertificateExists
	}
	c.AccountID = s.accountForContext(ctx)
	p.acm[c.ARN] = copyACM(c, true)
	return nil
}

func (s *Store) GetACMCertificate(ctx context.Context, arn string) (store.ACMCertificate, error) {
	p := s.lockPKI()
	defer p.mu.Unlock()
	c, ok := p.acm[arn]
	if !ok || !visible(ctx, c.AccountID) {
		return store.ACMCertificate{}, store.ErrACMCertificateNotFound
	}
	return copyACM(c, true), nil
}

func (s *Store) ListACMCertificates(ctx context.Context) ([]store.ACMCertificate, error) {
	p := s.lockPKI()
	defer p.mu.Unlock()
	var out []store.ACMCertificate
	for _, c := range p.acm {
		if visible(ctx, c.AccountID) {
			out = append(out, copyACM(c, false))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return strings.Compare(out[i].ARN, out[j].ARN) < 0
	})
	return out, nil
}

func (s *Store) UpdateACMCertificate(ctx context.Context, c store.ACMCertificate) error {
	p := s.lockPKI()
	defer p.mu.Unlock()
	cur, ok := p.acm[c.ARN]
	if !ok || !visible(ctx, cur.AccountID) {
		return store.ErrACMCertificateNotFound
	}
	c.AccountID, c.CreatedAt, c.UpdatedAt = cur.AccountID, cur.CreatedAt, time.Now().UTC()
	p.acm[c.ARN] = copyACM(c, true)
	return nil
}

func (s *Store) DeleteACMCertificate(ctx context.Context, arn string) error {
	p := s.lockPKI()
	defer p.mu.Unlock()
	c, ok := p.acm[arn]
	if !ok || !visible(ctx, c.AccountID) {
		return store.ErrACMCertificateNotFound
	}
	delete(p.acm, arn)
	return nil
}
