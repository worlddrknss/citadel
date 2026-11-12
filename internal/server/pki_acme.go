package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/worlddrknss/citadel/internal/acme"
	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/postgres"
)

// Citadel's ACME server: internal/acme mounted at /acme/, issuing from the
// tenant's private CA. Every ACME account must be created with an external
// account binding key, which ties it to the Citadel account that issued the
// key; that account's ACME settings decide the issuing CA, which names may
// be requested and which addresses http-01 validation may reach.

// auditActorACME is the actor type of events caused by an ACME account.
const auditActorACME = "acme-account"

// pkiRuntime is the lazily built ACME machinery.
type pkiRuntime struct {
	once      sync.Once
	acmeStore acme.Store
	acmeSrv   *acme.Server // nil when ACME is disabled
	handler   http.Handler

	// validators overrides challenge validators (tests only); it must be
	// set before first use.
	validators map[string]acme.Validator
}

// acmeRuntime builds the ACME server on first use.
func (s *Server) acmeRuntime() *pkiRuntime {
	rt := &s.pki
	rt.once.Do(func() {
		if pg, ok := s.store.(*postgres.Store); ok {
			rt.acmeStore = pg.ACMEServerStore()
		} else {
			rt.acmeStore = acme.NewMemoryStore()
		}
		if s.cfg.PublicURL == "" {
			log.Printf("ACME server disabled: set KMS_PUBLIC_URL (the externally visible base URL) to enable /acme/")
			rt.handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"type":"urn:ietf:params:acme:error:malformed","detail":"the ACME server is not enabled on this deployment","status":404}`))
			})
			return
		}
		validators := map[string]acme.Validator{acme.ChallengeHTTP01: guardedHTTP01{s: s}}
		for k, v := range rt.validators {
			validators[k] = v
		}
		srv, err := acme.New(acme.Config{
			BaseURL:    s.cfg.PublicURL + "/acme",
			Store:      rt.acmeStore,
			Issuer:     acmeIssuer{s: s},
			Policy:     acmePolicy{s: s},
			Validators: validators,
			RequireEAB: true,
			EABKeys:    acmeEAB{s: s},
			Website:    s.cfg.PublicURL,
			Logger:     slog.Default(),
		})
		if err != nil {
			log.Printf("ACME server disabled: %v", err)
			rt.handler = http.NotFoundHandler()
			return
		}
		rt.acmeSrv = srv
		rt.handler = newACMERateLimiter(s).wrap(srv)
		log.Printf("ACME server enabled at %s/acme/directory", s.cfg.PublicURL)
	})
	return rt
}

// acmeAuditCtx scopes ctx to the bound Citadel account for store access and
// audit records.
func acmeAuditCtx(ctx context.Context, accountRef string) context.Context {
	return store.WithCallerAccount(ctx, accountRef)
}

func (s *Server) recordACMEAudit(ctx context.Context, action, acmeAccountID, resource, result, errType string) {
	s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: resource, Result: result, ErrorType: errType,
		AuditOrigin: store.AuditOrigin{Actor: "acme:" + acmeAccountID, ActorType: auditActorACME, Resource: resource}})
}

// acmeIssuingCA returns the account's configured issuing CA, or its first
// active CA when none is configured. ctx must carry the account.
func (s *Server) acmeIssuingCA(ctx context.Context) (store.PCACertificateAuthority, error) {
	settings, err := s.store.GetACMEServerSettings(ctx)
	if err != nil && !errors.Is(err, store.ErrACMEServerSettingsNotFound) {
		return store.PCACertificateAuthority{}, err
	}
	if settings.IssuingCAID != "" {
		return s.store.GetCertificateAuthorityByID(ctx, settings.IssuingCAID)
	}
	cas, err := s.store.ListCertificateAuthorities(ctx)
	if err != nil {
		return store.PCACertificateAuthority{}, err
	}
	var best *store.PCACertificateAuthority
	now := time.Now()
	for i := range cas {
		ca := &cas[i]
		if ca.State != "ACTIVE" || now.After(ca.NotAfter) {
			continue
		}
		if best == nil || ca.CreatedAt.Before(best.CreatedAt) {
			best = ca
		}
	}
	if best == nil {
		return store.PCACertificateAuthority{}, store.ErrCANotFound
	}
	return *best, nil
}

// acmeIssuer issues ACME certificates from the bound account's CA.
type acmeIssuer struct{ s *Server }

const acmeDefaultLifetime = 90 * 24 * time.Hour

func (i acmeIssuer) Issue(ctx context.Context, req acme.IssueRequest) ([]byte, error) {
	if req.AccountRef == "" {
		return nil, &acme.Problem{Type: "urn:ietf:params:acme:error:unauthorized", Detail: "ACME account is not bound to a Citadel account", Status: http.StatusForbidden}
	}
	ctx = acmeAuditCtx(ctx, req.AccountRef)
	ca, err := i.s.acmeIssuingCA(ctx)
	if err != nil {
		i.s.recordACMEAudit(ctx, "citadel.ACMEIssueCertificate", req.AccountID, req.OrderID, "error", "NoIssuingCA")
		if errors.Is(err, store.ErrCANotFound) {
			return nil, &acme.Problem{Type: "urn:ietf:params:acme:error:serverInternal", Detail: "no active certificate authority is configured for ACME on this account", Status: http.StatusInternalServerError}
		}
		return nil, err
	}
	var names []string
	cn := req.CSR.Subject.CommonName
	for _, id := range req.Identifiers {
		names = append(names, id.Value)
		if cn == "" && id.Type == acme.IdentifierDNS {
			cn = id.Value
		}
	}
	notAfter := req.NotAfter
	if notAfter.IsZero() {
		notAfter = time.Now().Add(acmeDefaultLifetime)
	}
	leaf, err := i.s.pkiIssueLeaf(ctx, leafRequest{CA: ca, CSR: req.CSR, Template: templateServer, CommonName: cn,
		ExtraSANs: names, ExactNames: true, NotAfter: notAfter})
	if err != nil {
		i.s.recordACMEAudit(ctx, "citadel.ACMEIssueCertificate", req.AccountID, req.OrderID, "error", "IssueFailed")
		var pe *pkiError
		if errors.As(err, &pe) {
			return nil, &acme.Problem{Type: "urn:ietf:params:acme:error:badCSR", Detail: pe.msg, Status: http.StatusBadRequest}
		}
		return nil, err
	}
	i.s.recordACMEAudit(ctx, "citadel.ACMEIssueCertificate", req.AccountID, leaf.rec.CertID, "ok", "")
	out := append(encodeCertificatePEM(leaf.cert.Raw), leaf.chainPEM...)
	return out, nil
}

func (i acmeIssuer) Revoke(ctx context.Context, serial *big.Int, reason int) error {
	matches, err := i.s.store.FindCertificatesBySerial(ctx, serial.String())
	if err != nil {
		return err
	}
	if len(matches) != 1 {
		return fmt.Errorf("acme revoke: %d certificates with serial %s", len(matches), serial)
	}
	cert := matches[0]
	actx := acmeAuditCtx(ctx, cert.AccountID)
	name, ok := consoleReasonNames[reason]
	if !ok {
		name = consoleReasonNames[0]
	}
	err = i.s.store.RevokeCertificate(actx, cert.CertID, name)
	if errors.Is(err, store.ErrCertificateAlreadyRevoked) {
		return acme.ErrAlreadyRevoked
	}
	result, errType := "ok", ""
	if err != nil {
		result, errType = "error", "RevokeFailed"
	}
	i.s.recordAudit(actx, store.AuditEvent{Action: "citadel.ACMERevokeCertificate", KeyID: cert.CertID, Result: result, ErrorType: errType,
		AuditOrigin: store.AuditOrigin{Actor: "acme", ActorType: auditActorACME, Resource: cert.CertID}})
	return err
}

// acmeEAB resolves and binds EAB keys.
type acmeEAB struct{ s *Server }

func (e acmeEAB) Lookup(ctx context.Context, kid string) ([]byte, string, error) {
	k, err := e.s.store.GetEABKey(ctx, kid)
	if err != nil {
		return nil, "", err
	}
	if k.Status != store.EABStatusUnused {
		return nil, "", store.ErrEABKeyUnavailable
	}
	return k.HMACKey, k.AccountID, nil
}

func (e acmeEAB) Bind(ctx context.Context, kid, accountID string) error {
	k, err := e.s.store.GetEABKey(ctx, kid)
	if err != nil {
		return err
	}
	clear(k.HMACKey)
	actx := acmeAuditCtx(ctx, k.AccountID)
	if err := e.s.store.BindEABKey(actx, kid, accountID, time.Now().UTC()); err != nil {
		e.s.recordACMEAudit(actx, "citadel.ACMEBindAccount", accountID, kid, "error", "EABKeyUnavailable")
		return err
	}
	e.s.recordACMEAudit(actx, "citadel.ACMEBindAccount", accountID, kid, "ok", "")
	return nil
}

// acmePolicy enforces the bound account's allowed names.
type acmePolicy struct{ s *Server }

func acmeRejected(id acme.Identifier, detail string) error {
	return &acme.Problem{Type: "urn:ietf:params:acme:error:rejectedIdentifier", Detail: detail, Status: http.StatusBadRequest, Identifier: &id}
}

func (p acmePolicy) Allow(ctx context.Context, accountRef string, id acme.Identifier) error {
	if accountRef == "" {
		return acmeRejected(id, "ACME account is not bound to a Citadel account")
	}
	settings, err := p.s.store.GetACMEServerSettings(acmeAuditCtx(ctx, accountRef))
	if errors.Is(err, store.ErrACMEServerSettingsNotFound) {
		return acmeRejected(id, "no ACME identifiers are allowed for this account")
	}
	if err != nil {
		return err
	}
	switch id.Type {
	case acme.IdentifierDNS:
		name := strings.TrimPrefix(id.Value, "*.")
		for _, suffix := range settings.AllowedDomains {
			suffix = strings.ToLower(strings.Trim(strings.TrimSpace(suffix), "."))
			if suffix != "" && (name == suffix || strings.HasSuffix(name, "."+suffix)) {
				return nil
			}
		}
		return acmeRejected(id, fmt.Sprintf("%q is not under a domain allowed for this account", id.Value))
	case acme.IdentifierIP:
		addr, err := netip.ParseAddr(id.Value)
		if err != nil {
			return acmeRejected(id, "invalid IP address")
		}
		addr = addr.Unmap()
		if !prefixesContain(settings.AllowedIPRanges, addr) {
			return acmeRejected(id, fmt.Sprintf("%s is not in an IP range allowed for this account", id.Value))
		}
		if ssrfBlocked(addr) && !prefixesContain(settings.ValidationAllowedCIDRs, addr) {
			return acmeRejected(id, fmt.Sprintf("%s is a loopback, link-local or metadata address", id.Value))
		}
		return nil
	}
	return acmeRejected(id, "unsupported identifier type")
}

func prefixesContain(cidrs []string, addr netip.Addr) bool {
	for _, c := range cidrs {
		if p, err := parseCIDROrAddr(c); err == nil && p.Contains(addr) {
			return true
		}
	}
	return false
}

func parseCIDROrAddr(raw string) (netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "/") {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return netip.Prefix{}, err
		}
		if p.Addr().Is4In6() {
			return netip.Prefix{}, fmt.Errorf("IPv4-mapped prefixes are not supported")
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// ssrfBlockedPrefixes are addresses http-01 validation must not reach unless
// an account explicitly allows them: cloud metadata services and other
// host-local endpoints.
var ssrfBlockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("169.254.169.254/32"), // AWS, GCP, Azure, OpenStack metadata (also covered by link-local)
	netip.MustParsePrefix("100.100.100.200/32"), // Alibaba Cloud metadata
	netip.MustParsePrefix("192.0.0.192/32"),     // Oracle Cloud metadata
	netip.MustParsePrefix("168.63.129.16/32"),   // Azure wire server
	netip.MustParsePrefix("fd00:ec2::254/128"),  // AWS IPv6 metadata
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("255.255.255.255/32"),
}

// ssrfBlocked reports whether addr is loopback, link-local, unspecified,
// multicast or a known metadata address.
func ssrfBlocked(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsInterfaceLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	for _, p := range ssrfBlockedPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

var errSSRFBlocked = errors.New("validation target address is not allowed")

// ssrfDialControl rejects connections to blocked addresses at dial time, so
// DNS answers and redirects cannot steer validation to them.
func ssrfDialControl(allowed []string) func(ctx context.Context, network, address string, c syscall.RawConn) error {
	return func(_ context.Context, _ string, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return errSSRFBlocked
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return errSSRFBlocked
		}
		addr = addr.Unmap()
		if ssrfBlocked(addr) && !prefixesContain(allowed, addr) {
			return errSSRFBlocked
		}
		return nil
	}
}

// ssrfHTTPClient is acme.DefaultHTTP01Client with the dial-time guard.
func ssrfHTTPClient(allowed []string) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, ControlContext: ssrfDialControl(allowed)}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            dialer.DialContext,
			TLSHandshakeTimeout:    5 * time.Second,
			ResponseHeaderTimeout:  10 * time.Second,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
			DisableKeepAlives:      true,
			MaxResponseHeaderBytes: 16 << 10,
		},
	}
}

// guardedHTTP01 is http-01 validation with the account's SSRF policy.
type guardedHTTP01 struct{ s *Server }

func (g guardedHTTP01) Validate(ctx context.Context, id acme.Identifier, token, keyAuth string) error {
	ref := acme.AccountRefFromContext(ctx)
	var allowed []string
	if ref != "" {
		settings, err := g.s.store.GetACMEServerSettings(acmeAuditCtx(ctx, ref))
		if err != nil && !errors.Is(err, store.ErrACMEServerSettingsNotFound) {
			return err
		}
		allowed = settings.ValidationAllowedCIDRs
	}
	err := acme.HTTP01Validator{Client: ssrfHTTPClient(allowed)}.Validate(ctx, id, token, keyAuth)
	var p *acme.Problem
	if errors.As(err, &p) && strings.Contains(p.Detail, errSSRFBlocked.Error()) {
		return &acme.Problem{Type: "urn:ietf:params:acme:error:connection", Status: http.StatusBadRequest,
			Detail: "validation target resolves to a loopback, link-local or metadata address, which this account does not allow"}
	}
	return err
}

// acmeRateLimiter limits newNonce and newAccount per client IP.
type acmeRateLimiter struct {
	s       *Server
	mu      sync.Mutex
	buckets map[string]*tokenBucket
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

type rateRule struct {
	perSecond float64
	burst     float64
}

var (
	acmeNonceRule   = rateRule{perSecond: 2, burst: 20}
	acmeAccountRule = rateRule{perSecond: 0.1, burst: 5}
)

func newACMERateLimiter(s *Server) *acmeRateLimiter {
	return &acmeRateLimiter{s: s, buckets: map[string]*tokenBucket{}}
}

func (l *acmeRateLimiter) allow(key string, rule rateRule, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.buckets) > 50000 {
		for k, b := range l.buckets {
			if now.Sub(b.last) > 10*time.Minute {
				delete(l.buckets, k)
			}
		}
	}
	b, ok := l.buckets[key]
	if !ok {
		b = &tokenBucket{tokens: rule.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * rule.perSecond
	if b.tokens > rule.burst {
		b.tokens = rule.burst
	}
	b.last = now
	if b.tokens < 1 {
		wait := time.Duration((1 - b.tokens) / rule.perSecond * float64(time.Second))
		return false, wait
	}
	b.tokens--
	return true, 0
}

func (l *acmeRateLimiter) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rule rateRule
		var kind string
		switch {
		case strings.HasSuffix(r.URL.Path, "/new-nonce"):
			rule, kind = acmeNonceRule, "nonce"
		case strings.HasSuffix(r.URL.Path, "/new-account"):
			rule, kind = acmeAccountRule, "account"
		default:
			next.ServeHTTP(w, r)
			return
		}
		ok, wait := l.allow(kind+"|"+l.s.clientIP(r), rule, time.Now())
		if !ok {
			secs := int(wait.Seconds()) + 1
			w.Header().Set("Retry-After", fmt.Sprint(secs))
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"type":"urn:ietf:params:acme:error:rateLimited","detail":"too many requests from this address","status":429}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

var errACMEStale = acme.ErrStale
