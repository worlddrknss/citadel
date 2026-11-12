package acme

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Issuer signs certificates for finalized orders and revokes them.
type Issuer interface {
	// Issue signs the CSR. The server has already checked the CSR's
	// signature, key type and that its names equal req.Identifiers. It
	// returns a PEM chain, leaf first. Returning a *Problem sets the error
	// the client sees; other errors become serverInternal.
	Issue(ctx context.Context, req IssueRequest) (chainPEM []byte, err error)
	// Revoke revokes the certificate with the given serial. It returns
	// ErrAlreadyRevoked if it was already revoked.
	Revoke(ctx context.Context, serial *big.Int, reason int) error
}

// IssueRequest is passed to Issuer.Issue.
type IssueRequest struct {
	// AccountRef is the host account bound via EAB ("" if unbound).
	AccountRef string
	// AccountID and OrderID identify the ACME objects, for audit.
	AccountID string
	OrderID   string
	CSR       *x509.CertificateRequest
	// Identifiers are the order's normalized identifiers.
	Identifiers []Identifier
	// NotAfter is the client-requested expiry, or zero for the issuer's
	// default.
	NotAfter time.Time
}

// EABResolver resolves external account binding keys (RFC 8555 §7.3.4).
type EABResolver interface {
	// Lookup returns the HMAC key (at least 32 bytes) for an EAB key ID and
	// the host account reference the new ACME account is bound to.
	Lookup(ctx context.Context, kid string) (hmacKey []byte, accountRef string, err error)
}

// EABBinder may be implemented by an EABResolver to enforce single-use
// binding keys. Bind is called after the binding's MAC has been verified and
// before the ACME account is stored; it must atomically mark the key as used
// by accountID and fail if it was already used or is no longer valid. A
// failed Bind rejects the newAccount request.
type EABBinder interface {
	Bind(ctx context.Context, kid, accountID string) error
}

type accountRefCtxKey struct{}

func withAccountRef(ctx context.Context, ref string) context.Context {
	return context.WithValue(ctx, accountRefCtxKey{}, ref)
}

// AccountRefFromContext returns the host account reference of the ACME
// account whose challenge is being validated. Validators receive it in their
// context so host policy (for example which addresses may be fetched) can
// depend on the tenant. It returns "" for unbound accounts.
func AccountRefFromContext(ctx context.Context) string {
	ref, _ := ctx.Value(accountRefCtxKey{}).(string)
	return ref
}

// Config configures a Server. BaseURL, Store, Issuer and Policy are
// required.
type Config struct {
	// BaseURL is the externally visible URL of the mount point, for
	// example "https://citadel.example.com/acme". All ACME URLs are
	// BaseURL + "/directory", "/new-nonce", ... and JWS "url" headers must
	// match them exactly.
	BaseURL string
	Store   Store
	Issuer  Issuer
	Policy  Policy
	// Validators overrides challenge validators by type ("http-01",
	// "dns-01"). Types without an entry use HTTP01Validator{} and
	// DNS01Validator{}.
	Validators map[string]Validator
	// Clock returns the current time; nil means time.Now.
	Clock func() time.Time
	// Logger receives operational logs; nil means slog.Default().
	Logger *slog.Logger

	// RequireEAB makes newAccount require externalAccountBinding.
	RequireEAB bool
	// EABKeys resolves EAB keys. Required when RequireEAB is set; when set
	// without RequireEAB, a supplied binding is still verified.
	EABKeys EABResolver
	// TermsOfService, if set, is advertised and must be agreed to.
	TermsOfService string
	// Website is advertised in the directory meta, if set.
	Website string

	// OrderLifetime bounds how long an order may stay pending (default 7d).
	OrderLifetime time.Duration
	// AuthzLifetime is how long a valid authorization stays valid
	// (default 30d).
	AuthzLifetime time.Duration
	// NonceLifetime is how long an unused nonce stays valid (default 1h).
	NonceLifetime time.Duration
	// ValidationTimeout bounds one challenge validation (default 30s).
	ValidationTimeout time.Duration
	// IssueTimeout bounds one Issuer.Issue call (default 60s).
	IssueTimeout time.Duration
	// MaxCertLifetime caps a client-requested notAfter (default 398d).
	MaxCertLifetime time.Duration
	// MaxIdentifiers caps identifiers per order (default 100).
	MaxIdentifiers int
	// MaxPendingOrders caps pending/ready orders per account (default 300).
	MaxPendingOrders int
	// MaxConcurrentValidations caps concurrent validations (default 64).
	MaxConcurrentValidations int
}

// Server is an RFC 8555 ACME server. Create it with New and release it
// with Close.
type Server struct {
	cfg        Config
	base       string
	basePath   string
	store      Store
	now        func() time.Time
	log        *slog.Logger
	validators map[string]Validator

	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
	sem    chan struct{}
}

const maxBodyBytes = 64 << 10

// New validates cfg and returns a Server.
func New(cfg Config) (*Server, error) {
	if cfg.BaseURL == "" || cfg.Store == nil || cfg.Issuer == nil || cfg.Policy == nil {
		return nil, errors.New("acme: BaseURL, Store, Issuer and Policy are required")
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("acme: BaseURL must be an absolute http(s) URL without query")
	}
	if cfg.RequireEAB && cfg.EABKeys == nil {
		return nil, errors.New("acme: RequireEAB needs EABKeys")
	}
	setDefault := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	setDefault(&cfg.OrderLifetime, 7*24*time.Hour)
	setDefault(&cfg.AuthzLifetime, 30*24*time.Hour)
	setDefault(&cfg.NonceLifetime, time.Hour)
	setDefault(&cfg.ValidationTimeout, 30*time.Second)
	setDefault(&cfg.IssueTimeout, 60*time.Second)
	setDefault(&cfg.MaxCertLifetime, 398*24*time.Hour)
	if cfg.MaxIdentifiers <= 0 {
		cfg.MaxIdentifiers = 100
	}
	if cfg.MaxPendingOrders <= 0 {
		cfg.MaxPendingOrders = 300
	}
	if cfg.MaxConcurrentValidations <= 0 {
		cfg.MaxConcurrentValidations = 64
	}
	s := &Server{
		cfg:        cfg,
		base:       trimURL(cfg.BaseURL),
		basePath:   strings.TrimRight(u.Path, "/"),
		store:      cfg.Store,
		now:        cfg.Clock,
		log:        cfg.Logger,
		validators: map[string]Validator{ChallengeHTTP01: HTTP01Validator{}, ChallengeDNS01: DNS01Validator{}},
		sem:        make(chan struct{}, cfg.MaxConcurrentValidations),
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	for k, v := range cfg.Validators {
		s.validators[k] = v
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	return s, nil
}

// Close cancels in-flight validations and waits for them to finish.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.cancel()
	s.wg.Wait()
	return nil
}

// URL paths relative to BaseURL.
const (
	pathDirectory = "/directory"
	pathNewNonce  = "/new-nonce"
	pathNewAcct   = "/new-account"
	pathNewOrder  = "/new-order"
	pathRevoke    = "/revoke-cert"
	pathKeyChange = "/key-change"
	pathAcct      = "/acct/"
	pathOrder     = "/order/"
	pathAuthz     = "/authz/"
	pathChall     = "/chall/"
	pathCert      = "/cert/"
)

func (s *Server) url(rel string) string { return s.base + rel }

// relPath maps the request path to a path relative to BaseURL. It works
// whether the host strips the mount prefix or not.
func (s *Server) relPath(p string) string {
	if s.basePath != "" && strings.HasPrefix(p, s.basePath+"/") {
		return p[len(s.basePath):]
	}
	return p
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rel := s.relPath(r.URL.Path)
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Add("Link", linkHeader(s.url(pathDirectory), "index"))
	if n, err := s.newNonce(r.Context()); err == nil {
		h.Set("Replay-Nonce", n)
	} else {
		s.log.Error("acme: storing nonce", "err", err)
	}

	seg := strings.Split(strings.Trim(rel, "/"), "/")
	switch {
	case rel == pathDirectory:
		if !s.method(w, r, http.MethodGet, http.MethodHead) {
			return
		}
		s.handleDirectory(w, r)
	case rel == pathNewNonce:
		if !s.method(w, r, http.MethodGet, http.MethodHead) {
			return
		}
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	case !s.method(w, r, http.MethodPost):
		return
	case rel == pathNewAcct:
		s.handleNewAccount(w, r, rel)
	case rel == pathNewOrder:
		s.handleNewOrder(w, r, rel)
	case rel == pathRevoke:
		s.handleRevoke(w, r, rel)
	case rel == pathKeyChange:
		s.handleKeyChange(w, r, rel)
	case len(seg) == 2 && seg[0] == "acct":
		s.handleAccount(w, r, rel, seg[1])
	case len(seg) == 3 && seg[0] == "acct" && seg[2] == "orders":
		s.handleOrderList(w, r, rel, seg[1])
	case len(seg) == 2 && seg[0] == "order":
		s.handleOrder(w, r, rel, seg[1])
	case len(seg) == 3 && seg[0] == "order" && seg[2] == "finalize":
		s.handleFinalize(w, r, rel, seg[1])
	case len(seg) == 2 && seg[0] == "authz":
		s.handleAuthz(w, r, rel, seg[1])
	case len(seg) == 3 && seg[0] == "chall":
		s.handleChallenge(w, r, rel, seg[1], seg[2])
	case len(seg) == 2 && seg[0] == "cert":
		s.handleCert(w, r, rel, seg[1])
	default:
		s.problem(w, notFound("resource"))
	}
}

func (s *Server) method(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	for _, m := range allowed {
		if r.Method == m {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	s.problem(w, newProblem(ProbMalformed, http.StatusMethodNotAllowed, "method %s not allowed", r.Method))
	return false
}

func linkHeader(u, rel string) string { return "<" + u + `>;rel="` + rel + `"` }

func randomID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return b64enc(b)
}

func (s *Server) newNonce(ctx context.Context) (string, error) {
	n := randomID(16)
	return n, s.store.AddNonce(ctx, n, s.now().Add(s.cfg.NonceLifetime))
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		s.problem(w, serverInternal("encoding response"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func (s *Server) problem(w http.ResponseWriter, p *Problem) {
	if p.Status == 0 {
		p.Status = statusFor(p.Type)
	}
	b, _ := json.Marshal(p)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	_, _ = w.Write(b)
}

// internal logs err and returns a generic serverInternal problem.
func (s *Server) internal(msg string, err error) *Problem {
	s.log.Error("acme: "+msg, "err", err)
	return serverInternal("%s", msg)
}

// keyMode says which key reference an endpoint accepts.
type keyMode int

const (
	kidOnly keyMode = iota
	jwkOnly
	jwkOrKID
)

// authedRequest is a verified POST.
type authedRequest struct {
	url     string
	account *Account // nil when signed with an embedded jwk
	key     crypto.PublicKey
	thumb   string
	payload []byte
}

func (a *authedRequest) postAsGet() bool { return len(a.payload) == 0 }

// verify authenticates a POST per RFC 8555 §6.2–6.5.
func (s *Server) verify(r *http.Request, rel string, mode keyMode) (*authedRequest, *Problem) {
	ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || ct != "application/jose+json" {
		return nil, newProblem(ProbMalformed, http.StatusUnsupportedMediaType, "Content-Type must be application/jose+json")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return nil, malformed("reading request body")
	}
	if len(body) > maxBodyBytes {
		return nil, newProblem(ProbMalformed, http.StatusRequestEntityTooLarge, "request body too large")
	}
	j, prob := parseJWS(body)
	if prob != nil {
		return nil, prob
	}
	h := j.header
	if prob := checkOuterAlg(h.Alg); prob != nil {
		return nil, prob
	}
	want := s.url(rel)
	if h.URL == "" {
		return nil, malformed("JWS protected header has no url")
	}
	if h.URL != want {
		return nil, unauthorized("JWS url %q does not match request URL %q", h.URL, want)
	}
	if h.Nonce == "" {
		return nil, newProblem(ProbBadNonce, http.StatusBadRequest, "JWS protected header has no nonce")
	}
	hasJWK, hasKID := len(h.JWK) > 0, h.KID != ""
	if hasJWK == hasKID {
		return nil, malformed("JWS must contain exactly one of jwk and kid")
	}
	if hasJWK && mode == kidOnly {
		return nil, malformed("this request must be signed with an account key (kid)")
	}
	if hasKID && mode == jwkOnly {
		return nil, malformed("this request must be signed with an embedded jwk")
	}

	req := &authedRequest{url: want, payload: j.payload}
	if hasJWK {
		pub, prob := parseJWK(h.JWK)
		if prob != nil {
			return nil, prob
		}
		req.key = pub
	} else {
		prefix := s.url(pathAcct)
		id, ok := strings.CutPrefix(h.KID, prefix)
		if !ok || id == "" || strings.Contains(id, "/") {
			return nil, newProblem(ProbAccountDoesNotExist, http.StatusBadRequest, "kid is not an account URL of this server")
		}
		acct, err := s.store.GetAccount(r.Context(), id)
		if errors.Is(err, ErrNotFound) {
			return nil, newProblem(ProbAccountDoesNotExist, http.StatusBadRequest, "account does not exist")
		}
		if err != nil {
			return nil, s.internal("loading account", err)
		}
		if acct.Status != StatusValid {
			return nil, unauthorized("account is %s", acct.Status)
		}
		pub, prob := parseJWK(acct.KeyJWK)
		if prob != nil {
			return nil, s.internal("stored account key unusable", prob)
		}
		req.account, req.key = acct, pub
	}
	if !algMatchesKey(h.Alg, req.key) {
		return nil, badSigAlg("algorithm %s does not match the key type", h.Alg)
	}
	if err := verifySignature(h.Alg, req.key, j.signingInput, j.signature); err != nil {
		return nil, malformed("JWS signature verification failed")
	}
	ok, err := s.store.ConsumeNonce(r.Context(), h.Nonce, s.now())
	if err != nil {
		return nil, s.internal("checking nonce", err)
	}
	if !ok {
		return nil, newProblem(ProbBadNonce, http.StatusBadRequest, "JWS has an invalid or reused nonce")
	}
	tp, err := Thumbprint(req.key)
	if err != nil {
		return nil, s.internal("computing thumbprint", err)
	}
	req.thumb = tp
	return req, nil
}

// decodePayload strictly decodes a JSON object payload.
func decodePayload(payload []byte, v any) *Problem {
	if len(payload) == 0 {
		return malformed("request payload must not be empty")
	}
	if err := json.Unmarshal(payload, v); err != nil {
		return malformed("invalid request payload: %v", err)
	}
	return nil
}

// ---- JSON representations ----

type directoryJSON struct {
	NewNonce   string        `json:"newNonce"`
	NewAccount string        `json:"newAccount"`
	NewOrder   string        `json:"newOrder"`
	RevokeCert string        `json:"revokeCert"`
	KeyChange  string        `json:"keyChange"`
	Meta       directoryMeta `json:"meta"`
}

type directoryMeta struct {
	TermsOfService          string `json:"termsOfService,omitempty"`
	Website                 string `json:"website,omitempty"`
	ExternalAccountRequired bool   `json:"externalAccountRequired"`
}

func (s *Server) handleDirectory(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, directoryJSON{
		NewNonce:   s.url(pathNewNonce),
		NewAccount: s.url(pathNewAcct),
		NewOrder:   s.url(pathNewOrder),
		RevokeCert: s.url(pathRevoke),
		KeyChange:  s.url(pathKeyChange),
		Meta: directoryMeta{
			TermsOfService:          s.cfg.TermsOfService,
			Website:                 s.cfg.Website,
			ExternalAccountRequired: s.cfg.RequireEAB,
		},
	})
}

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func retryAfter(w http.ResponseWriter, d time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(d.Seconds())))
}

func serialHex(n *big.Int) string { return fmt.Sprintf("%x", n) }
