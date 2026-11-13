package server

import (
	"crypto/hkdf"
	"crypto/sha256"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/worlddrknss/citadel/internal/oidclogin"
	"github.com/worlddrknss/citadel/internal/ratelimit"
	"github.com/worlddrknss/citadel/internal/workloadid"
)

// identityState is the process-local machinery of the identity domain
// (console SSO, workload identity, first-run bootstrap token). It is kept
// beside the Server (keyed by its pointer) rather than in it so the domain
// stays in its own files.
type identityState struct {
	// bootstrap token (see bootstrap_token.go). bootShared: the token lives
	// in the database (any replica's generated token is accepted).
	bootMu       sync.Mutex
	bootToken    string
	bootConsumed bool
	bootShared   bool

	// SSO relying parties, one per provider version.
	rpMu  sync.Mutex
	rps   map[string]*oidclogin.RelyingParty
	ssoIP *ratelimit.Limiter

	// workload identity
	issuerOnce sync.Once
	issuer     *workloadid.Issuer
	issuerErr  error
	signers    *kmsSignerSet
	tokenIP    *ratelimit.Limiter
	tokenCli   *ratelimit.Limiter
	k8sAuth    *workloadid.KubernetesAuthenticator

	// Test hooks: a client for outbound IdP / Kubernetes calls and
	// permission to use plain http for them.
	httpClient        *http.Client
	allowInsecureHTTP bool
	now               func() time.Time
}

var identityStates sync.Map // *Server -> *identityState

func (s *Server) identity() *identityState {
	if v, ok := identityStates.Load(s); ok {
		return v.(*identityState)
	}
	st := &identityState{
		rps:      map[string]*oidclogin.RelyingParty{},
		ssoIP:    ratelimit.New(time.Second, 30),
		tokenIP:  ratelimit.New(time.Second, 30),
		tokenCli: ratelimit.New(200*time.Millisecond, 60),
		now:      time.Now,
	}
	v, _ := identityStates.LoadOrStore(s, st)
	return v.(*identityState)
}

// identitySecret is the deployment secret identity keys are derived from
// (see deploymentSecret). nil disables SSO.
func (s *Server) identitySecret() []byte {
	if secret := s.deploymentSecret(); len(secret) >= 32 {
		return secret
	}
	return nil
}

// deriveIdentityKey HKDF-SHA256-derives a 32-byte key for purpose.
func (s *Server) deriveIdentityKey(purpose string) ([]byte, bool) {
	secret := s.identitySecret()
	if secret == nil {
		return nil, false
	}
	k, err := hkdf.Key(sha256.New, secret, []byte("citadel/identity/v1"), purpose, 32)
	if err != nil {
		return nil, false
	}
	return k, true
}

// publicURL is KMS_PUBLIC_URL (no trailing slash), or "".
func (s *Server) publicURL() string { return strings.TrimRight(s.cfg.PublicURL, "/") }

// insecureIdentityURLs permits http:// issuers and API servers: in tests, in
// insecure dev mode, or when KMS_PUBLIC_URL itself is a loopback http URL.
func (s *Server) insecureIdentityURLs() bool {
	if s.identity().allowInsecureHTTP || s.cfg.InsecureDev {
		return true
	}
	return isLoopbackHTTP(s.publicURL())
}

func isLoopbackHTTP(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" {
		return false
	}
	h := u.Hostname()
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}
