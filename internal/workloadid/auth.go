package workloadid

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// Workload is an authenticated caller of the token endpoint.
type Workload struct {
	AccountRef string
	ClientID   string
	// Subject identifies the workload as the authenticator sees it (e.g.
	// "system:serviceaccount:ns:sa" or an access key ID). It is recorded in
	// the custom claims; the token's sub comes from the client's template.
	Subject string
	// Attributes feed the subject template and the custom claims, e.g.
	// namespace, service_account, pod, repository, ref.
	Attributes map[string]string
}

// AuthRequest is what an Authenticator sees.
type AuthRequest struct {
	// Client is the registered client the caller asked to act as.
	Client Client
	// Credential is the bearer credential presented, if any: the
	// "credential" field of the request or the Authorization: Bearer value.
	Credential string
	// HTTP is the original request (headers and remote address; the body has
	// already been consumed). Nil when Issue is called directly.
	HTTP *http.Request
}

// Authenticator authenticates a token request for a client. It must return
// ErrUnauthenticated (possibly wrapped) when the caller cannot prove the
// identity, and ErrForbidden when the caller is known but not allowed to use
// the client. The issuer re-checks that the returned Workload's AccountRef
// and ClientID equal the client's.
type Authenticator interface {
	Authenticate(ctx context.Context, req *AuthRequest) (Workload, error)
}

var (
	ErrUnauthenticated = errors.New("workloadid: workload not authenticated")
	ErrForbidden       = errors.New("workloadid: workload not allowed to use this client")
)

// AuthenticatorFunc is the pluggable callback Authenticator. The host
// implements access_key authentication with it, for example by verifying a
// SigV4 signature on req.HTTP and checking that the access key belongs to
// req.Client.AccountRef and may use the client.
type AuthenticatorFunc func(ctx context.Context, req *AuthRequest) (Workload, error)

// Authenticate implements Authenticator.
func (f AuthenticatorFunc) Authenticate(ctx context.Context, req *AuthRequest) (Workload, error) {
	return f(ctx, req)
}

// MethodRouter dispatches to an Authenticator by the client's AuthMethod.
type MethodRouter map[AuthMethod]Authenticator

// Authenticate implements Authenticator.
func (m MethodRouter) Authenticate(ctx context.Context, req *AuthRequest) (Workload, error) {
	a, ok := m[req.Client.AuthMethod]
	if !ok {
		return Workload{}, fmt.Errorf("%w: no authenticator for method %q", ErrUnauthenticated, req.Client.AuthMethod)
	}
	return a.Authenticate(ctx, req)
}
