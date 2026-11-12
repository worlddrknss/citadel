package acme

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// Validator checks one challenge type. id is the identifier being
// authorized (for a wildcard, the base domain). A nil error means the
// challenge is satisfied; a *Problem is recorded on the challenge as is.
type Validator interface {
	Validate(ctx context.Context, id Identifier, token, keyAuthorization string) error
}

// ValidatorFunc adapts a function to Validator.
type ValidatorFunc func(ctx context.Context, id Identifier, token, keyAuthorization string) error

// Validate calls f.
func (f ValidatorFunc) Validate(ctx context.Context, id Identifier, token, keyAuthorization string) error {
	return f(ctx, id, token, keyAuthorization)
}

const (
	http01Timeout      = 10 * time.Second
	http01MaxRedirects = 10
	http01MaxBody      = 1024
)

// HTTP01Validator implements http-01 (RFC 8555 §8.3, RFC 8738 §3).
type HTTP01Validator struct {
	// Client performs the fetch. Nil means a default client with
	// certificate verification enabled. Whatever client is used, its
	// redirect policy is replaced by the RFC-conformant one below and its
	// timeout is capped at 10s.
	Client *http.Client
}

// DefaultHTTP01Client returns the client used when HTTP01Validator.Client
// is nil. It does not use proxies and verifies TLS certificates when a
// redirect leads to https.
func DefaultHTTP01Client() *http.Client {
	return &http.Client{
		Timeout: http01Timeout,
		Transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			TLSHandshakeTimeout:    5 * time.Second,
			ResponseHeaderTimeout:  http01Timeout,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
			DisableKeepAlives:      true,
			MaxResponseHeaderBytes: 16 << 10,
		},
	}
}

// http01CheckRedirect allows at most 10 redirects, only to http on port 80
// or https on port 443.
func http01CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > http01MaxRedirects {
		return fmt.Errorf("too many redirects")
	}
	port := req.URL.Port()
	switch req.URL.Scheme {
	case "http":
		if port != "" && port != "80" {
			return fmt.Errorf("redirect to disallowed port %s", port)
		}
	case "https":
		if port != "" && port != "443" {
			return fmt.Errorf("redirect to disallowed port %s", port)
		}
	default:
		return fmt.Errorf("redirect to disallowed scheme %q", req.URL.Scheme)
	}
	return nil
}

// Validate implements Validator.
func (v HTTP01Validator) Validate(ctx context.Context, id Identifier, token, keyAuth string) error {
	client := v.Client
	if client == nil {
		client = DefaultHTTP01Client()
	}
	c := *client
	c.CheckRedirect = http01CheckRedirect
	if c.Timeout == 0 || c.Timeout > http01Timeout {
		c.Timeout = http01Timeout
	}

	host := id.Value
	if id.Type == IdentifierIP {
		addr, err := netip.ParseAddr(id.Value)
		if err != nil {
			return malformed("invalid IP identifier")
		}
		if addr.Is6() {
			host = "[" + addr.String() + "]"
		}
	} else if strings.HasPrefix(host, "*.") {
		return unauthorized("http-01 cannot validate wildcard names")
	}
	url := "http://" + host + "/.well-known/acme-challenge/" + token
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return malformed("cannot build validation request")
	}
	req.Header.Set("User-Agent", "citadel-acme-validator")
	req.Header.Set("Accept", "*/*")
	resp, err := c.Do(req)
	if err != nil {
		return newProblem(ProbConnection, http.StatusBadRequest, "fetching %s: %v", url, cleanErr(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return unauthorized("fetching %s: HTTP status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, http01MaxBody+1))
	if err != nil {
		return newProblem(ProbConnection, http.StatusBadRequest, "reading %s: %v", url, cleanErr(err))
	}
	if len(body) > http01MaxBody {
		return unauthorized("response from %s exceeds %d bytes", url, http01MaxBody)
	}
	if strings.TrimSpace(string(body)) != keyAuth {
		return unauthorized("key authorization at %s does not match", url)
	}
	return nil
}

func cleanErr(err error) string {
	var uerr interface{ Unwrap() error }
	if errors.As(err, &uerr) && uerr.Unwrap() != nil {
		return uerr.Unwrap().Error()
	}
	return err.Error()
}

// TXTResolver looks up TXT records. *net.Resolver satisfies it; it follows
// CNAMEs.
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// DNS01Validator implements dns-01 (RFC 8555 §8.4).
type DNS01Validator struct {
	// Resolver performs the lookup; nil means net.DefaultResolver.
	Resolver TXTResolver
}

// DNS01Digest returns the TXT record value for a key authorization.
func DNS01Digest(keyAuth string) string {
	sum := sha256.Sum256([]byte(keyAuth))
	return b64enc(sum[:])
}

// Validate implements Validator.
func (v DNS01Validator) Validate(ctx context.Context, id Identifier, _ string, keyAuth string) error {
	if id.Type != IdentifierDNS {
		return unauthorized("dns-01 can only validate DNS names")
	}
	r := v.Resolver
	if r == nil {
		r = net.DefaultResolver
	}
	name := "_acme-challenge." + strings.TrimPrefix(id.Value, "*.")
	records, err := r.LookupTXT(ctx, name)
	if err != nil {
		return newProblem(ProbDNS, http.StatusBadRequest, "TXT lookup of %s failed: %v", name, err)
	}
	want := DNS01Digest(keyAuth)
	for _, rec := range records {
		if strings.TrimSpace(rec) == want {
			return nil
		}
	}
	return unauthorized("no TXT record at %s matches the key authorization", name)
}
