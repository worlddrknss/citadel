package server

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// newGuardedHTTPClient returns an HTTP client for requests to destinations
// chosen by users (notification webhooks and the like). It applies the same
// rule as the ACME validator and rotation webhooks: the resolved address is
// checked at dial time, so neither DNS answers nor redirects can steer a
// request to loopback, link-local (cloud metadata), multicast, unspecified
// or the other ssrfBlocked ranges, unless an address is inside one of
// allowedCIDRs. Private (RFC 1918) ranges are allowed. Redirects are not
// followed, no proxy is used, and TLS is 1.2 or later.
func newGuardedHTTPClient(allowedCIDRs []netip.Prefix, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: timeout, ControlContext: guardedDialControl(allowedCIDRs)}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            dialer.DialContext,
			TLSHandshakeTimeout:    timeout,
			ResponseHeaderTimeout:  timeout,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConns:           4,
			IdleConnTimeout:        time.Minute,
			MaxResponseHeaderBytes: 16 << 10,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// guardedDialControl is ssrfDialControl with parsed prefixes.
func guardedDialControl(allowed []netip.Prefix) func(ctx context.Context, network, address string, c syscall.RawConn) error {
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
		if !ssrfBlocked(addr) {
			return nil
		}
		for _, p := range allowed {
			if p.Contains(addr) {
				return nil
			}
		}
		return errSSRFBlocked
	}
}
