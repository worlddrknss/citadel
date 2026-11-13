package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// Outbound connections to addresses that users or agents choose.
//
// Every feature that connects to a user-supplied destination (ACME http-01
// validation, rotation webhooks and databases, SIEM streaming, notification
// webhooks, the agent HTTP broker) checks the *resolved* address at dial
// time, so neither a DNS answer nor a redirect can steer the connection to
// the host itself or to a cloud metadata service. outboundPolicy is that one
// check; the features differ only in which ranges they let through.

// ssrfBlockedPrefixes are cloud metadata services and other host-local
// endpoints that no outbound feature may reach unless explicitly allowed.
var ssrfBlockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("169.254.169.254/32"), // AWS, GCP, Azure, OpenStack metadata (also covered by link-local)
	netip.MustParsePrefix("100.100.100.200/32"), // Alibaba Cloud metadata
	netip.MustParsePrefix("192.0.0.192/32"),     // Oracle Cloud metadata
	netip.MustParsePrefix("168.63.129.16/32"),   // Azure wire server
	netip.MustParsePrefix("fd00:ec2::254/128"),  // AWS IPv6 metadata
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("255.255.255.255/32"),
}

// privateExtraPrefixes are non-public ranges that netip.Addr.IsPrivate does
// not cover.
var privateExtraPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT (RFC 6598)
	netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking (RFC 2544)
	netip.MustParsePrefix("::/96"),         // IPv4-compatible IPv6 (deprecated)
}

// Prefixes whose IPv6 addresses embed an IPv4 address that is what the
// packet really reaches.
var (
	nat64Prefix      = netip.MustParsePrefix("64:ff9b::/96")
	nat64LocalPrefix = netip.MustParsePrefix("64:ff9b:1::/48")
	sixToFourPrefix  = netip.MustParsePrefix("2002::/16")
)

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

// privateAddr reports whether addr is in a private or otherwise non-public
// range (RFC 1918, unique local, CGNAT and friends).
func privateAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.IsPrivate() {
		return true
	}
	for _, p := range privateExtraPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// embeddedIPv4 returns the IPv4 address carried in a NAT64 or 6to4 address.
func embeddedIPv4(addr netip.Addr) (netip.Addr, bool) {
	if !addr.Is6() || addr.Is4In6() {
		return netip.Addr{}, false
	}
	b := addr.As16()
	switch {
	case nat64Prefix.Contains(addr), nat64LocalPrefix.Contains(addr):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case sixToFourPrefix.Contains(addr):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	}
	return netip.Addr{}, false
}

// outboundPolicy decides which resolved addresses an outbound connection
// may reach. The zero value blocks loopback, link-local, multicast,
// unspecified and metadata addresses and allows everything else, including
// private ranges.
type outboundPolicy struct {
	// blockPrivate also blocks private and other non-public ranges.
	blockPrivate bool
	// allowLoopback lets loopback addresses through (tests, local
	// development).
	allowLoopback bool
	// allowed are ranges let through regardless of the rules above.
	allowed []netip.Prefix
}

// permits reports whether a connection to addr is allowed.
func (p outboundPolicy) permits(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, a := range p.allowed {
		if a.Contains(addr) {
			return true
		}
	}
	if p.allowLoopback && addr.IsLoopback() {
		return true
	}
	if ssrfBlocked(addr) || (p.blockPrivate && privateAddr(addr)) {
		return false
	}
	if v4, ok := embeddedIPv4(addr); ok {
		return p.permits(v4)
	}
	return true
}

// control is a net.Dialer ControlContext that refuses connections the policy
// does not permit with blocked.
func (p outboundPolicy) control(blocked error) func(ctx context.Context, network, address string, c syscall.RawConn) error {
	return func(_ context.Context, _ string, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return blocked
		}
		addr, err := netip.ParseAddr(host)
		if err != nil || !p.permits(addr) {
			return blocked
		}
		return nil
	}
}

// errOutboundBlocked is returned (wrapped in the client's *url.Error) when
// the destination address is not allowed.
var errOutboundBlocked = errors.New("the destination address is not allowed (loopback, link-local, private or metadata)")

// outboundConnectTimeout bounds the TCP connect of guarded clients.
const outboundConnectTimeout = 5 * time.Second

// guardedClient builds an HTTP client whose connections the policy checks.
// It never uses a proxy from the environment (the check would then apply to
// the proxy), never follows redirects (callers that want to follow one
// re-validate the target and send it themselves), and gives up after
// timeout overall (connect: at most 5s).
func guardedClient(policy outboundPolicy, blocked error, timeout time.Duration) *http.Client {
	connect := outboundConnectTimeout
	if timeout > 0 && timeout < connect {
		connect = timeout
	}
	dialer := &net.Dialer{Timeout: connect, ControlContext: policy.control(blocked)}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            dialer.DialContext,
			ForceAttemptHTTP2:      true,
			TLSHandshakeTimeout:    connect,
			ResponseHeaderTimeout:  timeout,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
			MaxResponseHeaderBytes: 64 << 10,
			MaxIdleConns:           4,
			IdleConnTimeout:        30 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// newGuardedHTTPClient returns an HTTP client for requests to destinations
// chosen by users (notification webhooks and the like): loopback,
// link-local (cloud metadata), multicast, unspecified and the other
// ssrfBlocked ranges are refused unless inside allowedCIDRs; private (RFC
// 1918) ranges are allowed. A refused dial fails with errSSRFBlocked.
func newGuardedHTTPClient(allowedCIDRs []netip.Prefix, timeout time.Duration) *http.Client {
	return guardedClient(outboundPolicy{allowed: append([]netip.Prefix(nil), allowedCIDRs...)}, errSSRFBlocked, timeout)
}

// newAgentBrokerHTTPClient is the agent broker's client: stricter than
// newGuardedHTTPClient, it also refuses private and other non-public ranges
// unless the credential's allowedCIDRs include them. A refused dial fails
// with errOutboundBlocked.
func newAgentBrokerHTTPClient(allowedCIDRs []netip.Prefix, timeout time.Duration) *http.Client {
	return guardedClient(outboundPolicy{blockPrivate: true, allowed: append([]netip.Prefix(nil), allowedCIDRs...)}, errOutboundBlocked, timeout)
}

// isOutboundBlocked reports whether err came from the dial-time guard.
func isOutboundBlocked(err error) bool {
	return errors.Is(err, errOutboundBlocked)
}
