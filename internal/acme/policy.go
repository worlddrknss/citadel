package acme

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
)

// Policy decides whether an account may obtain a certificate for an
// identifier. accountRef is the host account bound through external account
// binding ("" for an unbound ACME account). The identifier is normalized; a
// wildcard DNS identifier keeps its "*." prefix. Returning a *Problem sets
// the error the client sees; any other error becomes rejectedIdentifier.
type Policy interface {
	Allow(ctx context.Context, accountRef string, id Identifier) error
}

// PolicyFunc adapts a function to Policy.
type PolicyFunc func(ctx context.Context, accountRef string, id Identifier) error

// Allow calls f.
func (f PolicyFunc) Allow(ctx context.Context, accountRef string, id Identifier) error {
	return f(ctx, accountRef, id)
}

// SuffixPolicy allows DNS names under per-account suffixes and IP addresses
// inside per-account prefixes. Map keys are account references; the "" key
// applies to ACME accounts without an external account binding. An account
// with no entry may not request anything.
type SuffixPolicy struct {
	// Suffixes maps accountRef to DNS suffixes. A suffix "example.com"
	// allows example.com itself and any name below it, including
	// *.example.com.
	Suffixes map[string][]string
	// IPPrefixes maps accountRef to allowed IP ranges.
	IPPrefixes map[string][]netip.Prefix
}

// Allow implements Policy.
func (p SuffixPolicy) Allow(_ context.Context, accountRef string, id Identifier) error {
	switch id.Type {
	case IdentifierDNS:
		name := strings.TrimPrefix(id.Value, "*.")
		for _, s := range p.Suffixes[accountRef] {
			s = strings.ToLower(strings.Trim(s, "."))
			if s == "" {
				continue
			}
			if name == s || strings.HasSuffix(name, "."+s) {
				return nil
			}
		}
	case IdentifierIP:
		addr, err := netip.ParseAddr(id.Value)
		if err == nil {
			for _, pfx := range p.IPPrefixes[accountRef] {
				if pfx.Contains(addr) {
					return nil
				}
			}
		}
	}
	return rejected(id, "%s %q is not allowed for this account", id.Type, id.Value)
}

func rejected(id Identifier, format string, args ...any) *Problem {
	p := newProblem(ProbRejectedIdentifier, http.StatusBadRequest, format, args...)
	p.Identifier = &id
	return p
}

// normalizeIdentifier validates and canonicalizes a client identifier.
func normalizeIdentifier(id Identifier) (Identifier, *Problem) {
	switch id.Type {
	case IdentifierDNS:
		v := strings.ToLower(id.Value)
		out := Identifier{Type: IdentifierDNS, Value: v}
		base := strings.TrimPrefix(v, "*.")
		if err := checkDNSName(base); err != nil {
			return out, rejected(out, "invalid DNS name %q: %v", id.Value, err)
		}
		return out, nil
	case IdentifierIP:
		addr, err := netip.ParseAddr(id.Value)
		if err != nil || addr.Zone() != "" {
			return id, rejected(id, "invalid IP address %q", id.Value)
		}
		return Identifier{Type: IdentifierIP, Value: addr.Unmap().String()}, nil
	default:
		p := newProblem(ProbUnsupportedIdentifier, http.StatusBadRequest, "identifier type %q is not supported", id.Type)
		p.Identifier = &id
		return id, p
	}
}

// checkDNSName validates a non-wildcard ASCII (A-label) DNS name.
func checkDNSName(name string) error {
	if name == "" {
		return fmt.Errorf("empty name")
	}
	if len(name) > 253 {
		return fmt.Errorf("name longer than 253 octets")
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return fmt.Errorf("IP address given as a dns identifier")
	}
	labels := strings.Split(name, ".")
	for _, l := range labels {
		if l == "" {
			return fmt.Errorf("empty label")
		}
		if len(l) > 63 {
			return fmt.Errorf("label longer than 63 octets")
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("label starts or ends with a hyphen")
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return fmt.Errorf("invalid character %q (names must be lowercase LDH A-labels)", c)
			}
		}
	}
	tld := labels[len(labels)-1]
	if strings.Trim(tld, "0123456789") == "" {
		return fmt.Errorf("all-numeric top-level label")
	}
	return nil
}
