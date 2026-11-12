package oidclogin

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Identity is the result of a successful sign-in.
type Identity struct {
	Provider      string
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Username      string
	Groups        []string
	RawClaims     map[string]any
	// ReturnTo is the validated same-origin path passed to Start. It is not
	// an identity attribute; it is carried here so the host can redirect.
	ReturnTo string
}

// Role is a Citadel console role.
type Role string

const (
	RoleAdmin  Role = "admin"
	RoleEditor Role = "editor"
	RoleViewer Role = "viewer"
)

func (r Role) rank() int {
	switch r {
	case RoleAdmin:
		return 3
	case RoleEditor:
		return 2
	case RoleViewer:
		return 1
	}
	return 0
}

// RoleRule grants Role on Account to members of Group (exact,
// case-sensitive match against Identity.Groups).
type RoleRule struct {
	Group   string `json:"group"`
	Account string `json:"account"`
	Role    Role   `json:"role"`
}

// Membership is a resolved (account, role) pair.
type Membership struct {
	Account string `json:"account"`
	Role    Role   `json:"role"`
}

// RoleMapping maps provider groups to Citadel memberships.
type RoleMapping struct {
	Rules []RoleRule
	// DefaultAccount/DefaultRole, when both set, grant every signed-in
	// identity at least DefaultRole on DefaultAccount.
	DefaultAccount string
	DefaultRole    Role
}

// ErrNoMembership is returned by Resolve when an identity maps to nothing;
// the host should refuse the sign-in.
var ErrNoMembership = errors.New("oidclogin: identity has no Citadel membership")

// Validate checks every rule.
func (m RoleMapping) Validate() error {
	for i, r := range m.Rules {
		if r.Group == "" || r.Account == "" || r.Role.rank() == 0 {
			return fmt.Errorf("oidclogin: role rule %d: group, account and a role of admin|editor|viewer are required", i)
		}
	}
	if (m.DefaultAccount == "") != (m.DefaultRole == "") {
		return errors.New("oidclogin: default account and default role must be set together")
	}
	if m.DefaultRole != "" && m.DefaultRole.rank() == 0 {
		return fmt.Errorf("oidclogin: invalid default role %q", m.DefaultRole)
	}
	return nil
}

// Resolve returns the memberships for groups: for each account, the highest
// role granted by any matching rule or the default. The result is sorted by
// account. It returns ErrNoMembership if nothing matched.
func (m RoleMapping) Resolve(groups []string) ([]Membership, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	have := make(map[string]bool, len(groups))
	for _, g := range groups {
		have[g] = true
	}
	best := map[string]Role{}
	grant := func(account string, role Role) {
		if role.rank() > best[account].rank() {
			best[account] = role
		}
	}
	for _, r := range m.Rules {
		if have[r.Group] {
			grant(r.Account, r.Role)
		}
	}
	if m.DefaultAccount != "" {
		grant(m.DefaultAccount, m.DefaultRole)
	}
	if len(best) == 0 {
		return nil, ErrNoMembership
	}
	out := make([]Membership, 0, len(best))
	for a, r := range best {
		out = append(out, Membership{Account: a, Role: r})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Account < out[j].Account })
	return out, nil
}

// EmailDomainAllowed reports whether email's domain is in domains (exact,
// case-insensitive). An empty list allows every address.
func EmailDomainAllowed(email string, domains []string) bool {
	if len(domains) == 0 {
		return true
	}
	at := strings.LastIndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return false
	}
	d := strings.ToLower(email[at+1:])
	for _, allowed := range domains {
		if d == strings.ToLower(allowed) {
			return true
		}
	}
	return false
}

// ValidateReturnTo accepts only same-origin relative paths such as
// "/secrets?x=1". Empty means "/". Scheme-relative ("//host"), backslash
// tricks, absolute URLs, control characters and encoded leading slashes are
// rejected to prevent open redirects.
func ValidateReturnTo(s string) (string, error) {
	if s == "" {
		return "/", nil
	}
	if len(s) > 2048 || s[0] != '/' {
		return "", ErrInvalidReturnTo
	}
	if len(s) > 1 && (s[1] == '/' || s[1] == '\\') {
		return "", ErrInvalidReturnTo
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= 0x20 || c == 0x7f || c == '\\' {
			return "", ErrInvalidReturnTo
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return "", ErrInvalidReturnTo
	}
	if strings.HasPrefix(u.Path, "//") || strings.Contains(u.Path, "\\") {
		return "", ErrInvalidReturnTo
	}
	return s, nil
}
