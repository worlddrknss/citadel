package store

import (
	"context"
	"errors"
	"strings"
	"time"
)

// STSSessionResolver is implemented by stores that persist STS sessions.
type STSSessionResolver interface {
	GetSTSSessionSecret(ctx context.Context, keyID string) (accountID, secret, sessionToken string, expiresAt time.Time, err error)
}

var (
	ErrOIDCProviderNotFound = errors.New("oidc provider not found")
	ErrIAMRoleNotFound      = errors.New("iam role not found")
	ErrSTSSessionNotFound   = errors.New("sts session not found")
	ErrSTSSessionExpired    = errors.New("sts session expired")
)

// TrustPolicy is Citadel's deliberately small subset of an IAM role trust
// policy. It is persisted as JSON in iam_roles.trust_policy and is expressive
// enough for the two flows Citadel supports: web-identity federation (OIDC) and
// cross/same-account AssumeRole by principals.
type TrustPolicy struct {
	// Type is "oidc" or "account".
	Type string `json:"type"`
	// ProviderURL is the OIDC issuer URL (https://...) for type "oidc". It must
	// match a registered iam_oidc_providers row.
	ProviderURL string `json:"providerUrl,omitempty"`
	// Audiences lists acceptable JWT "aud" values for type "oidc".
	Audiences []string `json:"audiences,omitempty"`
	// Subjects lists acceptable JWT "sub" values for type "oidc". A trailing
	// "*" performs a prefix match (e.g. "system:serviceaccount:app:*").
	Subjects []string `json:"subjects,omitempty"`
	// Principals lists account IDs allowed to AssumeRole for type "account".
	Principals []string `json:"principals,omitempty"`
}

// OIDCProvider is a registered external token issuer.
type OIDCProvider struct {
	ProviderARN string
	AccountID   string
	URL         string
	ClientIDs   []string
	Thumbprints []string
	CreatedAt   time.Time
}

// IAMRole is a named identity with an attached trust policy.
type IAMRole struct {
	RoleARN        string
	AccountID      string
	RoleName       string
	Description    string
	Trust          TrustPolicy
	MaxSessionSecs int
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// STSSession is a minted set of temporary credentials.
type STSSession struct {
	AccessKeyID     string
	AccountID       string
	RoleARN         string
	RoleSessionName string
	Subject         string
	ExpiresAt       time.Time
	CreatedAt       time.Time
}

// IsTempAccessKeyID reports whether keyID is an STS temporary credential.
func IsTempAccessKeyID(keyID string) bool {
	return strings.HasPrefix(strings.TrimSpace(keyID), "ASIA")
}

// NormalizeIssuerURL strips a trailing slash so issuer comparisons are stable.
func NormalizeIssuerURL(u string) string {
	return strings.TrimRight(strings.TrimSpace(u), "/")
}

// subjectAllowed reports whether sub satisfies the policy's Subjects list.
func (p TrustPolicy) SubjectAllowed(sub string) bool {
	sub = strings.TrimSpace(sub)
	if sub == "" {
		return false
	}
	for _, want := range p.Subjects {
		want = strings.TrimSpace(want)
		if want == "*" {
			return true
		}
		if strings.HasSuffix(want, "*") {
			if strings.HasPrefix(sub, strings.TrimSuffix(want, "*")) {
				return true
			}
			continue
		}
		if want == sub {
			return true
		}
	}
	return false
}

// audienceAllowed reports whether any of the token audiences is accepted.
func (p TrustPolicy) AudienceAllowed(auds []string) bool {
	if len(p.Audiences) == 0 {
		return false
	}
	for _, got := range auds {
		got = strings.TrimSpace(got)
		for _, want := range p.Audiences {
			if strings.TrimSpace(want) == got {
				return true
			}
		}
	}
	return false
}

// principalAllowed reports whether accountID may AssumeRole under this policy.
func (p TrustPolicy) PrincipalAllowed(accountID string) bool {
	accountID = strings.TrimSpace(accountID)
	for _, want := range p.Principals {
		want = strings.TrimSpace(want)
		if want == "*" || want == accountID {
			return true
		}
	}
	return false
}
