// Package acme implements an RFC 8555 ACME certificate-issuance server.
//
// The server is an http.Handler meant to be mounted by a host application
// under a prefix (for example /acme). It verifies every request's JWS, keeps
// replay nonces in a shared Store, validates http-01 and dns-01 challenges
// for real, and hands finalized CSRs to an Issuer. It uses only FIPS 140-3
// approved primitives so it runs under GODEBUG=fips140=only.
package acme

import (
	"errors"
	"time"
)

// Identifier types (RFC 8555 §9.7.7, RFC 8738).
const (
	IdentifierDNS = "dns"
	IdentifierIP  = "ip"
)

// Challenge types supported by this server.
const (
	ChallengeHTTP01 = "http-01"
	ChallengeDNS01  = "dns-01"
)

// Object statuses (RFC 8555 §7.1.6).
const (
	StatusPending     = "pending"
	StatusReady       = "ready"
	StatusProcessing  = "processing"
	StatusValid       = "valid"
	StatusInvalid     = "invalid"
	StatusDeactivated = "deactivated"
	StatusExpired     = "expired"
	StatusRevoked     = "revoked"
)

// Identifier is an ACME identifier. Values are stored normalized: DNS names
// lowercase (a wildcard keeps its "*." prefix in an order's identifier list),
// IP addresses in canonical textual form.
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Store errors. Implementations must return these (possibly wrapped).
var (
	// ErrNotFound means the requested object does not exist.
	ErrNotFound = errors.New("acme: not found")
	// ErrStale means an Update's Version did not match the stored version
	// (another writer got there first). Callers reload and retry.
	ErrStale = errors.New("acme: stale object version")
	// ErrDuplicate means a uniqueness constraint was violated (for example
	// two accounts with the same key thumbprint).
	ErrDuplicate = errors.New("acme: duplicate")
)

// ErrAlreadyRevoked may be returned by Issuer.Revoke.
var ErrAlreadyRevoked = errors.New("acme: certificate already revoked")

// Account is an ACME account (RFC 8555 §7.1.2).
type Account struct {
	ID     string
	Status string // valid, deactivated, revoked
	// Contact holds mailto: URLs.
	Contact              []string
	TermsOfServiceAgreed bool
	// KeyJWK is the canonical RFC 7638 JSON form of the account public key.
	KeyJWK []byte
	// KeyThumbprint is base64url(SHA-256(KeyJWK)); unique across accounts.
	KeyThumbprint string
	// AccountRef is the host-side account (tenant) this ACME account is
	// bound to via external account binding; "" when unbound.
	AccountRef string
	// EABKeyID is the EAB key identifier used to create the account.
	EABKeyID  string
	CreatedAt time.Time
	// Version is used for optimistic concurrency; the Store owns it.
	Version int64
}

// Order is an ACME order (RFC 8555 §7.1.3).
type Order struct {
	ID          string
	AccountID   string
	Status      string
	Identifiers []Identifier
	AuthzIDs    []string
	Expires     time.Time
	NotAfter    time.Time // zero when the client did not request one
	CreatedAt   time.Time
	// CertificateID is set once the order is valid.
	CertificateID string
	Error         *Problem
	Version       int64
}

// Authorization is an ACME authorization (RFC 8555 §7.1.4). Its challenges
// are stored inline.
type Authorization struct {
	ID        string
	AccountID string
	// Identifier is the identifier being authorized; for a wildcard order
	// identifier it is the base domain and Wildcard is true.
	Identifier Identifier
	Wildcard   bool
	Status     string
	Expires    time.Time
	Challenges []Challenge
	Version    int64
}

// Challenge is an ACME challenge (RFC 8555 §7.1.5, §8).
type Challenge struct {
	ID        string
	Type      string
	Token     string
	Status    string
	Validated time.Time
	Error     *Problem
}

// Certificate is a certificate issued for an order.
type Certificate struct {
	ID        string
	AccountID string
	OrderID   string
	// Serial is the leaf serial number in lowercase hex without leading
	// zeros; unique across certificates.
	Serial   string
	ChainPEM []byte
	LeafDER  []byte
	NotAfter time.Time
	Revoked  bool
	// RevocationReason is the RFC 5280 CRLReason when Revoked.
	RevocationReason int
	Version          int64
}
