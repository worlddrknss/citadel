package store

import (
	"context"
	"errors"
	"time"
)

// PKI errors. Backends return these (possibly wrapped) so callers can map
// them to stable client-facing messages.
var (
	ErrCANotFound                 = errors.New("certificate authority not found")
	ErrCertificateNotFound        = errors.New("certificate not found")
	ErrCertificateAlreadyRevoked  = errors.New("certificate already revoked")
	ErrEABKeyNotFound             = errors.New("eab key not found")
	ErrEABKeyUnavailable          = errors.New("eab key is not available for binding")
	ErrACMCertificateNotFound     = errors.New("acm certificate not found")
	ErrACMCertificateExists       = errors.New("acm certificate already exists")
	ErrACMEServerSettingsNotFound = errors.New("acme server settings not found")
)

// EAB key states.
const (
	EABStatusUnused  = "unused"
	EABStatusBound   = "bound"
	EABStatusRevoked = "revoked"
)

// EABKey is an ACME external account binding key. It ties the ACME account
// created with it to the Citadel account (tenant) that issued it. A key binds
// exactly one ACME account.
type EABKey struct {
	KID       string
	AccountID string
	Label     string
	// HMACKey is the plaintext MAC key. Backends encrypt it at rest; it is
	// only ever returned to the console once, at creation.
	HMACKey       []byte
	Status        string
	CreatedAt     time.Time
	CreatedBy     string
	BoundAt       *time.Time
	ACMEAccountID string
}

// ACMEServerSettings is an account's configuration of Citadel's own ACME
// server: which private CA signs its certificates and which identifiers and
// validation targets its ACME clients may use.
type ACMEServerSettings struct {
	AccountID string
	// IssuingCAID selects the CA; "" means the account's first active CA.
	IssuingCAID string
	// AllowedDomains are DNS suffixes ACME clients may request names under.
	AllowedDomains []string
	// AllowedIPRanges are CIDRs ACME clients may request IP identifiers in.
	AllowedIPRanges []string
	// ValidationAllowedCIDRs exempt addresses from the http-01 SSRF guard
	// (loopback, link-local and cloud metadata are blocked by default).
	ValidationAllowedCIDRs []string
	UpdatedAt              time.Time
	UpdatedBy              string
}

// ACM certificate types.
const (
	ACMTypePrivate  = "PRIVATE"
	ACMTypeImported = "IMPORTED"
)

// ACMCertificate is a certificate managed through the ACM API: either a
// private certificate issued by a Citadel CA with a Citadel-generated key, or
// an imported certificate. The private key is kept encrypted at rest so ACM
// ExportCertificate can return it.
type ACMCertificate struct {
	ARN        string
	AccountID  string
	Type       string
	CAID       string
	PCACertID  string
	DomainName string
	SANs       []string
	Serial     string
	CertB64    string // base64 DER of the leaf
	ChainPEM   string // issuer chain, PEM, leaf excluded
	// KeyDER is the plaintext PKCS#8 private key, populated in memory only.
	KeyDER    []byte
	Status    string
	NotBefore time.Time
	NotAfter  time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

// PKIExtStore extends PKIStore with lookups by ID and serial, certificate
// expiry, the ACME server's per-account settings and EAB keys, and ACM
// certificates. Reads and writes are scoped to the caller account on the
// context when one is present.
type PKIExtStore interface {
	GetCertificateAuthorityByID(ctx context.Context, caID string) (PCACertificateAuthority, error)
	FindCertificatesBySerial(ctx context.Context, serial string) ([]PCACertificate, error)
	// MarkExpiredCertificates moves issued certificates (private CA, ACM and
	// Let's Encrypt) and active CAs whose notAfter is before now to EXPIRED,
	// returning how many rows changed.
	MarkExpiredCertificates(ctx context.Context, now time.Time) (int64, error)

	// GetACMEServerSettings returns ErrACMEServerSettingsNotFound when the
	// account has saved none.
	GetACMEServerSettings(ctx context.Context) (ACMEServerSettings, error)
	PutACMEServerSettings(ctx context.Context, s ACMEServerSettings) error

	CreateEABKey(ctx context.Context, k EABKey) error
	// ListEABKeys returns the account's keys without their HMAC keys.
	ListEABKeys(ctx context.Context) ([]EABKey, error)
	// GetEABKey returns a key including its HMAC key.
	GetEABKey(ctx context.Context, kid string) (EABKey, error)
	RevokeEABKey(ctx context.Context, kid string) (EABKey, error)
	// BindEABKey atomically moves an unused key to bound; it returns
	// ErrEABKeyUnavailable when the key is bound or revoked.
	BindEABKey(ctx context.Context, kid, acmeAccountID string, at time.Time) error

	CreateACMCertificate(ctx context.Context, c ACMCertificate) error
	GetACMCertificate(ctx context.Context, arn string) (ACMCertificate, error)
	// ListACMCertificates returns certificates without key material.
	ListACMCertificates(ctx context.Context) ([]ACMCertificate, error)
	UpdateACMCertificate(ctx context.Context, c ACMCertificate) error
	DeleteACMCertificate(ctx context.Context, arn string) error
}
