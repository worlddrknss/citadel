package store

import (
	"context"
	"errors"
	"time"
)

// Errors returned by IdentityStore.
var (
	ErrSSOProviderNotFound      = errors.New("sso provider not found")
	ErrSSOProviderExists        = errors.New("sso provider already exists")
	ErrExternalIdentityNotFound = errors.New("external identity not found")
	ErrExternalIdentityExists   = errors.New("external identity already exists")
	ErrWorkloadClientNotFound   = errors.New("workload client not found")
	ErrWorkloadClientExists     = errors.New("workload client already exists")
	// ErrWorkloadClientNameTaken is returned by CreateWorkloadClient and
	// UpdateWorkloadClient when another client in the same account already
	// has the name (compared without case).
	ErrWorkloadClientNameTaken = errors.New("workload client name already used in this account")
	// ErrWorkloadRotationConflict is returned by RotateWorkloadSigningKey
	// when the current key is no longer the one the caller expected
	// (another replica rotated first).
	ErrWorkloadRotationConflict = errors.New("workload signing key rotation conflict")
)

// ExternalIdentity links an identity at an SSO provider, keyed by the
// provider and its stable subject (never the email), to a console user.
type ExternalIdentity struct {
	ProviderID  string
	Subject     string
	Username    string
	Email       string
	CreatedAt   time.Time
	LastLoginAt time.Time
}

// WorkloadSigningKey is one of the workload identity issuer's signing keys,
// held in Citadel KMS. The current key has a zero RetiredAt; previous keys
// stay published in the JWKS until UnpublishAt.
type WorkloadSigningKey struct {
	KID         string
	KMSKeyID    string
	Algorithm   string // ES256|ES384|RS256|PS256
	ActivatedAt time.Time
	RetiredAt   time.Time
	UnpublishAt time.Time
}

// WorkloadIssuerSettings configure the workload identity issuer.
type WorkloadIssuerSettings struct {
	Algorithm    string
	RotationDays int
	UpdatedAt    time.Time
	UpdatedBy    string
}

// Workload client authentication methods.
const (
	WorkloadAuthAccessKey = "access-key"
	WorkloadAuthK8s       = "k8s-token-review"
)

// WorkloadClient is a registered workload identity client, owned by one
// account. ClientID is globally unique.
type WorkloadClient struct {
	ClientID        string
	AccountID       string
	Name            string
	Audiences       []string
	TokenTTLSeconds int
	SubjectFormat   string
	AuthMethod      string
	// access-key
	AllowedUsers []string
	// k8s-token-review
	APIServer       string
	CAPEM           string
	ServiceAccounts []string // "namespace:name"
	ReviewAudience  string

	CreatedAt    time.Time
	UpdatedAt    time.Time
	LastIssuedAt time.Time // zero when never used
}

// IdentityStore persists console SSO (providers, linked external identities,
// single-use sign-in states) and the workload identity issuer (signing keys,
// settings, clients).
type IdentityStore interface {
	// GetSSOProvider returns one provider (without its secret).
	GetSSOProvider(ctx context.Context, id string) (SSOProvider, error)
	// GetSSOProviderSecret returns the provider's sealed client secret
	// (nil when none is stored).
	GetSSOProviderSecret(ctx context.Context, id string) ([]byte, error)
	// CreateSSOProvider stores p with its sealed client secret.
	CreateSSOProvider(ctx context.Context, p SSOProvider, sealedSecret []byte) error
	// UpdateSSOProvider replaces p's settings (CreatedAt is kept); a nil
	// sealedSecret keeps the stored secret.
	UpdateSSOProvider(ctx context.Context, p SSOProvider, sealedSecret []byte) error
	// DeleteSSOProvider removes a provider and its linked identities.
	DeleteSSOProvider(ctx context.Context, id string) error

	GetExternalIdentity(ctx context.Context, providerID, subject string) (ExternalIdentity, error)
	CreateExternalIdentity(ctx context.Context, id ExternalIdentity) error
	TouchExternalIdentity(ctx context.Context, providerID, subject, email string, at time.Time) error

	// ConsumeOnce records id until expires and reports whether it was fresh
	// (false: already consumed and not yet expired). Atomic across replicas.
	ConsumeOnce(ctx context.Context, id string, expires time.Time) (bool, error)
	// PurgeConsumed removes consumed ids that expired before now.
	PurgeConsumed(ctx context.Context, now time.Time) (int64, error)

	// ListWorkloadSigningKeys returns every stored key, newest first.
	ListWorkloadSigningKeys(ctx context.Context) ([]WorkloadSigningKey, error)
	// RotateWorkloadSigningKey atomically retires the current key (setting
	// retiredAt and unpublishAt) and makes next current. expectCurrentKID is
	// the KID the caller saw as current ("" when there was none); if it no
	// longer is, nothing changes and ErrWorkloadRotationConflict is returned.
	RotateWorkloadSigningKey(ctx context.Context, next WorkloadSigningKey, expectCurrentKID string, retiredAt, unpublishAt time.Time) error
	// DeleteUnpublishedWorkloadSigningKeys removes retired keys whose
	// unpublishAt is before now and returns them.
	DeleteUnpublishedWorkloadSigningKeys(ctx context.Context, now time.Time) ([]WorkloadSigningKey, error)
	GetWorkloadIssuerSettings(ctx context.Context) (WorkloadIssuerSettings, error)
	PutWorkloadIssuerSettings(ctx context.Context, s WorkloadIssuerSettings) error

	CreateWorkloadClient(ctx context.Context, c WorkloadClient) error
	// GetWorkloadClient looks a client up by ID across accounts (the token
	// endpoint); handlers must check AccountID.
	GetWorkloadClient(ctx context.Context, clientID string) (WorkloadClient, error)
	ListWorkloadClients(ctx context.Context, accountID string) ([]WorkloadClient, error)
	// UpdateWorkloadClient replaces the client with c.ClientID in
	// c.AccountID (CreatedAt and LastIssuedAt are kept).
	UpdateWorkloadClient(ctx context.Context, c WorkloadClient) error
	DeleteWorkloadClient(ctx context.Context, accountID, clientID string) error
	TouchWorkloadClientIssued(ctx context.Context, clientID string, at time.Time) error
}
