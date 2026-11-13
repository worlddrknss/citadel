// Package store defines Citadel's persistence contract: the domain records
// (KMS keys, secrets, parameters, certificates, identities, audit events...)
// and the interfaces a storage backend implements. The PostgreSQL backend
// lives in store/postgres and the in-memory one in store/memory.
//
// Tenancy: reads and writes are scoped to the caller account carried on the
// context (see WithCallerAccount and AccountFilter).
package store

import (
	"context"
	"errors"
	"time"
)

var (
	ErrUnsupported = errors.New("unsupported operation")
)

// Store is everything a storage backend provides. It is composed of one
// interface per domain so code that needs only part of it can say so.
type Store interface {
	KeyStore
	SecretStore
	AuditStore
	AuditQueryStore
	UserStore
	AccountStore
	AccessKeyStore
	FederationStore
	PKIStore
	PKIExtStore
	ACMEStore
	ParameterStore
	HierarchyStore
	AuthStore
	ParameterVersionStore
	ApprovalStore
	SecretSettingsStore
	SecretLifecycleStore
	AWSPageStore
	IdentityStore
	KMSLifecycleStore
	MFAStore
	SecretRotationStore
	WriteAheadStore
	PKIParityStore
}

// KeyStore persists KMS keys, aliases, key policies and grants.
type KeyStore interface {
	ResolveByID(ctx context.Context, keyID string) (KMSKey, error)
	ResolveDefault(ctx context.Context) (KMSKey, error)
	EnsureBootstrap(ctx context.Context, k KMSKey) error
	EnsureAccountDefaultKey(ctx context.Context, accountID string) (KMSKey, error)
	DeploymentIdentity() (region, accountID string)
	CreateKey(ctx context.Context, description, keyUsage, keySpec string) (KMSKey, error)
	ImportSigningKey(ctx context.Context, description string, privPKCS8DER, pubPKIXDER []byte, keySpec string) (KMSKey, error)
	ListKeys(ctx context.Context) ([]KMSKey, error)
	GetKeyPolicy(ctx context.Context, keyID, policyName string) (string, error)
	PutKeyPolicy(ctx context.Context, keyID, policyName, policyDocument string) error
	CreateAlias(ctx context.Context, aliasName, keyID string) error
	UpdateAlias(ctx context.Context, aliasName, keyID string) error
	DeleteAlias(ctx context.Context, aliasName string) error
	ListAliases(ctx context.Context) ([]KMSAlias, error)
	SetKeyEnabled(ctx context.Context, keyID string, enabled bool) error
	ScheduleKeyDeletion(ctx context.Context, keyID string, windowDays int) (time.Time, error)
	CancelKeyDeletion(ctx context.Context, keyID string) error
	ForceDeleteKey(ctx context.Context, keyID string) error
	CreateGrant(ctx context.Context, req CreateGrantRequest) (KMSGrant, error)
	ListGrants(ctx context.Context, keyID string) ([]KMSGrant, error)
	RevokeGrant(ctx context.Context, keyID, grantID string) error
	RetireGrant(ctx context.Context, grantID, grantToken string) error
}

// SecretStore persists Secrets Manager secrets, their versions and stages.
type SecretStore interface {
	CreateSecret(ctx context.Context, req CreateSecretRequest) (SecretMetadataRecord, SecretValueRecord, error)
	DescribeSecret(ctx context.Context, secretID string) (SecretMetadataRecord, error)
	SecretARNForCtx(ctx context.Context, name string) string
	GetSecretValue(ctx context.Context, secretID, versionID, versionStage string) (SecretValueRecord, error)
	PutSecretValue(ctx context.Context, req PutSecretValueRequest) (SecretValueRecord, error)
	UpdateSecret(ctx context.Context, req UpdateSecretRequest) (SecretMetadataRecord, *SecretValueRecord, error)
	DeleteSecret(ctx context.Context, secretID string, recoveryWindowDays int, forceDelete bool) (SecretMetadataRecord, error)
	RestoreSecret(ctx context.Context, secretID string) (SecretMetadataRecord, error)
	ListSecrets(ctx context.Context) ([]SecretMetadataRecord, error)
	ListSecretVersionIDs(ctx context.Context, secretID string) ([]SecretVersionListEntry, error)
	TagSecret(ctx context.Context, secretID string, tags []SecretTag) error
	UntagSecret(ctx context.Context, secretID string, tagKeys []string) error
	GetSecretResourcePolicy(ctx context.Context, secretID string) (string, error)
	// PutSecretResourcePolicy stores a policy; an empty document removes it.
	PutSecretResourcePolicy(ctx context.Context, secretID, policyDocument string) error
	RotateSecret(ctx context.Context, secretID, rotationLambdaARN string, automaticallyAfterDays int, rotateImmediately bool, clientRequestToken string) (SecretRotationResult, error)
	CancelRotateSecret(ctx context.Context, secretID string) (SecretMetadataRecord, error)
	UpdateSecretVersionStage(ctx context.Context, secretID, versionStage, moveToVersionID, removeFromVersionID string) (SecretMetadataRecord, error)
}

// AuditStore persists the hash-chained audit log.
type AuditStore interface {
	ListAuditEvents(ctx context.Context, limit int) ([]AuditRecord, error)
	RecordAudit(ctx context.Context, event AuditEvent) error
}

// UserStore persists console (UI) users.
type UserStore interface {
	ListUIUsers(ctx context.Context) ([]UIUser, error)
	UpsertUIUser(ctx context.Context, user UIUser) error
	DeleteUIUser(ctx context.Context, username string) error
}

// AccountStore persists accounts (tenants) and user membership in them.
type AccountStore interface {
	CreateUIAccount(ctx context.Context, name string) (string, error)
	GetUIAccount(ctx context.Context, accountID string) (UIAccountInfo, error)
	ListUIAccounts(ctx context.Context) ([]UIAccountInfo, error)
	UpsertUIAccount(ctx context.Context, account string) error
	DeleteUIAccount(ctx context.Context, accountID string) error
	AddUserAccount(ctx context.Context, username, accountID, role string) error
	RemoveUserAccount(ctx context.Context, username, accountID string) error
	ListUserAccounts(ctx context.Context, username string) ([]UserAccountInfo, error)
	ListAccountUsers(ctx context.Context, accountID string) ([]struct{ Username, Role string }, error)
}

// AccessKeyStore persists long-lived IAM-style access keys.
type AccessKeyStore interface {
	CreateAccessKey(ctx context.Context, username, accountID string) (AccessKeySecret, error)
	ListAccessKeys(ctx context.Context, username, accountID string) ([]AccessKeyInfo, error)
	GetAccessKeyByID(ctx context.Context, keyID string) (username, accountID, secret string, status string, err error)
	SetAccessKeyStatus(ctx context.Context, keyID, newStatus string) error
	DeleteAccessKey(ctx context.Context, keyID string) error
	TouchAccessKeyLastUsed(ctx context.Context, keyID string) error
}

// FederationStore persists STS / IAM identity federation state: OIDC
// providers, roles and temporary sessions.
type FederationStore interface {
	CreateOIDCProvider(ctx context.Context, p OIDCProvider) error
	ListOIDCProviders(ctx context.Context, accountID string) ([]OIDCProvider, error)
	GetOIDCProviderByURL(ctx context.Context, accountID, url string) (OIDCProvider, error)
	DeleteOIDCProvider(ctx context.Context, accountID, providerARN string) error
	CreateIAMRole(ctx context.Context, role IAMRole) error
	ListIAMRoles(ctx context.Context, accountID string) ([]IAMRole, error)
	GetIAMRole(ctx context.Context, accountID, roleName string) (IAMRole, error)
	GetIAMRoleByARN(ctx context.Context, roleARN string) (IAMRole, error)
	DeleteIAMRole(ctx context.Context, accountID, roleName string) error
	CreateSTSSession(ctx context.Context, sess STSSession, secret, sessionToken string) error
	DeleteExpiredSTSSessions(ctx context.Context) (int64, error)
}

// PKIStore persists private certificate authorities (acm-pca) and the
// certificates they issue.
type PKIStore interface {
	CreateCertificateAuthority(ctx context.Context, ca PCACertificateAuthority) error
	DescribeCertificateAuthority(ctx context.Context, arn string) (PCACertificateAuthority, error)
	ListCertificateAuthorities(ctx context.Context) ([]PCACertificateAuthority, error)
	CreateCertificate(ctx context.Context, cert PCACertificate) error
	GetCertificate(ctx context.Context, certID string) (PCACertificate, error)
	ListCertificates(ctx context.Context, caID string) ([]PCACertificate, error)
	RevokeCertificate(ctx context.Context, certID, reason string) error
}

// ACMEStore persists Let's Encrypt (ACME client) accounts, orders and
// certificates.
type ACMEStore interface {
	GetACMELEAccount(ctx context.Context, directoryURL string) (ACMELEAccount, error)
	UpsertACMELEAccount(ctx context.Context, account ACMELEAccount) error
	CreateACMELECertificate(ctx context.Context, cert ACMELECertificate) error
	GetACMELECertificate(ctx context.Context, certID string) (ACMELECertificate, error)
	ListACMELECertificates(ctx context.Context) ([]ACMELECertificate, error)
	CreateACMELEOrder(ctx context.Context, order ACMELEOrder) error
	GetACMELEOrder(ctx context.Context, orderID string) (ACMELEOrder, error)
	DeleteACMELEOrder(ctx context.Context, orderID string) error
	// UpdateACMELEOrder stores an order's status, progress, error, certificate
	// and order URL.
	UpdateACMELEOrder(ctx context.Context, order ACMELEOrder) error
	// TransitionACMELEOrder moves an order to status (with progress) only
	// if its status is one of from, and reports whether it did; it lets one
	// request, on any replica, start the background work for an order.
	TransitionACMELEOrder(ctx context.Context, orderID string, from []string, status, progress string) (bool, error)
}
