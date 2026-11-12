package server

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/worlddrknss/citadel/internal/arn"
	"github.com/worlddrknss/citadel/internal/config"
	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/postgres"
)

const (

	// AppName is the user-facing product name used in logs and UI.
	AppName = "Citadel"
)

var (
	errAccessDenied = errors.New("access denied")
)

type Server struct {
	cfg            config.Config
	store          store.Store
	ui             *uiRuntime
	acmeChallenges *acmeChallengeStore
	// acmeHTTPClient, when set, is used by the Let's Encrypt ACME client. It
	// allows trusting a private or test ACME CA (e.g. Pebble). When nil the
	// default HTTP client (public trust store) is used.
	acmeHTTPClient *http.Client
	// webFS is the built web console served under /app/; nil when absent.
	webFS fs.FS

	secretsOnce sync.Once
	secretsSvcV *secretsService
}

// secretsSvc returns the shared protocol-free secrets service, lazily binding
// it to the server's store on first use.
func (s *Server) secretsSvc() *secretsService {
	s.secretsOnce.Do(func() {
		s.secretsSvcV = newSecretsService(s.store)
	})
	return s.secretsSvcV
}

type awsError struct {
	Type    string `json:"__type"`
	Message string `json:"message"`
}

type encryptRequest struct {
	KeyID             string            `json:"KeyId"`
	Plaintext         string            `json:"Plaintext"`
	EncryptionContext map[string]string `json:"EncryptionContext"`
}

type encryptResponse struct {
	CiphertextBlob    string            `json:"CiphertextBlob"`
	KeyID             string            `json:"KeyId"`
	EncryptionContext map[string]string `json:"EncryptionContext,omitempty"`
}

type decryptRequest struct {
	CiphertextBlob    string            `json:"CiphertextBlob"`
	EncryptionContext map[string]string `json:"EncryptionContext"`
}

type decryptResponse struct {
	KeyID             string            `json:"KeyId"`
	Plaintext         string            `json:"Plaintext"`
	EncryptionContext map[string]string `json:"EncryptionContext,omitempty"`
}

type describeKeyRequest struct {
	KeyID string `json:"KeyId"`
}

type describeKeyResponse struct {
	KeyMetadata keyMetadata `json:"KeyMetadata"`
}

type createKeyRequest struct {
	Description string `json:"Description"`
	KeyUsage    string `json:"KeyUsage"`
	KeySpec     string `json:"KeySpec"`
}

type createKeyResponse struct {
	KeyMetadata keyMetadata `json:"KeyMetadata"`
}

type signRequest struct {
	KeyID            string `json:"KeyId"`
	Message          string `json:"Message"`
	MessageType      string `json:"MessageType"`
	SigningAlgorithm string `json:"SigningAlgorithm"`
}

type signResponse struct {
	KeyID            string `json:"KeyId"`
	Signature        string `json:"Signature"`
	SigningAlgorithm string `json:"SigningAlgorithm,omitempty"`
}

type verifyRequest struct {
	KeyID            string `json:"KeyId"`
	Message          string `json:"Message"`
	MessageType      string `json:"MessageType"`
	Signature        string `json:"Signature"`
	SigningAlgorithm string `json:"SigningAlgorithm"`
}

type verifyResponse struct {
	KeyID            string `json:"KeyId"`
	SignatureValid   bool   `json:"SignatureValid"`
	SigningAlgorithm string `json:"SigningAlgorithm,omitempty"`
}

type getPublicKeyRequest struct {
	KeyID string `json:"KeyId"`
}

type getPublicKeyResponse struct {
	KeyID             string   `json:"KeyId"`
	PublicKey         string   `json:"PublicKey"`
	SigningAlgorithms []string `json:"SigningAlgorithms,omitempty"`
	KeySpec           string   `json:"KeySpec,omitempty"`
}

type certificateAuthorityConfig struct {
	KeyAlgorithm     string        `json:"KeyAlgorithm"`
	SigningAlgorithm string        `json:"SigningAlgorithm"`
	Subject          subjectConfig `json:"Subject"`
}

type subjectConfig struct {
	Country          string `json:"Country,omitempty"`
	State            string `json:"State,omitempty"`
	Locality         string `json:"Locality,omitempty"`
	Organization     string `json:"Organization,omitempty"`
	OrganizationUnit string `json:"OrganizationalUnit,omitempty"`
	CommonName       string `json:"CommonName,omitempty"`
}

type createCertificateAuthorityRequest struct {
	CertificateAuthorityConfiguration certificateAuthorityConfig `json:"CertificateAuthorityConfiguration"`
	CAType                            string                     `json:"Type"`
}

type createCertificateAuthorityResponse struct {
	CertificateAuthorityARN string `json:"CertificateAuthorityArn"`
}

type describeCertificateAuthorityRequest struct {
	CertificateAuthorityARN string `json:"CertificateAuthorityArn"`
}

type certificateAuthorityRecord struct {
	ARN         string `json:"Arn"`
	Type        string `json:"Type"`
	Status      string `json:"Status"`
	Certificate string `json:"Certificate,omitempty"`
	CreatedAt   string `json:"CreatedAt,omitempty"`
}

type describeCertificateAuthorityResponse struct {
	CertificateAuthority certificateAuthorityRecord `json:"CertificateAuthority"`
}

type issueCertificateRequest struct {
	CertificateAuthorityARN string       `json:"CertificateAuthorityArn"`
	CSR                     string       `json:"Csr"`
	SigningAlgorithm        string       `json:"SigningAlgorithm"`
	Validity                validitySpec `json:"Validity"`
}

type validitySpec struct {
	Value int64  `json:"Value"`
	Type  string `json:"Type"`
}

type issueCertificateResponse struct {
	CertificateARN string `json:"CertificateArn"`
}

type getCertificateRequest struct {
	CertificateAuthorityARN string `json:"CertificateAuthorityArn"`
	CertificateARN          string `json:"CertificateArn"`
}

type getCertificateResponse struct {
	Certificate string `json:"Certificate"`
}

type revokeCertificateRequest struct {
	CertificateAuthorityARN string `json:"CertificateAuthorityArn"`
	CertificateARN          string `json:"CertificateArn"`
	RevocationReason        string `json:"RevocationReason"`
}

// ACM (Certificate Manager) types - facade over acm-pca
type requestCertificateRequest struct {
	DomainName       string   `json:"DomainName"`
	ValidationMethod string   `json:"ValidationMethod"`
	SubjectAltNames  []string `json:"SubjectAlternativeNames,omitempty"`
	Idempotency      string   `json:"IdempotencyToken,omitempty"`
}

type requestCertificateResponse struct {
	CertificateARN string `json:"CertificateArn"`
}

type describeCertificateRequest struct {
	CertificateARN string `json:"CertificateArn"`
}

type describeCertificateResponse struct {
	Certificate certificateDetail `json:"Certificate"`
}

type certificateDetail struct {
	ARN                     string   `json:"CertificateArn"`
	DomainName              string   `json:"DomainName"`
	SubjectAlternativeNames []string `json:"SubjectAlternativeNames,omitempty"`
	Status                  string   `json:"Status"`
	Serial                  string   `json:"Serial,omitempty"`
	NotBefore               string   `json:"NotBefore,omitempty"`
	NotAfter                string   `json:"NotAfter,omitempty"`
	CreatedAt               string   `json:"CreatedAt,omitempty"`
}

type listCertificatesRequest struct {
	Limit  int    `json:"MaxItems,omitempty"`
	Marker string `json:"Marker,omitempty"`
}

type listCertificatesResponse struct {
	CertificateSummaryList []certificateSummary `json:"CertificateSummaryList"`
	NextMarker             string               `json:"NextMarker,omitempty"`
}

type certificateSummary struct {
	ARN        string `json:"CertificateArn"`
	DomainName string `json:"DomainName"`
	Status     string `json:"Status"`
	CreatedAt  string `json:"CreatedAt,omitempty"`
}

type deleteCertificateRequest struct {
	CertificateARN string `json:"CertificateArn"`
}

type acmGetCertificateRequest struct {
	CertificateARN string `json:"CertificateArn"`
}

type acmGetCertificateResponse struct {
	Certificate string `json:"Certificate"`
	CertChain   string `json:"CertificateChain,omitempty"`
	PrivateKey  string `json:"PrivateKey,omitempty"`
}

type listKeysResponse struct {
	Keys       []listKeyEntry `json:"Keys"`
	NextMarker string         `json:"NextMarker,omitempty"`
	Truncated  bool           `json:"Truncated"`
}

type listKeysRequest struct {
	Limit  int    `json:"Limit"`
	Marker string `json:"Marker"`
}

type listKeyEntry struct {
	KeyID  string `json:"KeyId"`
	KeyARN string `json:"KeyArn"`
}

type createAliasRequest struct {
	AliasName   string `json:"AliasName"`
	TargetKeyID string `json:"TargetKeyId"`
}

type updateAliasRequest struct {
	AliasName   string `json:"AliasName"`
	TargetKeyID string `json:"TargetKeyId"`
}

type listAliasesResponse struct {
	Aliases    []aliasEntry `json:"Aliases"`
	NextMarker string       `json:"NextMarker,omitempty"`
	Truncated  bool         `json:"Truncated"`
}

type listAliasesRequest struct {
	Limit  int    `json:"Limit"`
	Marker string `json:"Marker"`
}

type aliasEntry struct {
	AliasName   string `json:"AliasName"`
	TargetKeyID string `json:"TargetKeyId"`
}

type keyIDRequest struct {
	KeyID string `json:"KeyId"`
}

type scheduleKeyDeletionRequest struct {
	KeyID               string `json:"KeyId"`
	PendingWindowInDays int    `json:"PendingWindowInDays"`
}

type scheduleKeyDeletionResponse struct {
	KeyID        string    `json:"KeyId"`
	DeletionDate time.Time `json:"DeletionDate"`
}

type createGrantResponse struct {
	GrantID    string `json:"GrantId"`
	GrantToken string `json:"GrantToken"`
}

type listGrantsRequest struct {
	KeyID string `json:"KeyId"`
}

type listGrantsResponse struct {
	Grants []grantListEntry `json:"Grants"`
}

type grantListEntry struct {
	GrantID           string    `json:"GrantId"`
	KeyID             string    `json:"KeyId"`
	GranteePrincipal  string    `json:"GranteePrincipal"`
	RetiringPrincipal string    `json:"RetiringPrincipal,omitempty"`
	Operations        []string  `json:"Operations"`
	Name              string    `json:"Name,omitempty"`
	CreationDate      time.Time `json:"CreationDate"`
}

type revokeGrantRequest struct {
	KeyID   string `json:"KeyId"`
	GrantID string `json:"GrantId"`
}

type retireGrantRequest struct {
	GrantID    string `json:"GrantId"`
	GrantToken string `json:"GrantToken"`
}

type getKeyPolicyRequest struct {
	KeyID      string `json:"KeyId"`
	PolicyName string `json:"PolicyName"`
}

type getKeyPolicyResponse struct {
	Policy string `json:"Policy"`
}

type putKeyPolicyRequest struct {
	KeyID      string `json:"KeyId"`
	PolicyName string `json:"PolicyName"`
	Policy     string `json:"Policy"`
}

type keyMetadata struct {
	AWSAccountID                string    `json:"AWSAccountId"`
	KeyID                       string    `json:"KeyId"`
	Arn                         string    `json:"Arn"`
	CreationDate                time.Time `json:"CreationDate"`
	Enabled                     bool      `json:"Enabled"`
	Description                 string    `json:"Description"`
	KeyUsage                    string    `json:"KeyUsage"`
	KeyState                    string    `json:"KeyState"`
	Origin                      string    `json:"Origin"`
	KeyManager                  string    `json:"KeyManager"`
	CustomerMasterKeySpec       string    `json:"CustomerMasterKeySpec"`
	KeySpec                     string    `json:"KeySpec"`
	EncryptionAlgorithms        []string  `json:"EncryptionAlgorithms"`
	MultiRegion                 bool      `json:"MultiRegion"`
	SigningAlgorithms           []string  `json:"SigningAlgorithms"`
	PendingDeletionWindowInDays int       `json:"PendingDeletionWindowInDays,omitempty"`
}

// New readies st for serving (legacy key bootstrap, per-account default
// keys, console users merged from the database), refuses configurations that
// would leave Citadel open, and returns the server. webFS holds the built web
// console; nil serves a "console not built" page.
func New(ctx context.Context, cfg config.Config, st store.Store, webFS fs.FS) (*Server, error) {
	if err := maybeBootstrapFromLegacy(ctx, cfg, st); err != nil {
		return nil, fmt.Errorf("failed to bootstrap key material: %w", err)
	}

	// Provision the immutable per-account default key (alias/default) for every
	// known account. Idempotent; best-effort so a transient failure does not
	// block startup (ResolveDefault still falls back to legacy resolution).
	if err := ensureManagedDefaultKeys(ctx, st); err != nil {
		log.Printf("warning: failed to ensure per-account default keys: %v", err)
	}

	// Merge admin-console users from the database (RBAC tied into the DB) with
	// any env-configured users, seeding env users into the DB on first run.
	if mergedUsers, err := mergeDBUIUsers(ctx, st, cfg.UIUsers); err != nil {
		log.Printf("warning: failed to load admin users from database: %v", err)
	} else {
		cfg.UIUsers = mergedUsers
	}

	_, dbBacked := st.(*postgres.Store)
	if err := config.CheckSecurityPosture(cfg, dbBacked); err != nil {
		return nil, fmt.Errorf("refusing to start: %w", err)
	}
	if cfg.InsecureDev {
		log.Printf("WARNING: KMS_INSECURE_DEV=true — authentication is DISABLED. Never use this outside local development.")
	}

	return &Server{cfg: cfg, store: st, acmeChallenges: newACMEChallengeStore(), webFS: webFS}, nil
}

// handler returns the HTTP handler serving every route, wrapped in the
// middleware chain.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/healthz", s.handleHealth)

	// API endpoint remains available for AWS JSON-RPC clients
	mux.HandleFunc("/api", s.handleKMS)

	// Native Citadel API (/v1): protocol-clean JSON consumed by the Svelte
	// control plane and native SDKs. Projects an Infisical-style hierarchy onto
	// the AWS-compatible secrets store.
	mux.HandleFunc("GET /v1/me", s.handleV1Me)
	mux.HandleFunc("GET /v1/projects", s.handleV1Projects)
	mux.HandleFunc("POST /v1/projects", s.handleV1CreateProject)
	mux.HandleFunc("POST /v1/environments", s.handleV1CreateEnvironment)
	mux.HandleFunc("POST /v1/folders", s.handleV1CreateFolder)
	mux.HandleFunc("POST /v1/projects/rename", s.handleV1RenameProject)
	mux.HandleFunc("DELETE /v1/projects", s.handleV1DeleteProject)
	mux.HandleFunc("POST /v1/environments/rename", s.handleV1RenameEnvironment)
	mux.HandleFunc("DELETE /v1/environments", s.handleV1DeleteEnvironment)
	mux.HandleFunc("DELETE /v1/folders", s.handleV1DeleteFolder)
	mux.HandleFunc("GET /v1/secrets", s.handleV1ListSecrets)
	mux.HandleFunc("POST /v1/secrets", s.handleV1PutSecret)
	mux.HandleFunc("DELETE /v1/secrets", s.handleV1DeleteSecret)
	// Removes an object occupying a folder's own name. DELETE /v1/secrets can't:
	// it addresses a secret by key, and this thing has no key.
	mux.HandleFunc("DELETE /v1/secrets/shadowing", s.handleV1DeleteShadowing)
	mux.HandleFunc("GET /v1/secrets/value", s.handleV1RevealSecret)
	mux.HandleFunc("GET /v1/secrets/versions", s.handleV1ListVersions)
	mux.HandleFunc("POST /v1/secrets/restore", s.handleV1RestoreSecret)
	mux.HandleFunc("GET /v1/secrets/detail", s.handleV1SecretDetail)
	mux.HandleFunc("POST /v1/secrets/metadata", s.handleV1UpdateSecretMetadata)
	mux.HandleFunc("POST /v1/secrets/rekey", s.handleV1ReKeySecret)
	mux.HandleFunc("POST /v1/secrets/versions/promote", s.handleV1PromoteVersion)
	mux.HandleFunc("POST /v1/secrets/tags", s.handleV1TagSecret)
	mux.HandleFunc("DELETE /v1/secrets/tags", s.handleV1UntagSecret)
	mux.HandleFunc("GET /v1/secrets/policy", s.handleV1GetSecretPolicy)
	mux.HandleFunc("POST /v1/secrets/policy", s.handleV1PutSecretPolicy)
	mux.HandleFunc("POST /v1/secrets/rotation", s.handleV1ConfigureRotation)
	mux.HandleFunc("DELETE /v1/secrets/rotation", s.handleV1CancelRotation)
	mux.HandleFunc("POST /v1/secrets/bulk", s.handleV1BulkSecrets)
	mux.HandleFunc("GET /v1/parameters", s.handleV1ListParameters)
	mux.HandleFunc("POST /v1/parameters", s.handleV1PutParameter)
	mux.HandleFunc("DELETE /v1/parameters", s.handleV1DeleteParameter)
	mux.HandleFunc("GET /v1/parameters/value", s.handleV1RevealParameter)
	mux.HandleFunc("GET /v1/parameters/history", s.handleV1ParameterHistory)
	mux.HandleFunc("GET /v1/parameters/tags", s.handleV1ListParameterTags)
	mux.HandleFunc("POST /v1/parameters/tags", s.handleV1TagParameter)
	mux.HandleFunc("DELETE /v1/parameters/tags", s.handleV1UntagParameter)
	mux.HandleFunc("POST /v1/parameters/label", s.handleV1LabelParameterVersion)
	mux.HandleFunc("GET /v1/kms/keys", s.handleV1ListKMSKeys)
	mux.HandleFunc("POST /v1/kms/keys", s.handleV1CreateKMSKey)
	mux.HandleFunc("POST /v1/kms/keys/enabled", s.handleV1SetKMSKeyEnabled)
	mux.HandleFunc("POST /v1/kms/keys/schedule-deletion", s.handleV1ScheduleKMSKeyDeletion)
	mux.HandleFunc("POST /v1/kms/keys/cancel-deletion", s.handleV1CancelKMSKeyDeletion)
	mux.HandleFunc("GET /v1/kms/keys/detail", s.handleV1KMSKeyDetail)
	mux.HandleFunc("POST /v1/kms/keys/policy", s.handleV1PutKMSKeyPolicy)
	mux.HandleFunc("POST /v1/kms/aliases", s.handleV1CreateKMSAlias)
	mux.HandleFunc("POST /v1/kms/aliases/update", s.handleV1UpdateKMSAlias)
	mux.HandleFunc("DELETE /v1/kms/aliases", s.handleV1DeleteKMSAlias)
	mux.HandleFunc("GET /v1/certificates", s.handleV1ListCertificates)
	mux.HandleFunc("POST /v1/certificates/authorities", s.handleV1CreateCA)
	mux.HandleFunc("POST /v1/certificates/authorities/import", s.handleV1ImportCA)
	mux.HandleFunc("POST /v1/certificates/issue", s.handleV1IssueCert)
	mux.HandleFunc("POST /v1/certificates/renew", s.handleV1RenewCert)
	mux.HandleFunc("POST /v1/certificates/revoke", s.handleV1RevokeCert)
	mux.HandleFunc("GET /v1/certificates/detail", s.handleV1CertificateDetail)
	mux.HandleFunc("GET /v1/certificates/letsencrypt/settings", s.handleV1GetLESettings)
	mux.HandleFunc("POST /v1/certificates/letsencrypt/settings", s.handleV1SaveLESettings)
	mux.HandleFunc("POST /v1/certificates/letsencrypt/request", s.handleV1RequestLECert)
	mux.HandleFunc("POST /v1/certificates/letsencrypt/dns/begin", s.handleV1BeginLEDNSOrder)
	mux.HandleFunc("POST /v1/certificates/letsencrypt/dns/complete", s.handleV1CompleteLEDNSOrder)
	mux.HandleFunc("GET /v1/audit", s.handleV1ListAudit)
	mux.HandleFunc("GET /v1/change-requests", s.handleV1ListChangeRequests)
	mux.HandleFunc("POST /v1/change-requests", s.handleV1CreateChangeRequest)
	mux.HandleFunc("POST /v1/change-requests/approve", s.handleV1ApproveChangeRequest)
	mux.HandleFunc("POST /v1/change-requests/reject", s.handleV1RejectChangeRequest)

	// Native session + self-service + master-admin actions (replace the legacy
	// html/template admin pages).
	mux.HandleFunc("POST /v1/login", s.handleV1Login)
	mux.HandleFunc("POST /v1/logout", s.handleV1Logout)
	mux.HandleFunc("GET /v1/account/keys", s.handleV1ListAccessKeys)
	mux.HandleFunc("POST /v1/account/keys", s.handleV1CreateAccessKey)
	mux.HandleFunc("DELETE /v1/account/keys", s.handleV1DeleteAccessKey)
	mux.HandleFunc("POST /v1/account/keys/status", s.handleV1SetAccessKeyStatus)
	mux.HandleFunc("POST /v1/account/password", s.handleV1ChangePassword)
	mux.HandleFunc("GET /v1/admin/users", s.handleV1ListUsers)
	mux.HandleFunc("POST /v1/admin/users", s.handleV1UpsertUser)
	mux.HandleFunc("DELETE /v1/admin/users", s.handleV1DeleteUser)
	mux.HandleFunc("GET /v1/admin/accounts", s.handleV1ListAccounts)
	mux.HandleFunc("POST /v1/admin/accounts", s.handleV1CreateAccount)
	mux.HandleFunc("DELETE /v1/admin/accounts", s.handleV1DeleteAccount)
	mux.HandleFunc("POST /v1/admin/accounts/assign", s.handleV1AssignUserAccount)
	mux.HandleFunc("DELETE /v1/admin/accounts/assign", s.handleV1RemoveUserAccount)

	// IAM identity federation: OIDC providers and roles consumed by STS.
	mux.HandleFunc("GET /v1/iam/oidc-providers", s.handleV1ListOIDCProviders)
	mux.HandleFunc("POST /v1/iam/oidc-providers", s.handleV1CreateOIDCProvider)
	mux.HandleFunc("DELETE /v1/iam/oidc-providers", s.handleV1DeleteOIDCProvider)
	mux.HandleFunc("GET /v1/iam/roles", s.handleV1ListRoles)
	mux.HandleFunc("POST /v1/iam/roles", s.handleV1CreateRole)
	mux.HandleFunc("DELETE /v1/iam/roles", s.handleV1DeleteRole)

	// Modern Svelte single-page control plane, embedded into the binary.
	mux.Handle("/app/", http.HandlerFunc(s.handleApp))
	mux.Handle("/app", http.RedirectHandler("/app/", http.StatusMovedPermanently))

	// ACME endpoints (RFC 8555)
	mux.HandleFunc("GET /acme/directory", s.handleACMEDirectory)
	mux.HandleFunc("GET /acme/new-nonce", s.handleACMENewNonce)
	mux.HandleFunc("POST /acme/new-nonce", s.handleACMENewNonce)
	mux.HandleFunc("POST /acme/new-account", s.handleACMENewAccount)
	mux.HandleFunc("POST /acme/new-order", s.handleACMENewOrder)
	mux.HandleFunc("GET /acme/order/{order_id}", s.handleACMEOrder)
	mux.HandleFunc("POST /acme/order/{order_id}", s.handleACMEOrder)
	mux.HandleFunc("POST /acme/order/{order_id}/finalize", s.handleACMEFinalize)
	mux.HandleFunc("GET /acme/authz/{authz_id}", s.handleACMEAuthorization)
	mux.HandleFunc("POST /acme/authz/{authz_id}", s.handleACMEAuthorization)
	mux.HandleFunc("POST /acme/challenge/{challenge_id}", s.handleACMEChallenge)
	mux.HandleFunc("GET /acme/cert/{cert_id}", s.handleACMECertificate)
	mux.HandleFunc("POST /acme/revoke-cert", s.handleACMERevokeCert)

	// Public HTTP-01 validation endpoint for the Let's Encrypt ACME *client*.
	// Must be reachable unauthenticated so the ACME CA can verify domain control.
	mux.HandleFunc("GET /.well-known/acme-challenge/{token}", s.handleACMEChallengeToken)

	// Public CRL distribution point. Certificate Revocation Lists are intended
	// to be fetched anonymously by relying parties, so this is served
	// unauthenticated in binary DER form at the conventional .crl path.
	mux.HandleFunc("GET /crl/{ca_id}", s.handleCRLDownload)

	// Middleware chain (outermost first): panic recovery, security headers,
	// request logging.
	return withPanicRecovery(withSecurityHeaders(withRequestLogging(mux)))
}

func maybeBootstrapFromLegacy(ctx context.Context, cfg config.Config, st store.Store) error {
	if len(cfg.LegacyMasterKey) == 0 {
		return nil
	}
	legacyKeyID := strings.TrimSpace(cfg.LegacyKeyID)
	if legacyKeyID == "" {
		if existing, err := st.ResolveDefault(ctx); err == nil && strings.TrimSpace(existing.ID) != "" {
			legacyKeyID = existing.ID
		} else if cfg.DBConnString == "" {
			legacyKeyID = cryptoutil.DeriveDeterministicLegacyKeyID(cfg.LegacyMasterKey)
		} else {
			legacyKeyID = cryptoutil.RandomHex(12)
		}
	}
	keyARN := cfg.LegacyKeyARN
	if keyARN == "" {
		keyARN = bootstrapKeyARN(st, legacyKeyID)
	}
	k := store.KMSKey{
		ID:           legacyKeyID,
		ARN:          keyARN,
		MasterKeyRaw: cfg.LegacyMasterKey,
		Description:  "go-kms key",
		CreatedAt:    time.Now().UTC(),
		Enabled:      true,
		KeyUsage:     store.KeyUsageEncryptDecrypt,
		KeySpec:      store.KeySpecSymmetricDefault,
	}
	if err := st.EnsureBootstrap(ctx, k); err != nil {
		return err
	}
	return nil
}

// bootstrapKeyARN builds the ARN for the bootstrap key using the store's
// deployment identity.
func bootstrapKeyARN(store store.Store, keyID string) string {
	region, accountID := store.DeploymentIdentity()
	return arn.Build("kms", region, accountID, "key/"+keyID)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAWSJSONError(w, http.StatusMethodNotAllowed, "InvalidAction", "method not allowed")
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleKMS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAWSJSONError(w, http.StatusMethodNotAllowed, "InvalidAction", "method not allowed")
		return
	}
	// Identity comes only from a verified signature, never from headers.
	r.Header.Del("X-KMS-Username")
	r.Header.Del("X-KMS-Account-ID")
	r, ok := s.authenticateAWSJSON(w, r)
	if !ok {
		return
	}

	target := r.Header.Get("X-Amz-Target")
	switch target {
	case "TrentService.Encrypt":
		s.handleEncrypt(w, r)
	case "TrentService.Decrypt":
		s.handleDecrypt(w, r)
	case "TrentService.DescribeKey":
		s.handleDescribeKey(w, r)
	case "TrentService.CreateKey":
		s.handleCreateKey(w, r)
	case "TrentService.ListKeys":
		s.handleListKeys(w, r)
	case "TrentService.CreateAlias":
		s.handleCreateAlias(w, r)
	case "TrentService.UpdateAlias":
		s.handleUpdateAlias(w, r)
	case "TrentService.ListAliases":
		s.handleListAliases(w, r)
	case "TrentService.EnableKey":
		s.handleSetKeyEnabled(w, r, true)
	case "TrentService.DisableKey":
		s.handleSetKeyEnabled(w, r, false)
	case "TrentService.ScheduleKeyDeletion":
		s.handleScheduleKeyDeletion(w, r)
	case "TrentService.CancelKeyDeletion":
		s.handleCancelKeyDeletion(w, r)
	case "TrentService.CreateGrant":
		s.handleCreateGrant(w, r)
	case "TrentService.ListGrants":
		s.handleListGrants(w, r)
	case "TrentService.RevokeGrant":
		s.handleRevokeGrant(w, r)
	case "TrentService.RetireGrant":
		s.handleRetireGrant(w, r)
	case "TrentService.GetKeyPolicy":
		s.handleGetKeyPolicy(w, r)
	case "TrentService.PutKeyPolicy":
		s.handlePutKeyPolicy(w, r)
	case "TrentService.Sign":
		s.handleSign(w, r)
	case "TrentService.Verify":
		s.handleVerify(w, r)
	case "TrentService.GetPublicKey":
		s.handleGetPublicKey(w, r)
	case "acm-pca.CreateCertificateAuthority":
		s.handleCreateCertificateAuthority(w, r)
	case "acm-pca.DescribeCertificateAuthority":
		s.handleDescribeCertificateAuthority(w, r)
	case "acm-pca.IssueCertificate":
		s.handleIssueCertificate(w, r)
	case "acm-pca.GetCertificate":
		s.handleGetCertificate(w, r)
	case "acm-pca.RevokeCertificate":
		s.handleRevokeCertificate(w, r)
	case "acm-pca.GetCRL":
		s.handleGetCRL(w, r)
	case "acm.RequestCertificate":
		s.handleACMRequestCertificate(w, r)
	case "acm.DescribeCertificate":
		s.handleACMDescribeCertificate(w, r)
	case "acm.ListCertificates":
		s.handleACMListCertificates(w, r)
	case "acm.GetCertificate":
		s.handleACMGetCertificate(w, r)
	case "acm.DeleteCertificate":
		s.handleACMDeleteCertificate(w, r)
	case "secretsmanager.CreateSecret":
		s.handleCreateSecret(w, r)
	case "secretsmanager.DescribeSecret":
		s.handleDescribeSecret(w, r)
	case "secretsmanager.GetSecretValue":
		s.handleGetSecretValue(w, r)
	case "secretsmanager.PutSecretValue":
		s.handlePutSecretValue(w, r)
	case "secretsmanager.UpdateSecret":
		s.handleUpdateSecret(w, r)
	case "secretsmanager.DeleteSecret":
		s.handleDeleteSecret(w, r)
	case "secretsmanager.RestoreSecret":
		s.handleRestoreSecret(w, r)
	case "secretsmanager.ListSecrets":
		s.handleListSecrets(w, r)
	case "secretsmanager.ListSecretVersionIds":
		s.handleListSecretVersionIDs(w, r)
	case "secretsmanager.TagResource":
		s.handleTagSecret(w, r)
	case "secretsmanager.UntagResource":
		s.handleUntagSecret(w, r)
	case "secretsmanager.GetResourcePolicy":
		s.handleGetSecretResourcePolicy(w, r)
	case "secretsmanager.PutResourcePolicy":
		s.handlePutSecretResourcePolicy(w, r)
	case "secretsmanager.ValidateResourcePolicy":
		s.handleValidateSecretResourcePolicy(w, r)
	case "secretsmanager.RotateSecret":
		s.handleRotateSecret(w, r)
	case "secretsmanager.CancelRotateSecret":
		s.handleCancelRotateSecret(w, r)
	case "secretsmanager.UpdateSecretVersionStage":
		s.handleUpdateSecretVersionStage(w, r)
	case "AmazonSSM.PutParameter":
		s.handleSSMPutParameter(w, r)
	case "AmazonSSM.GetParameter":
		s.handleSSMGetParameter(w, r)
	case "AmazonSSM.GetParameters":
		s.handleSSMGetParameters(w, r)
	case "AmazonSSM.GetParametersByPath":
		s.handleSSMGetParametersByPath(w, r)
	case "AmazonSSM.DeleteParameter":
		s.handleSSMDeleteParameter(w, r)
	case "AmazonSSM.DeleteParameters":
		s.handleSSMDeleteParameters(w, r)
	case "AmazonSSM.DescribeParameters":
		s.handleSSMDescribeParameters(w, r)
	case "AmazonSSM.GetParameterHistory":
		s.handleSSMGetParameterHistory(w, r)
	case "AmazonSSM.LabelParameterVersion":
		s.handleSSMLabelParameterVersion(w, r)
	case "AmazonSSM.AddTagsToResource":
		s.handleSSMAddTagsToResource(w, r)
	case "AmazonSSM.RemoveTagsFromResource":
		s.handleSSMRemoveTagsFromResource(w, r)
	case "AmazonSSM.ListTagsForResource":
		s.handleSSMListTagsForResource(w, r)
	default:
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidAction", "unsupported X-Amz-Target")
	}
}

func (s *Server) handleGetKeyPolicy(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.GetKeyPolicy"
	var req getKeyPolicyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		return
	}
	if req.KeyID == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "KeyId is required")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		return
	}
	if req.PolicyName == "" {
		req.PolicyName = "default"
	}
	key, err := s.store.ResolveByID(r.Context(), req.KeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key or policy not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:GetKeyPolicy"); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		return
	}
	doc, err := s.store.GetKeyPolicy(r.Context(), req.KeyID, req.PolicyName)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key or policy not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, getKeyPolicyResponse{Policy: doc})
}

func (s *Server) handlePutKeyPolicy(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.PutKeyPolicy"
	var req putKeyPolicyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		return
	}
	if req.KeyID == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "KeyId is required")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		return
	}
	if req.PolicyName == "" {
		req.PolicyName = "default"
	}
	if strings.TrimSpace(req.Policy) == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "Policy is required")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		return
	}
	normalizedPolicy, err := normalizePolicyDocument(req.Policy)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "MalformedPolicyDocumentException", "Policy must be valid JSON")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "MalformedPolicyDocumentException", Actor: r.RemoteAddr})
		return
	}
	key, err := s.store.ResolveByID(r.Context(), req.KeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:PutKeyPolicy"); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		return
	}
	if err := s.store.PutKeyPolicy(r.Context(), req.KeyID, req.PolicyName, normalizedPolicy); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleEncrypt(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.Encrypt"
	var req encryptRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if req.Plaintext == "" {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "Plaintext is required")
		return
	}

	var (
		key store.KMSKey
		err error
	)
	if req.KeyID != "" {
		key, err = s.store.ResolveByID(r.Context(), req.KeyID)
	} else {
		key, err = s.store.ResolveDefault(r.Context())
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
			writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "unknown key id")
			return
		}
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "key lookup failed")
		return
	}
	if keyUsage, _ := keyUsageAndSpecForMetadata(key); keyUsage != store.KeyUsageEncryptDecrypt {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "InvalidKeyUsageException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidKeyUsageException", "key does not support encryption")
		return
	}
	if keyUsage, _ := keyUsageAndSpecForMetadata(key); keyUsage != store.KeyUsageEncryptDecrypt {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "InvalidKeyUsageException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidKeyUsageException", "key does not support decryption")
		return
	}
	if !key.Enabled {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "DisabledException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "DisabledException", "key is disabled")
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:Encrypt"); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		return
	}

	plaintext, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "Plaintext must be base64")
		return
	}

	cipherBlob, err := cryptoutil.EncryptBlob(key.MasterKeyRaw, key.ID, plaintext, cryptoutil.CanonicalContext(req.EncryptionContext))
	if err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "encrypt failed")
		return
	}

	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", Actor: r.RemoteAddr})

	writeJSON(w, http.StatusOK, encryptResponse{
		CiphertextBlob:    base64.StdEncoding.EncodeToString(cipherBlob),
		KeyID:             key.ID,
		EncryptionContext: req.EncryptionContext,
	})
}

func (s *Server) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.Decrypt"
	var req decryptRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if req.CiphertextBlob == "" {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "CiphertextBlob is required")
		return
	}

	cipherBlob, err := base64.StdEncoding.DecodeString(req.CiphertextBlob)
	if err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "CiphertextBlob must be base64")
		return
	}

	keyID, rawBlob, err := cryptoutil.DecodeCipherBlob(cipherBlob)
	if err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidCiphertextException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidCiphertextException", "decrypt failed")
		return
	}

	var key store.KMSKey
	if keyID == "" {
		key, err = s.store.ResolveDefault(r.Context())
	} else {
		key, err = s.store.ResolveByID(r.Context(), keyID)
	}
	if err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: keyID, Result: "error", ErrorType: "InvalidCiphertextException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidCiphertextException", "decrypt failed")
		return
	}
	if !key.Enabled {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "DisabledException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "DisabledException", "key is disabled")
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:Decrypt"); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		return
	}

	plaintext, err := cryptoutil.DecryptBlob(key.MasterKeyRaw, rawBlob, cryptoutil.CanonicalContext(req.EncryptionContext))
	if err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "InvalidCiphertextException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidCiphertextException", "decrypt failed")
		return
	}

	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", Actor: r.RemoteAddr})

	writeJSON(w, http.StatusOK, decryptResponse{
		KeyID:             key.ID,
		Plaintext:         base64.StdEncoding.EncodeToString(plaintext),
		EncryptionContext: req.EncryptionContext,
	})
}

func (s *Server) handleDescribeKey(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.DescribeKey"
	var req describeKeyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}

	var (
		key store.KMSKey
		err error
	)
	if req.KeyID != "" {
		key, err = s.store.ResolveByID(r.Context(), req.KeyID)
	} else {
		key, err = s.store.ResolveDefault(r.Context())
	}
	if err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "unknown key id")
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:DescribeKey"); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		return
	}

	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", Actor: r.RemoteAddr})

	writeJSON(w, http.StatusOK, describeKeyResponse{
		KeyMetadata: toKeyMetadata(key),
	})
}

func (s *Server) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.CreateKey"
	var req createKeyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	key, err := s.store.CreateKey(r.Context(), req.Description, req.KeyUsage, req.KeySpec)
	if err != nil {
		errType := "DependencyTimeoutException"
		if errors.Is(err, store.ErrUnsupported) {
			errType = "UnsupportedOperationException"
			writeAWSJSONError(w, http.StatusBadRequest, errType, "CreateKey requires KMS_DB_URL")
		} else {
			writeAWSJSONError(w, http.StatusInternalServerError, errType, "create key failed")
		}
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: errType, Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, createKeyResponse{KeyMetadata: toKeyMetadata(key)})
}

func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.ListKeys"
	var req listKeysRequest
	if err := decodeOptionalJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	limit, err := normalizeListLimit(req.Limit)
	if err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	keys, err := s.store.ListKeys(r.Context())
	if err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "list keys failed")
		return
	}
	out := make([]listKeyEntry, 0, len(keys))
	for _, k := range keys {
		out = append(out, listKeyEntry{KeyID: k.ID, KeyARN: k.ARN})
	}
	out, nextMarker, truncated, err := paginateList(out, req.Marker, limit, func(item listKeyEntry) string { return item.KeyID })
	if err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, listKeysResponse{Keys: out, NextMarker: nextMarker, Truncated: truncated})
}

func (s *Server) handleCreateAlias(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.CreateAlias"
	var req createAliasRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if req.AliasName == "" || req.TargetKeyID == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "AliasName and TargetKeyId are required")
		return
	}
	if req.AliasName == store.ManagedDefaultAlias {
		writeAWSJSONError(w, http.StatusBadRequest, "UnsupportedOperationException", "alias/default is reserved for the account's managed default key")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.TargetKeyID, Result: "error", ErrorType: "UnsupportedOperationException", Actor: r.RemoteAddr})
		return
	}
	key, err := s.store.ResolveByID(r.Context(), req.TargetKeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "target key not found or alias exists")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.TargetKeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:CreateAlias"); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		return
	}
	if err := s.store.CreateAlias(r.Context(), req.AliasName, req.TargetKeyID); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "target key not found or alias exists")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.TargetKeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.TargetKeyID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleUpdateAlias(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.UpdateAlias"
	var req updateAliasRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if req.AliasName == "" || req.TargetKeyID == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "AliasName and TargetKeyId are required")
		return
	}
	if req.AliasName == store.ManagedDefaultAlias {
		writeAWSJSONError(w, http.StatusBadRequest, "UnsupportedOperationException", "alias/default is immutable and cannot be re-pointed")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.TargetKeyID, Result: "error", ErrorType: "UnsupportedOperationException", Actor: r.RemoteAddr})
		return
	}
	key, err := s.store.ResolveByID(r.Context(), req.TargetKeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "alias or key not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.TargetKeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:UpdateAlias"); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		return
	}
	if err := s.store.UpdateAlias(r.Context(), req.AliasName, req.TargetKeyID); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "alias or key not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.TargetKeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.TargetKeyID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleListAliases(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.ListAliases"
	var req listAliasesRequest
	if err := decodeOptionalJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		return
	}
	limit, err := normalizeListLimit(req.Limit)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		return
	}
	aliases, err := s.store.ListAliases(r.Context())
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "list aliases failed")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		return
	}
	out := make([]aliasEntry, 0, len(aliases))
	for _, a := range aliases {
		out = append(out, aliasEntry{AliasName: a.AliasName, TargetKeyID: a.TargetKeyID})
	}
	out, nextMarker, truncated, err := paginateList(out, req.Marker, limit, func(item aliasEntry) string { return item.AliasName })
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, listAliasesResponse{Aliases: out, NextMarker: nextMarker, Truncated: truncated})
}

func (s *Server) handleSetKeyEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	action := "TrentService.DisableKey"
	if enabled {
		action = "TrentService.EnableKey"
	}
	var req keyIDRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if req.KeyID == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "KeyId is required")
		return
	}
	key, err := s.store.ResolveByID(r.Context(), req.KeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	policyAction := "kms:DisableKey"
	if enabled {
		policyAction = "kms:EnableKey"
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, policyAction); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		return
	}
	if !enabled && key.Managed {
		writeAWSJSONError(w, http.StatusBadRequest, "UnsupportedOperationException", "the account default key cannot be disabled")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "UnsupportedOperationException", Actor: r.RemoteAddr})
		return
	}
	if err := s.store.SetKeyEnabled(r.Context(), req.KeyID, enabled); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleScheduleKeyDeletion(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.ScheduleKeyDeletion"
	var req scheduleKeyDeletionRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if req.KeyID == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "KeyId is required")
		return
	}
	if req.PendingWindowInDays == 0 {
		req.PendingWindowInDays = 30
	}
	if req.PendingWindowInDays < 7 || req.PendingWindowInDays > 30 {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "PendingWindowInDays must be between 7 and 30")
		return
	}
	key, err := s.store.ResolveByID(r.Context(), req.KeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:ScheduleKeyDeletion"); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		return
	}
	if key.Managed {
		writeAWSJSONError(w, http.StatusBadRequest, "UnsupportedOperationException", "the account default key cannot be scheduled for deletion")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "UnsupportedOperationException", Actor: r.RemoteAddr})
		return
	}
	deletionDate, err := s.store.ScheduleKeyDeletion(r.Context(), req.KeyID, req.PendingWindowInDays)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, scheduleKeyDeletionResponse{KeyID: req.KeyID, DeletionDate: deletionDate})
}

func (s *Server) handleCancelKeyDeletion(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.CancelKeyDeletion"
	var req keyIDRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if req.KeyID == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "KeyId is required")
		return
	}
	key, err := s.store.ResolveByID(r.Context(), req.KeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:CancelKeyDeletion"); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		return
	}
	if err := s.store.CancelKeyDeletion(r.Context(), req.KeyID); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "ok", Actor: r.RemoteAddr})
	key, err = s.store.ResolveByID(r.Context(), req.KeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "reload key failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"KeyMetadata": toKeyMetadata(key)})
}

func (s *Server) handleCreateGrant(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.CreateGrant"
	var req store.CreateGrantRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if strings.TrimSpace(req.KeyID) == "" || strings.TrimSpace(req.GranteePrincipal) == "" || len(req.Operations) == 0 {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "KeyId, GranteePrincipal, and Operations are required")
		return
	}
	key, err := s.store.ResolveByID(r.Context(), req.KeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:CreateGrant"); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		return
	}
	grant, err := s.store.CreateGrant(r.Context(), req)
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "create grant failed")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, createGrantResponse{GrantID: grant.GrantID, GrantToken: grant.GrantToken})
}

func (s *Server) handleListGrants(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.ListGrants"
	var req listGrantsRequest
	if err := decodeOptionalJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if strings.TrimSpace(req.KeyID) == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "KeyId is required")
		return
	}
	key, err := s.store.ResolveByID(r.Context(), req.KeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:ListGrants"); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		return
	}
	grants, err := s.store.ListGrants(r.Context(), req.KeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "list grants failed")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		return
	}
	out := make([]grantListEntry, 0, len(grants))
	for _, grant := range grants {
		out = append(out, grantListEntry{GrantID: grant.GrantID, KeyID: grant.KeyID, GranteePrincipal: grant.GranteePrincipal, RetiringPrincipal: grant.RetiringPrincipal, Operations: append([]string(nil), grant.Operations...), Name: grant.Name, CreationDate: grant.CreatedAt})
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, listGrantsResponse{Grants: out})
}

func (s *Server) handleRevokeGrant(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.RevokeGrant"
	var req revokeGrantRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if strings.TrimSpace(req.KeyID) == "" || strings.TrimSpace(req.GrantID) == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "KeyId and GrantId are required")
		return
	}
	key, err := s.store.ResolveByID(r.Context(), req.KeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:RevokeGrant"); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		return
	}
	if err := s.store.RevokeGrant(r.Context(), req.KeyID, req.GrantID); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "grant not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: key.ID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleRetireGrant(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.RetireGrant"
	var req retireGrantRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if strings.TrimSpace(req.GrantID) == "" && strings.TrimSpace(req.GrantToken) == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "GrantId or GrantToken is required")
		return
	}
	if err := s.store.RetireGrant(r.Context(), req.GrantID, req.GrantToken); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "grant not found")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, map[string]any{})
}

func keyState(key store.KMSKey) string {
	if key.DeletionDate != nil {
		return "PendingDeletion"
	}
	if key.Enabled {
		return "Enabled"
	}
	return "Disabled"
}

func toKeyMetadata(key store.KMSKey) keyMetadata {
	keyUsage, keySpec := keyUsageAndSpecForMetadata(key)
	return keyMetadata{
		AWSAccountID:                "000000000000",
		KeyID:                       key.ID,
		Arn:                         key.ARN,
		CreationDate:                key.CreatedAt,
		Enabled:                     key.Enabled,
		Description:                 key.Description,
		KeyUsage:                    keyUsage,
		KeyState:                    keyState(key),
		Origin:                      "AWS_KMS",
		KeyManager:                  "CUSTOMER",
		CustomerMasterKeySpec:       keySpec,
		KeySpec:                     keySpec,
		EncryptionAlgorithms:        keyEncryptionAlgorithms(key),
		SigningAlgorithms:           keySigningAlgorithms(key),
		MultiRegion:                 false,
		PendingDeletionWindowInDays: pendingDeletionDays(key.DeletionDate),
	}
}

func keyEncryptionAlgorithms(key store.KMSKey) []string {
	usage, _ := keyUsageAndSpecForMetadata(key)
	if usage != store.KeyUsageEncryptDecrypt {
		return nil
	}
	return []string{store.KeySpecSymmetricDefault}
}

func pendingDeletionDays(deletionDate *time.Time) int {
	if deletionDate == nil {
		return 0
	}
	days := int(time.Until(*deletionDate).Hours() / 24)
	if days < 0 {
		return 0
	}
	return days
}

func (s *Server) recordAudit(ctx context.Context, event store.AuditEvent) {
	if err := s.store.RecordAudit(ctx, event); err != nil {
		log.Printf("audit write failed action=%s key=%s: %v", event.Action, event.KeyID, err)
	}
}

func withRequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s target=%s", r.Method, r.URL.Path, r.Header.Get("X-Amz-Target"))
		next.ServeHTTP(w, r)
	})
}

func decodeJSONBody(r *http.Request, target any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

func decodeOptionalJSONBody(r *http.Request, target any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

func normalizeListLimit(limit int) (int, error) {
	if limit == 0 {
		return 100, nil
	}
	if limit < 0 || limit > 1000 {
		return 0, errors.New("Limit must be between 1 and 1000")
	}
	return limit, nil
}

func paginateList[T any](items []T, marker string, limit int, idOf func(T) string) ([]T, string, bool, error) {
	start := 0
	if marker != "" {
		found := false
		for i, item := range items {
			if idOf(item) == marker {
				start = i + 1
				found = true
				break
			}
		}
		if !found {
			return nil, "", false, errors.New("Marker is invalid")
		}
	}
	if start >= len(items) {
		return []T{}, "", false, nil
	}
	end := start + limit
	if end >= len(items) {
		return items[start:], "", false, nil
	}
	nextMarker := idOf(items[end-1])
	return items[start:end], nextMarker, true, nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeAWSJSONError(w http.ResponseWriter, status int, typ, msg string) {
	writeJSON(w, status, awsError{Type: typ, Message: msg})
}

func (s *Server) authorizeKeyAction(ctx context.Context, r *http.Request, key store.KMSKey, action string) error {
	policy, err := s.store.GetKeyPolicy(ctx, key.ID, "default")
	if err != nil {
		return err
	}
	allowed, err := policyAllows(policy, requestPrincipal(r), action, key.ARN, s.cfg.DefaultDenyPolicy)
	if err != nil {
		return err
	}
	if !allowed {
		return errAccessDenied
	}
	return nil
}

func requestPrincipal(r *http.Request) string {
	if c, ok := awsCallerFromContext(r.Context()); ok {
		return c.PrincipalARN()
	}
	auth := r.Header.Get("Authorization")
	if idx := strings.Index(auth, "Credential="); idx >= 0 {
		rest := auth[idx+len("Credential="):]
		if slash := strings.Index(rest, "/"); slash > 0 {
			accessKey := strings.TrimSpace(rest[:slash])
			if accessKey != "" {
				return "arn:aws:iam::000000000000:user/" + accessKey
			}
		}
	}
	return "arn:aws:iam::000000000000:root"
}

// policyAllows evaluates an AWS-style policy document. An explicit Deny always
// wins. When no statement matches the action/resource, the result depends on
// defaultDeny: false preserves the permissive legacy behavior, true enforces
// AWS-like deny-by-default.
func policyAllows(rawPolicy, principal, action, resource string, defaultDeny bool) (bool, error) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(rawPolicy), &doc); err != nil {
		return false, err
	}
	statements := asPolicyStatements(doc["Statement"])
	hasRelevantStatement := false
	allowed := false
	for _, stmt := range statements {
		if valueMatches(stmt["Action"], action, true) && valueMatches(stmt["Resource"], resource, false) {
			hasRelevantStatement = true
		}
		if !policyStatementMatches(stmt, principal, action, resource) {
			continue
		}
		effect := strings.ToLower(strings.TrimSpace(stringValue(stmt["Effect"])))
		if effect == "deny" {
			return false, nil
		}
		if effect == "allow" {
			allowed = true
		}
	}
	if hasRelevantStatement {
		return allowed, nil
	}
	return !defaultDeny, nil
}

func asPolicyStatements(value any) []map[string]any {
	switch typed := value.(type) {
	case []any:
		out := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			if stmt, ok := item.(map[string]any); ok {
				out = append(out, stmt)
			}
		}
		return out
	case map[string]any:
		return []map[string]any{typed}
	default:
		return nil
	}
}

func policyStatementMatches(stmt map[string]any, principal, action, resource string) bool {
	return principalMatches(stmt["Principal"], principal) && valueMatches(stmt["Action"], action, true) && valueMatches(stmt["Resource"], resource, false)
}

func principalMatches(value any, principal string) bool {
	if value == nil {
		return false
	}
	if stringValue(value) == "*" {
		return true
	}
	if principalMap, ok := value.(map[string]any); ok {
		return valueMatches(principalMap["AWS"], principal, false)
	}
	return valueMatches(value, principal, false)
}

func valueMatches(value any, target string, caseInsensitive bool) bool {
	patterns := stringValues(value)
	for _, pattern := range patterns {
		if wildcardMatch(pattern, target, caseInsensitive) {
			return true
		}
	}
	return false
}

func stringValues(value any) []string {
	switch typed := value.(type) {
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil
		}
		return []string{typed}
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if s := stringValue(item); strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		if s := stringValue(value); strings.TrimSpace(s) != "" {
			return []string{s}
		}
		return nil
	}
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return fmt.Sprint(value)
	}
}

func wildcardMatch(pattern, target string, caseInsensitive bool) bool {
	if caseInsensitive {
		pattern = strings.ToLower(pattern)
		target = strings.ToLower(target)
	}
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(target, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == target
}

func normalizePolicyDocument(raw string) (string, error) {
	var doc any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
