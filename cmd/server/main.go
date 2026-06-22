package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/lib/pq"
)

const (
	cipherBlobVersionV1 byte = 1

	// appName is the user-facing product name used in logs and UI.
	appName = "Citadel"
)

var (
	errUnsupported  = errors.New("unsupported operation")
	errAccessDenied = errors.New("access denied")
)

type config struct {
	addr              string
	dbConnString      string
	requireAccessKey  bool
	expectedAccessKey string
	secretAccessKey   string
	strictSigV4       bool
	defaultDenyPolicy bool
	wrappingKey       []byte
	legacyWrappingKey []byte
	auditHMACKey      []byte
	uiUsers           map[string]uiUserConfig
	uiSecureCookies   bool
	sessionIdleTTL    time.Duration
	sessionAbsTTL     time.Duration
	tlsCertFile       string
	tlsKeyFile        string

	awsRegion    string
	awsAccountID string

	legacyKeyID     string
	legacyMasterKey []byte
}

type server struct {
	cfg   config
	store keyStore
	ui    *uiRuntime
}

type keyStore interface {
	ResolveByID(ctx context.Context, keyID string) (kmsKey, error)
	ResolveDefault(ctx context.Context) (kmsKey, error)
	EnsureBootstrap(ctx context.Context, k kmsKey) error
	DeploymentIdentity() (region, accountID string)
	CreateKey(ctx context.Context, description, keyUsage, keySpec string) (kmsKey, error)
	ImportSigningKey(ctx context.Context, description string, privPKCS8DER, pubPKIXDER []byte, keySpec string) (kmsKey, error)
	ListKeys(ctx context.Context) ([]kmsKey, error)
	GetKeyPolicy(ctx context.Context, keyID, policyName string) (string, error)
	PutKeyPolicy(ctx context.Context, keyID, policyName, policyDocument string) error
	CreateAlias(ctx context.Context, aliasName, keyID string) error
	UpdateAlias(ctx context.Context, aliasName, keyID string) error
	ListAliases(ctx context.Context) ([]kmsAlias, error)
	SetKeyEnabled(ctx context.Context, keyID string, enabled bool) error
	ScheduleKeyDeletion(ctx context.Context, keyID string, windowDays int) (time.Time, error)
	CancelKeyDeletion(ctx context.Context, keyID string) error
	ForceDeleteKey(ctx context.Context, keyID string) error
	CreateGrant(ctx context.Context, req createGrantRequest) (kmsGrant, error)
	ListGrants(ctx context.Context, keyID string) ([]kmsGrant, error)
	RevokeGrant(ctx context.Context, keyID, grantID string) error
	RetireGrant(ctx context.Context, grantID, grantToken string) error
	CreateSecret(ctx context.Context, req createSecretRequest) (secretMetadataRecord, secretValueRecord, error)
	DescribeSecret(ctx context.Context, secretID string) (secretMetadataRecord, error)
	GetSecretValue(ctx context.Context, secretID, versionID, versionStage string) (secretValueRecord, error)
	PutSecretValue(ctx context.Context, req putSecretValueRequest) (secretValueRecord, error)
	UpdateSecret(ctx context.Context, req updateSecretRequest) (secretMetadataRecord, *secretValueRecord, error)
	DeleteSecret(ctx context.Context, secretID string, recoveryWindowDays int, forceDelete bool) (secretMetadataRecord, error)
	RestoreSecret(ctx context.Context, secretID string) (secretMetadataRecord, error)
	ListSecrets(ctx context.Context) ([]secretMetadataRecord, error)
	ListSecretVersionIDs(ctx context.Context, secretID string) ([]secretVersionListEntry, error)
	TagSecret(ctx context.Context, secretID string, tags []secretTag) error
	UntagSecret(ctx context.Context, secretID string, tagKeys []string) error
	GetSecretResourcePolicy(ctx context.Context, secretID string) (string, error)
	PutSecretResourcePolicy(ctx context.Context, secretID, policyDocument string) error
	RotateSecret(ctx context.Context, secretID, rotationLambdaARN string, automaticallyAfterDays int, rotateImmediately bool, clientRequestToken string) (secretRotationResult, error)
	CancelRotateSecret(ctx context.Context, secretID string) (secretMetadataRecord, error)
	UpdateSecretVersionStage(ctx context.Context, secretID, versionStage, moveToVersionID, removeFromVersionID string) (secretMetadataRecord, error)
	ListAuditEvents(ctx context.Context, limit int) ([]auditRecord, error)
	RecordAudit(ctx context.Context, event auditEvent) error
	ListUIUsers(ctx context.Context) ([]uiUserConfig, error)
	UpsertUIUser(ctx context.Context, user uiUserConfig) error
	DeleteUIUser(ctx context.Context, username string) error
	ListUIAccounts(ctx context.Context) ([]string, error)
	UpsertUIAccount(ctx context.Context, account string) error
	DeleteUIAccount(ctx context.Context, account string) error

	// Private CA (acm-pca) methods
	CreateCertificateAuthority(ctx context.Context, ca pcaCertificateAuthority) error
	DescribeCertificateAuthority(ctx context.Context, arn string) (pcaCertificateAuthority, error)
	ListCertificateAuthorities(ctx context.Context) ([]pcaCertificateAuthority, error)
	CreateCertificate(ctx context.Context, cert pcaCertificate) error
	GetCertificate(ctx context.Context, certID string) (pcaCertificate, error)
	ListCertificates(ctx context.Context, caID string) ([]pcaCertificate, error)
	RevokeCertificate(ctx context.Context, certID, reason string) error
}

type dbStore struct {
	db                *sql.DB
	wrappingKey       []byte
	legacyWrappingKey []byte
	auditHMACKey      []byte
	region            string
	accountID         string
}

type inMemoryStore struct {
	mu           sync.Mutex
	k            kmsKey
	keys         []kmsKey
	aliases      []kmsAlias
	grants       []kmsGrant
	policies     map[string]string
	secrets      map[string]*inMemorySecret
	audit        []auditRecord
	auditSeq     int64
	auditHMACKey []byte
	uiUsers      map[string]uiUserConfig
	uiAccounts   map[string]struct{}
	region       string
	accountID    string
}

type kmsKey struct {
	ID           string
	ARN          string
	MasterKeyRaw []byte
	PublicKeyRaw []byte
	Description  string
	CreatedAt    time.Time
	Enabled      bool
	DeletionDate *time.Time
	KeyUsage     string
	KeySpec      string
}

type kmsAlias struct {
	AliasName   string
	TargetKeyID string
}

type pcaCertificateAuthority struct {
	CAID        string
	ARN         string
	Type        string
	KMSKeyID    string
	SubjectDN   string
	State       string
	CACertB64   string
	PathLength  *int
	NotBefore   time.Time
	NotAfter    time.Time
	Description string
	Account     string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type pcaCertificate struct {
	CertID           string
	CAID             string
	Serial           string
	CSRB64           string
	CertB64          string
	Status           string
	NotBefore        time.Time
	NotAfter         time.Time
	RevokedAt        *time.Time
	RevocationReason string
	Template         string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type kmsGrant struct {
	GrantID           string
	GrantToken        string
	KeyID             string
	GranteePrincipal  string
	RetiringPrincipal string
	Operations        []string
	Name              string
	CreatedAt         time.Time
}

type awsError struct {
	Type    string `json:"__type"`
	Message string `json:"message"`
}

type auditEvent struct {
	Action    string
	KeyID     string
	Result    string
	ErrorType string
	Actor     string
}

type auditRecord struct {
	ID        int64
	Action    string
	KeyID     string
	Result    string
	ErrorType string
	Actor     string
	PrevHash  string
	EventHash string
	CreatedAt time.Time
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

type createGrantRequest struct {
	KeyID             string   `json:"KeyId"`
	GranteePrincipal  string   `json:"GranteePrincipal"`
	RetiringPrincipal string   `json:"RetiringPrincipal"`
	Operations        []string `json:"Operations"`
	Name              string   `json:"Name"`
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

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	store, cleanup, err := buildStore(cfg)
	if err != nil {
		log.Fatalf("failed to initialize key store: %v", err)
	}
	defer cleanup()

	if err := maybeBootstrapFromLegacy(context.Background(), cfg, store); err != nil {
		log.Fatalf("failed to bootstrap key material: %v", err)
	}

	// Merge admin-console users from the database (RBAC tied into the DB) with
	// any env-configured users, seeding env users into the DB on first run.
	if mergedUsers, err := mergeDBUIUsers(context.Background(), store, cfg.uiUsers); err != nil {
		log.Printf("warning: failed to load admin users from database: %v", err)
	} else {
		cfg.uiUsers = mergedUsers
	}

	s := &server{cfg: cfg, store: store}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/login", s.handleAdminLogin)
	mux.HandleFunc("/logout", s.handleAdminLogout)
	mux.HandleFunc("/secrets", s.handleSecretsAdmin)
	mux.HandleFunc("/certificates", s.handleCertificatesAdmin)
	mux.HandleFunc("/audit", s.handleAudit)

	// Master admin UI pages
	mux.HandleFunc("/admin", s.handleMasterAdminOverview)
	mux.HandleFunc("/admin/users", s.handleMasterAdminUsers)
	mux.HandleFunc("/admin/rbac", s.handleMasterAdminRBAC)
	mux.HandleFunc("/admin/accounts", s.handleMasterAdminAccounts)
	mux.HandleFunc("/admin/settings", s.handleMasterAdminSettings)
	mux.HandleFunc("/admin/tenants", s.handleLegacyTenantsRedirect)

	// Compatibility aliases for old UI paths
	mux.Handle("/admin/login", http.RedirectHandler("/login", http.StatusMovedPermanently))
	mux.Handle("/admin/logout", http.RedirectHandler("/logout", http.StatusMovedPermanently))
	mux.Handle("/admin/secrets", http.RedirectHandler("/secrets", http.StatusMovedPermanently))
	mux.Handle("/admin/certificates", http.RedirectHandler("/certificates", http.StatusMovedPermanently))
	mux.Handle("/admin/audit", http.RedirectHandler("/audit", http.StatusMovedPermanently))

	// API endpoint remains available for AWS JSON-RPC clients
	mux.HandleFunc("/api", s.handleKMS)

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

	// Middleware chain (outermost first): panic recovery, security headers,
	// request logging.
	h := withPanicRecovery(withSecurityHeaders(withRequestLogging(mux)))

	httpServer := &http.Server{
		Addr:              cfg.addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		if cfg.tlsCertFile != "" && cfg.tlsKeyFile != "" {
			log.Printf("%s listening on %s (TLS)", appName, cfg.addr)
			serveErr <- httpServer.ListenAndServeTLS(cfg.tlsCertFile, cfg.tlsKeyFile)
			return
		}
		log.Printf("%s listening on %s", appName, cfg.addr)
		serveErr <- httpServer.ListenAndServe()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server exited with error: %v", err)
		}
	case sig := <-sigCh:
		log.Printf("received %s, shutting down gracefully", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Printf("graceful shutdown error: %v", err)
		}
	}
}

func loadConfig() (config, error) {
	cfg := config{
		addr:         envOrDefault("KMS_LISTEN_ADDR", ":8080"),
		dbConnString: os.Getenv("KMS_DB_URL"),
	}

	expectedAccessKey := os.Getenv("KMS_ACCESS_KEY_ID")
	cfg.expectedAccessKey = expectedAccessKey
	cfg.requireAccessKey = expectedAccessKey != ""
	cfg.secretAccessKey = os.Getenv("KMS_SECRET_ACCESS_KEY")
	cfg.strictSigV4 = strings.EqualFold(envOrDefault("KMS_SIGV4_STRICT", "false"), "true")
	cfg.defaultDenyPolicy = strings.EqualFold(envOrDefault("KMS_POLICY_DEFAULT_DENY", "false"), "true")
	cfg.uiSecureCookies = strings.EqualFold(envOrDefault("KMS_UI_SECURE_COOKIES", "false"), "true")
	cfg.sessionIdleTTL = envDurationOrDefault("KMS_UI_SESSION_IDLE_TTL", 30*time.Minute)
	cfg.sessionAbsTTL = envDurationOrDefault("KMS_UI_SESSION_MAX_TTL", 12*time.Hour)
	cfg.tlsCertFile = os.Getenv("KMS_TLS_CERT_FILE")
	cfg.tlsKeyFile = os.Getenv("KMS_TLS_KEY_FILE")

	cfg.awsRegion = strings.TrimSpace(envOrDefault("KMS_AWS_REGION", defaultAWSRegion))
	cfg.awsAccountID = strings.TrimSpace(os.Getenv("KMS_AWS_ACCOUNT_ID"))

	if hmacKeyB64 := os.Getenv("KMS_AUDIT_HMAC_KEY_B64"); hmacKeyB64 != "" {
		hmacKey, err := base64.StdEncoding.DecodeString(hmacKeyB64)
		if err != nil {
			return config{}, fmt.Errorf("decode KMS_AUDIT_HMAC_KEY_B64: %w", err)
		}
		cfg.auditHMACKey = hmacKey
	}

	masterKeyB64 := os.Getenv("KMS_MASTER_KEY_B64")
	if masterKeyB64 != "" {
		masterKey, err := base64.StdEncoding.DecodeString(masterKeyB64)
		if err != nil {
			return config{}, fmt.Errorf("decode KMS_MASTER_KEY_B64: %w", err)
		}
		if len(masterKey) != 32 {
			return config{}, errors.New("KMS_MASTER_KEY_B64 must decode to exactly 32 bytes")
		}
		cfg.legacyMasterKey = masterKey
		cfg.legacyKeyID = os.Getenv("KMS_KEY_ID")
	}

	wrappingKeyB64 := os.Getenv("KMS_WRAPPING_KEY_B64")
	if wrappingKeyB64 != "" {
		wrappingKey, err := base64.StdEncoding.DecodeString(wrappingKeyB64)
		if err != nil {
			return config{}, fmt.Errorf("decode KMS_WRAPPING_KEY_B64: %w", err)
		}
		if len(wrappingKey) != 32 {
			return config{}, errors.New("KMS_WRAPPING_KEY_B64 must decode to exactly 32 bytes")
		}
		cfg.wrappingKey = wrappingKey
	}
	if len(cfg.wrappingKey) == 0 && len(cfg.legacyMasterKey) == 32 {
		cfg.wrappingKey = deriveWrappingKeyHKDF(cfg.legacyMasterKey)
		// Retain the previous (v1) derivation so key material wrapped before the
		// HKDF upgrade can still be unwrapped.
		cfg.legacyWrappingKey = deriveWrappingKey(cfg.legacyMasterKey)
	}

	if cfg.dbConnString == "" && len(cfg.legacyMasterKey) == 0 {
		return config{}, errors.New("set KMS_DB_URL, or provide legacy KMS_MASTER_KEY_B64")
	}
	if cfg.dbConnString != "" && len(cfg.wrappingKey) != 32 {
		return config{}, errors.New("set KMS_WRAPPING_KEY_B64 (or KMS_MASTER_KEY_B64 for derived wrapping key) when using KMS_DB_URL")
	}

	uiUsers, err := loadUIUsersFromEnv()
	if err != nil {
		return config{}, err
	}
	cfg.uiUsers = uiUsers

	return cfg, nil
}

func buildStore(cfg config) (keyStore, func(), error) {
	if cfg.dbConnString == "" {
		if len(cfg.legacyMasterKey) == 0 {
			return nil, nil, errors.New("legacy key is required when KMS_DB_URL is not set")
		}
		legacyKeyID := strings.TrimSpace(cfg.legacyKeyID)
		if legacyKeyID == "" {
			legacyKeyID = deriveDeterministicLegacyKeyID(cfg.legacyMasterKey)
		}
		region := effectiveRegion(cfg.awsRegion)
		accountID := cfg.awsAccountID
		if !isValidAccountID(accountID) {
			accountID = generateAccountID()
		}
		k := kmsKey{
			ID:           legacyKeyID,
			ARN:          envOrDefault("KMS_KEY_ARN", arnFor("kms", region, accountID, "key/"+legacyKeyID)),
			MasterKeyRaw: cfg.legacyMasterKey,
			Description:  "go-kms key",
			CreatedAt:    time.Now().UTC(),
			Enabled:      true,
		}
		return &inMemoryStore{k: k, auditHMACKey: cfg.auditHMACKey, region: region, accountID: accountID}, func() {}, nil
	}

	db, err := sql.Open("postgres", cfg.dbConnString)
	if err != nil {
		return nil, nil, fmt.Errorf("open postgres connection: %w", err)
	}
	cleanup := func() {
		_ = db.Close()
	}
	if err := db.Ping(); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("ping postgres: %w", err)
	}
	if err := ensureSchema(context.Background(), db); err != nil {
		cleanup()
		return nil, nil, err
	}
	store := &dbStore{db: db, wrappingKey: cfg.wrappingKey, legacyWrappingKey: cfg.legacyWrappingKey, auditHMACKey: cfg.auditHMACKey}
	region, accountID, err := resolveDeploymentIdentity(context.Background(), db, cfg)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("resolve deployment identity: %w", err)
	}
	store.region = region
	store.accountID = accountID
	if err := store.migrateLegacyKeyMaterial(context.Background()); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("migrate legacy key material: %w", err)
	}
	if err := store.migrateResourceARNs(context.Background()); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("migrate resource ARNs: %w", err)
	}
	return store, cleanup, nil
}

func ensureSchema(ctx context.Context, db *sql.DB) error {
	const ddl = `
-- Migrate legacy tenant objects to the account naming (idempotent).
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'ui_tenants')
     AND NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'ui_accounts') THEN
    ALTER TABLE ui_tenants RENAME TO ui_accounts;
  END IF;
END $$;

DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'ui_accounts' AND column_name = 'tenant')
     AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'ui_accounts' AND column_name = 'account') THEN
    ALTER TABLE ui_accounts RENAME COLUMN tenant TO account;
  END IF;
END $$;

DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'ui_users' AND column_name = 'tenants_json')
     AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'ui_users' AND column_name = 'accounts_json') THEN
    ALTER TABLE ui_users RENAME COLUMN tenants_json TO accounts_json;
  END IF;
END $$;

DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'pca_certificate_authorities' AND column_name = 'tenant')
     AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'pca_certificate_authorities' AND column_name = 'account') THEN
    ALTER TABLE pca_certificate_authorities RENAME COLUMN tenant TO account;
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS kms_keys (
  id TEXT PRIMARY KEY,
  arn TEXT NOT NULL UNIQUE,
  master_key_b64 TEXT NOT NULL,
	wrapped_key_b64 TEXT NOT NULL DEFAULT '',
	key_nonce_b64 TEXT NOT NULL DEFAULT '',
	public_key_b64 TEXT NOT NULL DEFAULT '',
	key_usage TEXT NOT NULL DEFAULT 'ENCRYPT_DECRYPT',
	key_spec TEXT NOT NULL DEFAULT 'SYMMETRIC_DEFAULT',
  description TEXT NOT NULL DEFAULT '',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
	deletion_date TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS kms_aliases (
	alias_name TEXT PRIMARY KEY,
	target_key_id TEXT NOT NULL REFERENCES kms_keys(id),
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS kms_settings (
  setting_key TEXT PRIMARY KEY,
  setting_value TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS kms_key_policies (
	key_id TEXT NOT NULL REFERENCES kms_keys(id),
	policy_name TEXT NOT NULL,
	policy_document TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (key_id, policy_name)
);

CREATE TABLE IF NOT EXISTS kms_grants (
	grant_id TEXT PRIMARY KEY,
	grant_token TEXT NOT NULL UNIQUE,
	key_id TEXT NOT NULL REFERENCES kms_keys(id),
	grantee_principal TEXT NOT NULL,
	retiring_principal TEXT NOT NULL DEFAULT '',
	operations_json TEXT NOT NULL,
	grant_name TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS kms_audit_events (
	id BIGSERIAL PRIMARY KEY,
	action TEXT NOT NULL,
	key_id TEXT,
	result TEXT NOT NULL,
	error_type TEXT,
	actor TEXT,
	prev_hash TEXT,
	event_hash TEXT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sm_secrets (
	name TEXT PRIMARY KEY,
	arn TEXT NOT NULL UNIQUE,
	description TEXT NOT NULL DEFAULT '',
	kms_key_id TEXT NOT NULL REFERENCES kms_keys(id),
	current_version_id TEXT NOT NULL,
	previous_version_id TEXT NOT NULL DEFAULT '',
	deleted_date TIMESTAMPTZ,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sm_secret_versions (
	secret_name TEXT NOT NULL REFERENCES sm_secrets(name) ON DELETE CASCADE,
	version_id TEXT NOT NULL,
	client_request_token TEXT NOT NULL,
	encrypted_payload_b64 TEXT NOT NULL,
	is_binary BOOLEAN NOT NULL DEFAULT FALSE,
	version_created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (secret_name, version_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS sm_secret_versions_secret_token_idx
	ON sm_secret_versions (secret_name, client_request_token);

CREATE TABLE IF NOT EXISTS sm_secret_tags (
	secret_name TEXT NOT NULL REFERENCES sm_secrets(name) ON DELETE CASCADE,
	tag_key TEXT NOT NULL,
	tag_value TEXT NOT NULL,
	PRIMARY KEY (secret_name, tag_key)
);

CREATE TABLE IF NOT EXISTS sm_secret_policies (
	secret_name TEXT PRIMARY KEY REFERENCES sm_secrets(name) ON DELETE CASCADE,
	policy_document TEXT NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sm_secret_version_stages (
	secret_name TEXT NOT NULL REFERENCES sm_secrets(name) ON DELETE CASCADE,
	version_id TEXT NOT NULL,
	stage_label TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (secret_name, stage_label)
);

CREATE TABLE IF NOT EXISTS ui_users (
	username TEXT PRIMARY KEY,
	password_hash TEXT NOT NULL,
	role TEXT NOT NULL DEFAULT 'viewer',
	display_name TEXT NOT NULL DEFAULT '',
	accounts_json TEXT NOT NULL DEFAULT '[]',
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ui_accounts (
	account TEXT PRIMARY KEY,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE sm_secrets ADD COLUMN IF NOT EXISTS rotation_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE sm_secrets ADD COLUMN IF NOT EXISTS rotation_lambda_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE sm_secrets ADD COLUMN IF NOT EXISTS rotation_days INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sm_secrets ADD COLUMN IF NOT EXISTS next_rotation_date TIMESTAMPTZ;

ALTER TABLE kms_audit_events ADD COLUMN IF NOT EXISTS prev_hash TEXT;
ALTER TABLE kms_audit_events ADD COLUMN IF NOT EXISTS event_hash TEXT;
ALTER TABLE kms_keys ADD COLUMN IF NOT EXISTS deletion_date TIMESTAMPTZ;
ALTER TABLE kms_keys ADD COLUMN IF NOT EXISTS wrapped_key_b64 TEXT NOT NULL DEFAULT '';
ALTER TABLE kms_keys ADD COLUMN IF NOT EXISTS key_nonce_b64 TEXT NOT NULL DEFAULT '';
ALTER TABLE kms_keys ADD COLUMN IF NOT EXISTS public_key_b64 TEXT NOT NULL DEFAULT '';
ALTER TABLE kms_keys ADD COLUMN IF NOT EXISTS key_usage TEXT NOT NULL DEFAULT 'ENCRYPT_DECRYPT';
ALTER TABLE kms_keys ADD COLUMN IF NOT EXISTS key_spec TEXT NOT NULL DEFAULT 'SYMMETRIC_DEFAULT';

CREATE TABLE IF NOT EXISTS pca_certificate_authorities (
	ca_id TEXT PRIMARY KEY,
	urn TEXT NOT NULL UNIQUE,
	type TEXT NOT NULL DEFAULT 'ROOT',
	kms_key_id TEXT NOT NULL REFERENCES kms_keys(id),
	subject_dn TEXT NOT NULL,
	state TEXT NOT NULL DEFAULT 'CREATING',
	ca_cert_b64 TEXT NOT NULL DEFAULT '',
	path_length INTEGER,
	not_before TIMESTAMPTZ NOT NULL,
	not_after TIMESTAMPTZ NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	account TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS pca_certificates (
	cert_id TEXT PRIMARY KEY,
	ca_id TEXT NOT NULL REFERENCES pca_certificate_authorities(ca_id) ON DELETE CASCADE,
	serial TEXT NOT NULL,
	csr_b64 TEXT NOT NULL DEFAULT '',
	cert_b64 TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT 'ISSUED',
	not_before TIMESTAMPTZ NOT NULL,
	not_after TIMESTAMPTZ NOT NULL,
	revoked_at TIMESTAMPTZ,
	revocation_reason TEXT,
	template TEXT NOT NULL DEFAULT 'EndEntityCertificate',
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS pca_certificates_ca_serial_idx
	ON pca_certificates (ca_id, serial);

CREATE TABLE IF NOT EXISTS pca_ca_policies (
	ca_id TEXT NOT NULL REFERENCES pca_certificate_authorities(ca_id) ON DELETE CASCADE,
	policy_name TEXT NOT NULL,
	policy_document TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (ca_id, policy_name)
);

CREATE TABLE IF NOT EXISTS pca_crl_state (
	ca_id TEXT PRIMARY KEY REFERENCES pca_certificate_authorities(ca_id) ON DELETE CASCADE,
	crl_number BIGINT NOT NULL DEFAULT 1,
	last_generated TIMESTAMPTZ,
	next_update TIMESTAMPTZ,
	crl_b64 TEXT NOT NULL DEFAULT ''
);
`
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("initialize schema: %w", err)
	}
	return nil
}

func maybeBootstrapFromLegacy(ctx context.Context, cfg config, store keyStore) error {
	if len(cfg.legacyMasterKey) == 0 {
		return nil
	}
	legacyKeyID := strings.TrimSpace(cfg.legacyKeyID)
	if legacyKeyID == "" {
		if existing, err := store.ResolveDefault(ctx); err == nil && strings.TrimSpace(existing.ID) != "" {
			legacyKeyID = existing.ID
		} else if cfg.dbConnString == "" {
			legacyKeyID = deriveDeterministicLegacyKeyID(cfg.legacyMasterKey)
		} else {
			legacyKeyID = randomHex(12)
		}
	}
	k := kmsKey{
		ID:           legacyKeyID,
		ARN:          envOrDefault("KMS_KEY_ARN", bootstrapKeyARN(store, legacyKeyID)),
		MasterKeyRaw: cfg.legacyMasterKey,
		Description:  "go-kms key",
		CreatedAt:    time.Now().UTC(),
		Enabled:      true,
		KeyUsage:     keyUsageEncryptDecrypt,
		KeySpec:      keySpecSymmetricDefault,
	}
	if err := store.EnsureBootstrap(ctx, k); err != nil {
		return err
	}
	return nil
}

// bootstrapKeyARN builds the ARN for the bootstrap key using the store's
// deployment identity.
func bootstrapKeyARN(store keyStore, keyID string) string {
	region, accountID := store.DeploymentIdentity()
	return arnFor("kms", region, accountID, "key/"+keyID)
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAWSJSONError(w, http.StatusMethodNotAllowed, "InvalidAction", "method not allowed")
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *server) handleKMS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAWSJSONError(w, http.StatusMethodNotAllowed, "InvalidAction", "method not allowed")
		return
	}
	if s.cfg.strictSigV4 {
		if err := validateSigV4Request(r); err != nil {
			writeAWSJSONError(w, http.StatusForbidden, "IncompleteSignature", "request signature is invalid")
			return
		}
		// When a secret access key is configured, verify the signature
		// cryptographically rather than only checking header presence.
		if s.cfg.secretAccessKey != "" {
			bodyHash, err := drainAndHashBody(r, 1<<20)
			if err != nil {
				writeAWSJSONError(w, http.StatusBadRequest, "InvalidSignatureException", "request signature is invalid")
				return
			}
			if err := verifyAWSV4Signature(r, bodyHash, s.cfg.secretAccessKey); err != nil {
				log.Printf("sigv4 verification failed: %v", err)
				writeAWSJSONError(w, http.StatusForbidden, "InvalidSignatureException", "request signature is invalid")
				return
			}
		}
	}

	if s.cfg.requireAccessKey {
		if !hasAccessKey(r.Header.Get("Authorization"), s.cfg.expectedAccessKey) {
			writeAWSJSONError(w, http.StatusForbidden, "UnrecognizedClientException", "invalid access key")
			return
		}
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
	default:
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidAction", "unsupported X-Amz-Target")
	}
}

func (s *server) handleGetKeyPolicy(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.GetKeyPolicy"
	var req getKeyPolicyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		return
	}
	if req.KeyID == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "KeyId is required")
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		return
	}
	if req.PolicyName == "" {
		req.PolicyName = "default"
	}
	key, err := s.store.ResolveByID(r.Context(), req.KeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key or policy not found")
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:GetKeyPolicy"); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		return
	}
	doc, err := s.store.GetKeyPolicy(r.Context(), req.KeyID, req.PolicyName)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key or policy not found")
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, getKeyPolicyResponse{Policy: doc})
}

func (s *server) handlePutKeyPolicy(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.PutKeyPolicy"
	var req putKeyPolicyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		return
	}
	if req.KeyID == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "KeyId is required")
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		return
	}
	if req.PolicyName == "" {
		req.PolicyName = "default"
	}
	if strings.TrimSpace(req.Policy) == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "Policy is required")
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		return
	}
	normalizedPolicy, err := normalizePolicyDocument(req.Policy)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "MalformedPolicyDocumentException", "Policy must be valid JSON")
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "MalformedPolicyDocumentException", Actor: r.RemoteAddr})
		return
	}
	key, err := s.store.ResolveByID(r.Context(), req.KeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key not found")
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:PutKeyPolicy"); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		return
	}
	if err := s.store.PutKeyPolicy(r.Context(), req.KeyID, req.PolicyName, normalizedPolicy); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key not found")
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *server) handleEncrypt(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.Encrypt"
	var req encryptRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if req.Plaintext == "" {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "Plaintext is required")
		return
	}

	var (
		key kmsKey
		err error
	)
	if req.KeyID != "" {
		key, err = s.store.ResolveByID(r.Context(), req.KeyID)
	} else {
		key, err = s.store.ResolveDefault(r.Context())
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
			writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "unknown key id")
			return
		}
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "key lookup failed")
		return
	}
	if keyUsage, _ := keyUsageAndSpecForMetadata(key); keyUsage != keyUsageEncryptDecrypt {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "InvalidKeyUsageException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidKeyUsageException", "key does not support encryption")
		return
	}
	if keyUsage, _ := keyUsageAndSpecForMetadata(key); keyUsage != keyUsageEncryptDecrypt {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "InvalidKeyUsageException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidKeyUsageException", "key does not support decryption")
		return
	}
	if !key.Enabled {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "DisabledException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "DisabledException", "key is disabled")
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:Encrypt"); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		return
	}

	plaintext, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "Plaintext must be base64")
		return
	}

	cipherBlob, err := encryptBlob(key.MasterKeyRaw, key.ID, plaintext, canonicalContext(req.EncryptionContext))
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "encrypt failed")
		return
	}

	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "ok", Actor: r.RemoteAddr})

	writeJSON(w, http.StatusOK, encryptResponse{
		CiphertextBlob:    base64.StdEncoding.EncodeToString(cipherBlob),
		KeyID:             key.ID,
		EncryptionContext: req.EncryptionContext,
	})
}

func (s *server) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.Decrypt"
	var req decryptRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if req.CiphertextBlob == "" {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "CiphertextBlob is required")
		return
	}

	cipherBlob, err := base64.StdEncoding.DecodeString(req.CiphertextBlob)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "CiphertextBlob must be base64")
		return
	}

	keyID, rawBlob, err := decodeCipherBlob(cipherBlob)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "InvalidCiphertextException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidCiphertextException", "decrypt failed")
		return
	}

	var key kmsKey
	if keyID == "" {
		key, err = s.store.ResolveDefault(r.Context())
	} else {
		key, err = s.store.ResolveByID(r.Context(), keyID)
	}
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: keyID, Result: "error", ErrorType: "InvalidCiphertextException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidCiphertextException", "decrypt failed")
		return
	}
	if !key.Enabled {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "DisabledException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "DisabledException", "key is disabled")
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:Decrypt"); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		return
	}

	plaintext, err := decryptBlob(key.MasterKeyRaw, rawBlob, canonicalContext(req.EncryptionContext))
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "InvalidCiphertextException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidCiphertextException", "decrypt failed")
		return
	}

	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "ok", Actor: r.RemoteAddr})

	writeJSON(w, http.StatusOK, decryptResponse{
		KeyID:             key.ID,
		Plaintext:         base64.StdEncoding.EncodeToString(plaintext),
		EncryptionContext: req.EncryptionContext,
	})
}

func (s *server) handleDescribeKey(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.DescribeKey"
	var req describeKeyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}

	var (
		key kmsKey
		err error
	)
	if req.KeyID != "" {
		key, err = s.store.ResolveByID(r.Context(), req.KeyID)
	} else {
		key, err = s.store.ResolveDefault(r.Context())
	}
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "unknown key id")
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:DescribeKey"); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		return
	}

	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "ok", Actor: r.RemoteAddr})

	writeJSON(w, http.StatusOK, describeKeyResponse{
		KeyMetadata: toKeyMetadata(key),
	})
}

func (s *server) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.CreateKey"
	var req createKeyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	key, err := s.store.CreateKey(r.Context(), req.Description, req.KeyUsage, req.KeySpec)
	if err != nil {
		errType := "DependencyTimeoutException"
		if errors.Is(err, errUnsupported) {
			errType = "UnsupportedOperationException"
			writeAWSJSONError(w, http.StatusBadRequest, errType, "CreateKey requires KMS_DB_URL")
		} else {
			writeAWSJSONError(w, http.StatusInternalServerError, errType, "create key failed")
		}
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: errType, Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, createKeyResponse{KeyMetadata: toKeyMetadata(key)})
}

func (s *server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.ListKeys"
	var req listKeysRequest
	if err := decodeOptionalJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	limit, err := normalizeListLimit(req.Limit)
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	keys, err := s.store.ListKeys(r.Context())
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "list keys failed")
		return
	}
	out := make([]listKeyEntry, 0, len(keys))
	for _, k := range keys {
		out = append(out, listKeyEntry{KeyID: k.ID, KeyARN: k.ARN})
	}
	out, nextMarker, truncated, err := paginateList(out, req.Marker, limit, func(item listKeyEntry) string { return item.KeyID })
	if err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, listKeysResponse{Keys: out, NextMarker: nextMarker, Truncated: truncated})
}

func (s *server) handleCreateAlias(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.CreateAlias"
	var req createAliasRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if req.AliasName == "" || req.TargetKeyID == "" {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", "AliasName and TargetKeyId are required")
		return
	}
	key, err := s.store.ResolveByID(r.Context(), req.TargetKeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "target key not found or alias exists")
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.TargetKeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:CreateAlias"); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		return
	}
	if err := s.store.CreateAlias(r.Context(), req.AliasName, req.TargetKeyID); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "target key not found or alias exists")
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.TargetKeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.TargetKeyID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *server) handleUpdateAlias(w http.ResponseWriter, r *http.Request) {
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
	key, err := s.store.ResolveByID(r.Context(), req.TargetKeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "alias or key not found")
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.TargetKeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:UpdateAlias"); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		return
	}
	if err := s.store.UpdateAlias(r.Context(), req.AliasName, req.TargetKeyID); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "alias or key not found")
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.TargetKeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.TargetKeyID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *server) handleListAliases(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.ListAliases"
	var req listAliasesRequest
	if err := decodeOptionalJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		return
	}
	limit, err := normalizeListLimit(req.Limit)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		return
	}
	aliases, err := s.store.ListAliases(r.Context())
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "list aliases failed")
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		return
	}
	out := make([]aliasEntry, 0, len(aliases))
	for _, a := range aliases {
		out = append(out, aliasEntry{AliasName: a.AliasName, TargetKeyID: a.TargetKeyID})
	}
	out, nextMarker, truncated, err := paginateList(out, req.Marker, limit, func(item aliasEntry) string { return item.AliasName })
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, listAliasesResponse{Aliases: out, NextMarker: nextMarker, Truncated: truncated})
}

func (s *server) handleSetKeyEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
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
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	policyAction := "kms:DisableKey"
	if enabled {
		policyAction = "kms:EnableKey"
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, policyAction); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		return
	}
	if err := s.store.SetKeyEnabled(r.Context(), req.KeyID, enabled); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key not found")
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *server) handleScheduleKeyDeletion(w http.ResponseWriter, r *http.Request) {
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
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:ScheduleKeyDeletion"); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		return
	}
	deletionDate, err := s.store.ScheduleKeyDeletion(r.Context(), req.KeyID, req.PendingWindowInDays)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key not found")
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, scheduleKeyDeletionResponse{KeyID: req.KeyID, DeletionDate: deletionDate})
}

func (s *server) handleCancelKeyDeletion(w http.ResponseWriter, r *http.Request) {
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
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:CancelKeyDeletion"); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		return
	}
	if err := s.store.CancelKeyDeletion(r.Context(), req.KeyID); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "key not found")
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "ok", Actor: r.RemoteAddr})
	key, err = s.store.ResolveByID(r.Context(), req.KeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "reload key failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"KeyMetadata": toKeyMetadata(key)})
}

func (s *server) handleCreateGrant(w http.ResponseWriter, r *http.Request) {
	const action = "TrentService.CreateGrant"
	var req createGrantRequest
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
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:CreateGrant"); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		return
	}
	grant, err := s.store.CreateGrant(r.Context(), req)
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "create grant failed")
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, createGrantResponse{GrantID: grant.GrantID, GrantToken: grant.GrantToken})
}

func (s *server) handleListGrants(w http.ResponseWriter, r *http.Request) {
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
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:ListGrants"); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		return
	}
	grants, err := s.store.ListGrants(r.Context(), req.KeyID)
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "DependencyTimeoutException", "list grants failed")
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "DependencyTimeoutException", Actor: r.RemoteAddr})
		return
	}
	out := make([]grantListEntry, 0, len(grants))
	for _, grant := range grants {
		out = append(out, grantListEntry{GrantID: grant.GrantID, KeyID: grant.KeyID, GranteePrincipal: grant.GranteePrincipal, RetiringPrincipal: grant.RetiringPrincipal, Operations: append([]string(nil), grant.Operations...), Name: grant.Name, CreationDate: grant.CreatedAt})
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, listGrantsResponse{Grants: out})
}

func (s *server) handleRevokeGrant(w http.ResponseWriter, r *http.Request) {
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
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: req.KeyID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	if err := s.authorizeKeyAction(r.Context(), r, key, "kms:RevokeGrant"); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", "access denied by key policy")
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "AccessDeniedException", Actor: r.RemoteAddr})
		return
	}
	if err := s.store.RevokeGrant(r.Context(), req.KeyID, req.GrantID); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "NotFoundException", "grant not found")
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: key.ID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *server) handleRetireGrant(w http.ResponseWriter, r *http.Request) {
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
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "NotFoundException", Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, map[string]any{})
}

func keyState(key kmsKey) string {
	if key.DeletionDate != nil {
		return "PendingDeletion"
	}
	if key.Enabled {
		return "Enabled"
	}
	return "Disabled"
}

func toKeyMetadata(key kmsKey) keyMetadata {
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

func keyEncryptionAlgorithms(key kmsKey) []string {
	usage, _ := keyUsageAndSpecForMetadata(key)
	if usage != keyUsageEncryptDecrypt {
		return nil
	}
	return []string{keySpecSymmetricDefault}
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

func validateSigV4Request(r *http.Request) error {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return errors.New("missing Authorization header")
	}
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		return errors.New("unsupported authorization algorithm")
	}
	for _, part := range []string{"Credential=", "SignedHeaders=", "Signature="} {
		if !strings.Contains(auth, part) {
			return fmt.Errorf("authorization header missing %s", strings.TrimSuffix(part, "="))
		}
	}
	if r.Header.Get("X-Amz-Date") == "" {
		return errors.New("missing X-Amz-Date header")
	}
	if r.Header.Get("X-Amz-Target") == "" {
		return errors.New("missing X-Amz-Target header")
	}
	return nil
}

func (s *server) recordAudit(ctx context.Context, event auditEvent) {
	if err := s.store.RecordAudit(ctx, event); err != nil {
		log.Printf("audit write failed action=%s key=%s: %v", event.Action, event.KeyID, err)
	}
}

func (s *dbStore) ResolveByID(ctx context.Context, keyID string) (kmsKey, error) {
	if strings.HasPrefix(keyID, "alias/") {
		var target string
		if err := s.db.QueryRowContext(ctx, `SELECT target_key_id FROM kms_aliases WHERE alias_name = $1`, keyID).Scan(&target); err != nil {
			return kmsKey{}, err
		}
		keyID = target
	}
	const q = `
	SELECT id, arn, master_key_b64, wrapped_key_b64, key_nonce_b64, public_key_b64, key_usage, key_spec, description, enabled, deletion_date, created_at
FROM kms_keys
WHERE id = $1
`
	var (
		k            kmsKey
		masterB64    string
		wrappedB64   string
		nonceB64     string
		publicB64    string
		keyUsage     string
		keySpec      string
		deletionDate sql.NullTime
	)
	err := s.db.QueryRowContext(ctx, q, keyID).Scan(&k.ID, &k.ARN, &masterB64, &wrappedB64, &nonceB64, &publicB64, &keyUsage, &keySpec, &k.Description, &k.Enabled, &deletionDate, &k.CreatedAt)
	if err != nil {
		return kmsKey{}, err
	}
	if deletionDate.Valid {
		k.DeletionDate = &deletionDate.Time
	}
	k.KeyUsage = normalizeKeyUsage(keyUsage)
	if k.KeyUsage == "" {
		k.KeyUsage = keyUsageEncryptDecrypt
	}
	k.KeySpec = strings.ToUpper(strings.TrimSpace(keySpec))
	if k.KeySpec == "" {
		k.KeySpec = defaultKeySpecForUsage(k.KeyUsage)
	}
	if publicB64 != "" {
		k.PublicKeyRaw, err = base64.StdEncoding.DecodeString(publicB64)
		if err != nil {
			return kmsKey{}, err
		}
	}
	k.MasterKeyRaw, err = s.resolveKeyMaterial(ctx, k.ID, masterB64, wrappedB64, nonceB64)
	if err != nil {
		return kmsKey{}, fmt.Errorf("load key material for %s: %w", k.ID, err)
	}
	return k, nil
}

func (s *dbStore) ResolveDefault(ctx context.Context) (kmsKey, error) {
	const keyBySetting = `
SELECT setting_value
FROM kms_settings
WHERE setting_key = 'default_key_id'
`
	var keyID string
	err := s.db.QueryRowContext(ctx, keyBySetting).Scan(&keyID)
	if err == nil {
		return s.ResolveByID(ctx, keyID)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return kmsKey{}, err
	}

	const fallback = `
SELECT id
FROM kms_keys
WHERE enabled = TRUE
ORDER BY created_at ASC
LIMIT 1
`
	err = s.db.QueryRowContext(ctx, fallback).Scan(&keyID)
	if err != nil {
		return kmsKey{}, err
	}
	return s.ResolveByID(ctx, keyID)
}

func (s *dbStore) EnsureBootstrap(ctx context.Context, k kmsKey) error {
	wrappedB64, nonceB64, err := s.wrapKeyMaterial(k.ID, k.MasterKeyRaw)
	if err != nil {
		return fmt.Errorf("wrap bootstrap key material: %w", err)
	}
	const upsertKey = `
INSERT INTO kms_keys (id, arn, master_key_b64, wrapped_key_b64, key_nonce_b64, public_key_b64, key_usage, key_spec, description, enabled, created_at)
VALUES ($1, $2, '', $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (id) DO NOTHING
`
	if _, err := s.db.ExecContext(ctx, upsertKey, k.ID, k.ARN, wrappedB64, nonceB64, base64.StdEncoding.EncodeToString(k.PublicKeyRaw), k.KeyUsage, k.KeySpec, k.Description, k.Enabled, k.CreatedAt); err != nil {
		return fmt.Errorf("bootstrap key row: %w", err)
	}

	const upsertDefault = `
INSERT INTO kms_settings (setting_key, setting_value)
VALUES ('default_key_id', $1)
ON CONFLICT (setting_key) DO NOTHING
`
	if _, err := s.db.ExecContext(ctx, upsertDefault, k.ID); err != nil {
		return fmt.Errorf("bootstrap default key setting: %w", err)
	}
	return nil
}

func (s *dbStore) CreateKey(ctx context.Context, description, keyUsage, keySpec string) (kmsKey, error) {
	raw, publicRaw, normalizedUsage, normalizedSpec, err := generateKeyMaterial(keyUsage, keySpec)
	if err != nil {
		return kmsKey{}, err
	}
	id := randomHex(12)
	k := kmsKey{
		ID:           id,
		ARN:          s.keyARN(id),
		MasterKeyRaw: raw,
		PublicKeyRaw: publicRaw,
		Description:  description,
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
		KeyUsage:     normalizedUsage,
		KeySpec:      normalizedSpec,
	}
	wrappedB64, nonceB64, err := s.wrapKeyMaterial(k.ID, k.MasterKeyRaw)
	if err != nil {
		return kmsKey{}, err
	}
	const q = `
INSERT INTO kms_keys (id, arn, master_key_b64, wrapped_key_b64, key_nonce_b64, public_key_b64, key_usage, key_spec, description, enabled, deletion_date, created_at)
VALUES ($1, $2, '', $3, $4, $5, $6, $7, $8, $9, NULL, $10)
`
	if _, err := s.db.ExecContext(ctx, q, k.ID, k.ARN, wrappedB64, nonceB64, base64.StdEncoding.EncodeToString(publicRaw), k.KeyUsage, k.KeySpec, k.Description, k.Enabled, k.CreatedAt); err != nil {
		return kmsKey{}, err
	}
	return k, nil
}

// ImportSigningKey persists externally supplied asymmetric key material as a
// SIGN_VERIFY key. The private key must be PKCS#8 DER and the public key PKIX
// DER; both are stored using the same wrapping path as generated keys.
func (s *dbStore) ImportSigningKey(ctx context.Context, description string, privPKCS8DER, pubPKIXDER []byte, keySpec string) (kmsKey, error) {
	normalizedSpec, err := normalizeKeySpec(keyUsageSignVerify, keySpec)
	if err != nil {
		return kmsKey{}, err
	}
	id := randomHex(12)
	k := kmsKey{
		ID:           id,
		ARN:          s.keyARN(id),
		MasterKeyRaw: privPKCS8DER,
		PublicKeyRaw: pubPKIXDER,
		Description:  description,
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
		KeyUsage:     keyUsageSignVerify,
		KeySpec:      normalizedSpec,
	}
	wrappedB64, nonceB64, err := s.wrapKeyMaterial(k.ID, k.MasterKeyRaw)
	if err != nil {
		return kmsKey{}, err
	}
	const q = `
INSERT INTO kms_keys (id, arn, master_key_b64, wrapped_key_b64, key_nonce_b64, public_key_b64, key_usage, key_spec, description, enabled, deletion_date, created_at)
VALUES ($1, $2, '', $3, $4, $5, $6, $7, $8, $9, NULL, $10)
`
	if _, err := s.db.ExecContext(ctx, q, k.ID, k.ARN, wrappedB64, nonceB64, base64.StdEncoding.EncodeToString(pubPKIXDER), k.KeyUsage, k.KeySpec, k.Description, k.Enabled, k.CreatedAt); err != nil {
		return kmsKey{}, err
	}
	return k, nil
}

func (s *dbStore) ListKeys(ctx context.Context) ([]kmsKey, error) {
	const q = `
	SELECT id, arn, master_key_b64, wrapped_key_b64, key_nonce_b64, public_key_b64, key_usage, key_spec, description, enabled, deletion_date, created_at
FROM kms_keys
ORDER BY created_at ASC
`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]kmsKey, 0)
	for rows.Next() {
		var (
			k            kmsKey
			masterB64    string
			wrappedB64   string
			nonceB64     string
			publicB64    string
			keyUsage     string
			keySpec      string
			deletionDate sql.NullTime
		)
		if err := rows.Scan(&k.ID, &k.ARN, &masterB64, &wrappedB64, &nonceB64, &publicB64, &keyUsage, &keySpec, &k.Description, &k.Enabled, &deletionDate, &k.CreatedAt); err != nil {
			return nil, err
		}
		if deletionDate.Valid {
			k.DeletionDate = &deletionDate.Time
		}
		k.KeyUsage = normalizeKeyUsage(keyUsage)
		if k.KeyUsage == "" {
			k.KeyUsage = keyUsageEncryptDecrypt
		}
		k.KeySpec = strings.ToUpper(strings.TrimSpace(keySpec))
		if k.KeySpec == "" {
			k.KeySpec = defaultKeySpecForUsage(k.KeyUsage)
		}
		if publicB64 != "" {
			k.PublicKeyRaw, err = base64.StdEncoding.DecodeString(publicB64)
			if err != nil {
				return nil, err
			}
		}
		k.MasterKeyRaw, err = s.resolveKeyMaterial(ctx, k.ID, masterB64, wrappedB64, nonceB64)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *dbStore) GetKeyPolicy(ctx context.Context, keyID, policyName string) (string, error) {
	if policyName == "" {
		policyName = "default"
	}
	key, err := s.ResolveByID(ctx, keyID)
	if err != nil {
		return "", err
	}
	const q = `
SELECT policy_document
FROM kms_key_policies
WHERE key_id = $1 AND policy_name = $2
`
	var doc string
	err = s.db.QueryRowContext(ctx, q, key.ID, policyName).Scan(&doc)
	if errors.Is(err, sql.ErrNoRows) {
		return defaultKeyPolicy(key), nil
	}
	if err != nil {
		return "", err
	}
	return doc, nil
}

func (s *dbStore) PutKeyPolicy(ctx context.Context, keyID, policyName, policyDocument string) error {
	if policyName == "" {
		policyName = "default"
	}
	key, err := s.ResolveByID(ctx, keyID)
	if err != nil {
		return err
	}
	const q = `
INSERT INTO kms_key_policies (key_id, policy_name, policy_document)
VALUES ($1, $2, $3)
ON CONFLICT (key_id, policy_name)
DO UPDATE SET policy_document = EXCLUDED.policy_document, updated_at = NOW()
`
	_, err = s.db.ExecContext(ctx, q, key.ID, policyName, policyDocument)
	return err
}

func (s *dbStore) CreateAlias(ctx context.Context, aliasName, keyID string) error {
	const q = `
INSERT INTO kms_aliases (alias_name, target_key_id)
VALUES ($1, $2)
`
	_, err := s.db.ExecContext(ctx, q, aliasName, keyID)
	return err
}

func (s *dbStore) UpdateAlias(ctx context.Context, aliasName, keyID string) error {
	const q = `
UPDATE kms_aliases
SET target_key_id = $2, updated_at = NOW()
WHERE alias_name = $1
`
	res, err := s.db.ExecContext(ctx, q, aliasName, keyID)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *dbStore) ListAliases(ctx context.Context) ([]kmsAlias, error) {
	const q = `
SELECT alias_name, target_key_id
FROM kms_aliases
ORDER BY alias_name ASC
`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]kmsAlias, 0)
	for rows.Next() {
		var a kmsAlias
		if err := rows.Scan(&a.AliasName, &a.TargetKeyID); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *dbStore) SetKeyEnabled(ctx context.Context, keyID string, enabled bool) error {
	const q = `UPDATE kms_keys SET enabled = $2, updated_at = NOW() WHERE id = $1`
	res, err := s.db.ExecContext(ctx, q, keyID, enabled)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *dbStore) ScheduleKeyDeletion(ctx context.Context, keyID string, windowDays int) (time.Time, error) {
	deletionDate := time.Now().UTC().Add(time.Duration(windowDays) * 24 * time.Hour)
	const q = `UPDATE kms_keys SET deletion_date = $2, updated_at = NOW() WHERE id = $1`
	res, err := s.db.ExecContext(ctx, q, keyID, deletionDate)
	if err != nil {
		return time.Time{}, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return time.Time{}, err
	}
	if rows == 0 {
		return time.Time{}, sql.ErrNoRows
	}
	return deletionDate, nil
}

func (s *dbStore) CancelKeyDeletion(ctx context.Context, keyID string) error {
	const q = `UPDATE kms_keys SET deletion_date = NULL, updated_at = NOW() WHERE id = $1`
	res, err := s.db.ExecContext(ctx, q, keyID)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *dbStore) ForceDeleteKey(ctx context.Context, keyID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM kms_aliases WHERE target_key_id = $1`, keyID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM kms_key_policies WHERE key_id = $1`, keyID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM kms_grants WHERE key_id = $1`, keyID); err != nil {
		return err
	}

	res, err := tx.ExecContext(ctx, `DELETE FROM kms_keys WHERE id = $1`, keyID)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "foreign key") {
			return fmt.Errorf("key is in use and cannot be force deleted")
		}
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}

	return tx.Commit()
}

func (s *dbStore) CreateGrant(ctx context.Context, req createGrantRequest) (kmsGrant, error) {
	grant := kmsGrant{
		GrantID:           "grant-" + randomHex(12),
		GrantToken:        randomHex(16),
		KeyID:             req.KeyID,
		GranteePrincipal:  strings.TrimSpace(req.GranteePrincipal),
		RetiringPrincipal: strings.TrimSpace(req.RetiringPrincipal),
		Operations:        append([]string(nil), req.Operations...),
		Name:              strings.TrimSpace(req.Name),
		CreatedAt:         time.Now().UTC(),
	}
	operationsJSON, err := json.Marshal(grant.Operations)
	if err != nil {
		return kmsGrant{}, err
	}
	const q = `
INSERT INTO kms_grants (grant_id, grant_token, key_id, grantee_principal, retiring_principal, operations_json, grant_name, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
`
	if _, err := s.db.ExecContext(ctx, q, grant.GrantID, grant.GrantToken, grant.KeyID, grant.GranteePrincipal, grant.RetiringPrincipal, string(operationsJSON), grant.Name, grant.CreatedAt); err != nil {
		return kmsGrant{}, err
	}
	return grant, nil
}

func (s *dbStore) ListGrants(ctx context.Context, keyID string) ([]kmsGrant, error) {
	const q = `
SELECT grant_id, grant_token, key_id, grantee_principal, retiring_principal, operations_json, grant_name, created_at
FROM kms_grants
WHERE key_id = $1
ORDER BY created_at ASC
`
	rows, err := s.db.QueryContext(ctx, q, keyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]kmsGrant, 0)
	for rows.Next() {
		var grant kmsGrant
		var operationsJSON string
		if err := rows.Scan(&grant.GrantID, &grant.GrantToken, &grant.KeyID, &grant.GranteePrincipal, &grant.RetiringPrincipal, &operationsJSON, &grant.Name, &grant.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(operationsJSON), &grant.Operations); err != nil {
			return nil, err
		}
		out = append(out, grant)
	}
	return out, rows.Err()
}

func (s *dbStore) RevokeGrant(ctx context.Context, keyID, grantID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM kms_grants WHERE key_id = $1 AND grant_id = $2`, keyID, grantID)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *dbStore) RetireGrant(ctx context.Context, grantID, grantToken string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM kms_grants WHERE grant_id = $1 OR grant_token = $2`, grantID, grantToken)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *dbStore) RecordAudit(ctx context.Context, event auditEvent) error {
	var prevHash sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT event_hash FROM kms_audit_events ORDER BY id DESC LIMIT 1`).Scan(&prevHash); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	prev := ""
	if prevHash.Valid {
		prev = prevHash.String
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	eventHash := hashAuditRecord(s.auditHMACKey, prev, event, now)
	const q = `
INSERT INTO kms_audit_events (action, key_id, result, error_type, actor, prev_hash, event_hash, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
`
	_, err := s.db.ExecContext(ctx, q, event.Action, event.KeyID, event.Result, event.ErrorType, event.Actor, prev, eventHash, now)
	return err
}

func (s *dbStore) ListAuditEvents(ctx context.Context, limit int) ([]auditRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	const q = `
SELECT id, action, COALESCE(key_id, ''), result, COALESCE(error_type, ''), COALESCE(actor, ''), COALESCE(prev_hash, ''), COALESCE(event_hash, ''), created_at
FROM kms_audit_events
ORDER BY id DESC
LIMIT $1
`
	rows, err := s.db.QueryContext(ctx, q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]auditRecord, 0, limit)
	for rows.Next() {
		var entry auditRecord
		if err := rows.Scan(&entry.ID, &entry.Action, &entry.KeyID, &entry.Result, &entry.ErrorType, &entry.Actor, &entry.PrevHash, &entry.EventHash, &entry.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, rows.Err()
}

func (s *inMemoryStore) ResolveByID(_ context.Context, keyID string) (kmsKey, error) {
	for _, key := range s.keysSnapshot() {
		if keyID == "" || keyID == key.ID {
			return key, nil
		}
	}
	return kmsKey{}, sql.ErrNoRows
}

func (s *inMemoryStore) ResolveDefault(_ context.Context) (kmsKey, error) {
	keys := s.keysSnapshot()
	if len(keys) == 0 {
		return kmsKey{}, sql.ErrNoRows
	}
	return keys[0], nil
}

func (s *inMemoryStore) EnsureBootstrap(_ context.Context, _ kmsKey) error {
	return nil
}

func (s *inMemoryStore) CreateKey(_ context.Context, _ string, _ string, _ string) (kmsKey, error) {
	return kmsKey{}, errUnsupported
}

func (s *inMemoryStore) ImportSigningKey(_ context.Context, _ string, _, _ []byte, _ string) (kmsKey, error) {
	return kmsKey{}, errUnsupported
}

func (s *inMemoryStore) ListKeys(_ context.Context) ([]kmsKey, error) {
	return s.keysSnapshot(), nil
}

func (s *inMemoryStore) GetKeyPolicy(_ context.Context, keyID, policyName string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if keyID != "" && keyID != s.k.ID {
		return "", sql.ErrNoRows
	}
	if policyName == "" {
		policyName = "default"
	}
	if s.policies == nil {
		s.policies = map[string]string{}
	}
	if doc, ok := s.policies[policyName]; ok {
		return doc, nil
	}
	return defaultKeyPolicy(s.k), nil
}

func (s *inMemoryStore) PutKeyPolicy(_ context.Context, keyID, policyName, policyDocument string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if keyID != "" && keyID != s.k.ID {
		return sql.ErrNoRows
	}
	if policyName == "" {
		policyName = "default"
	}
	if s.policies == nil {
		s.policies = map[string]string{}
	}
	s.policies[policyName] = policyDocument
	return nil
}

func (s *inMemoryStore) CreateAlias(_ context.Context, _, _ string) error {
	return errUnsupported
}

func (s *inMemoryStore) UpdateAlias(_ context.Context, _, _ string) error {
	return errUnsupported
}

func (s *inMemoryStore) ListAliases(_ context.Context) ([]kmsAlias, error) {
	if len(s.aliases) == 0 {
		return nil, nil
	}
	out := make([]kmsAlias, len(s.aliases))
	copy(out, s.aliases)
	return out, nil
}

func (s *inMemoryStore) keysSnapshot() []kmsKey {
	if len(s.keys) == 0 {
		if strings.TrimSpace(s.k.ID) == "" {
			return nil
		}
		return []kmsKey{s.k}
	}
	out := make([]kmsKey, len(s.keys))
	copy(out, s.keys)
	return out
}

func (s *inMemoryStore) SetKeyEnabled(_ context.Context, _ string, _ bool) error {
	return errUnsupported
}

func (s *inMemoryStore) ScheduleKeyDeletion(_ context.Context, _ string, _ int) (time.Time, error) {
	return time.Time{}, errUnsupported
}

func (s *inMemoryStore) CancelKeyDeletion(_ context.Context, _ string) error {
	return errUnsupported
}

func (s *inMemoryStore) ForceDeleteKey(_ context.Context, _ string) error {
	return errUnsupported
}

func (s *inMemoryStore) CreateGrant(_ context.Context, req createGrantRequest) (kmsGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	grant := kmsGrant{
		GrantID:           "grant-" + randomHex(12),
		GrantToken:        randomHex(16),
		KeyID:             req.KeyID,
		GranteePrincipal:  strings.TrimSpace(req.GranteePrincipal),
		RetiringPrincipal: strings.TrimSpace(req.RetiringPrincipal),
		Operations:        append([]string(nil), req.Operations...),
		Name:              strings.TrimSpace(req.Name),
		CreatedAt:         time.Now().UTC(),
	}
	s.grants = append(s.grants, grant)
	return grant, nil
}

func (s *inMemoryStore) ListGrants(_ context.Context, keyID string) ([]kmsGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]kmsGrant, 0)
	for _, grant := range s.grants {
		if grant.KeyID == keyID {
			grantCopy := grant
			grantCopy.Operations = append([]string(nil), grant.Operations...)
			out = append(out, grantCopy)
		}
	}
	return out, nil
}

func (s *inMemoryStore) RevokeGrant(_ context.Context, keyID, grantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, grant := range s.grants {
		if grant.KeyID == keyID && grant.GrantID == grantID {
			s.grants = append(s.grants[:i], s.grants[i+1:]...)
			return nil
		}
	}
	return sql.ErrNoRows
}

func (s *inMemoryStore) RetireGrant(_ context.Context, grantID, grantToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, grant := range s.grants {
		if (grantID != "" && grant.GrantID == grantID) || (grantToken != "" && grant.GrantToken == grantToken) {
			s.grants = append(s.grants[:i], s.grants[i+1:]...)
			return nil
		}
	}
	return sql.ErrNoRows
}

func (s *inMemoryStore) RecordAudit(_ context.Context, event auditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditSeq++
	createdAt := time.Now().UTC()
	entry := auditRecord{ID: s.auditSeq, Action: event.Action, KeyID: event.KeyID, Result: event.Result, ErrorType: event.ErrorType, Actor: event.Actor, CreatedAt: createdAt}
	if len(s.audit) > 0 {
		entry.PrevHash = s.audit[len(s.audit)-1].EventHash
	}
	entry.EventHash = hashAuditRecord(s.auditHMACKey, entry.PrevHash, event, createdAt.Format(time.RFC3339Nano))
	s.audit = append(s.audit, entry)
	return nil
}

func (s *inMemoryStore) ListAuditEvents(_ context.Context, limit int) ([]auditRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	if len(s.audit) == 0 {
		return nil, nil
	}
	items := make([]auditRecord, len(s.audit))
	copy(items, s.audit)
	sort.Slice(items, func(i, j int) bool {
		return items[i].ID > items[j].ID
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func (s *dbStore) resolveKeyMaterial(ctx context.Context, keyID, masterB64, wrappedB64, nonceB64 string) ([]byte, error) {
	if strings.TrimSpace(wrappedB64) != "" && strings.TrimSpace(nonceB64) != "" {
		return s.unwrapKeyMaterial(keyID, wrappedB64, nonceB64)
	}
	if strings.TrimSpace(masterB64) == "" {
		return nil, errors.New("missing key material")
	}
	raw, err := base64.StdEncoding.DecodeString(masterB64)
	if err != nil {
		return nil, err
	}
	wrapped, nonce, err := s.wrapKeyMaterial(keyID, raw)
	if err != nil {
		return nil, err
	}
	if err := s.persistWrappedKeyMaterial(ctx, keyID, wrapped, nonce); err != nil {
		log.Printf("key migration warning key=%s: %v", keyID, err)
	}
	return raw, nil
}

func (s *dbStore) wrapKeyMaterial(keyID string, raw []byte) (string, string, error) {
	if len(s.wrappingKey) != 32 {
		return "", "", errors.New("wrapping key is not configured")
	}
	block, err := aes.NewCipher(s.wrappingKey)
	if err != nil {
		return "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", err
	}
	// Bind the key ID as additional authenticated data so a wrapped blob cannot
	// be transplanted onto a different key row.
	sealed := gcm.Seal(nil, nonce, raw, []byte(keyID))
	return base64.StdEncoding.EncodeToString(sealed), base64.StdEncoding.EncodeToString(nonce), nil
}

func (s *dbStore) unwrapKeyMaterial(keyID, wrappedB64, nonceB64 string) ([]byte, error) {
	if len(s.wrappingKey) != 32 {
		return nil, errors.New("wrapping key is not configured")
	}
	wrapped, err := base64.StdEncoding.DecodeString(wrappedB64)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, err
	}
	// Try the current key with AAD, then legacy combinations so material wrapped
	// before AAD binding / the HKDF derivation upgrade still decrypts.
	candidates := []struct {
		key []byte
		aad []byte
	}{
		{s.wrappingKey, []byte(keyID)},
		{s.wrappingKey, nil},
	}
	if len(s.legacyWrappingKey) == 32 {
		candidates = append(candidates,
			struct {
				key []byte
				aad []byte
			}{s.legacyWrappingKey, []byte(keyID)},
			struct {
				key []byte
				aad []byte
			}{s.legacyWrappingKey, nil},
		)
	}
	var lastErr error
	for _, c := range candidates {
		block, err := aes.NewCipher(c.key)
		if err != nil {
			lastErr = err
			continue
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			lastErr = err
			continue
		}
		if out, err := gcm.Open(nil, nonce, wrapped, c.aad); err == nil {
			return out, nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("unwrap failed")
	}
	return nil, lastErr
}

func (s *dbStore) persistWrappedKeyMaterial(ctx context.Context, keyID, wrappedB64, nonceB64 string) error {
	const q = `
UPDATE kms_keys
SET wrapped_key_b64 = $2, key_nonce_b64 = $3, master_key_b64 = '', updated_at = NOW()
WHERE id = $1
`
	_, err := s.db.ExecContext(ctx, q, keyID, wrappedB64, nonceB64)
	return err
}

func (s *dbStore) migrateLegacyKeyMaterial(ctx context.Context) error {
	const q = `
SELECT id, master_key_b64
FROM kms_keys
WHERE master_key_b64 <> '' AND wrapped_key_b64 = '' AND key_nonce_b64 = ''
`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return err
	}
	defer rows.Close()

	type row struct {
		id        string
		masterB64 string
	}
	legacy := make([]row, 0)
	for rows.Next() {
		var item row
		if err := rows.Scan(&item.id, &item.masterB64); err != nil {
			return err
		}
		legacy = append(legacy, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, item := range legacy {
		raw, err := base64.StdEncoding.DecodeString(item.masterB64)
		if err != nil {
			return fmt.Errorf("decode legacy key %s: %w", item.id, err)
		}
		wrapped, nonce, err := s.wrapKeyMaterial(item.id, raw)
		if err != nil {
			return fmt.Errorf("wrap legacy key %s: %w", item.id, err)
		}
		if err := s.persistWrappedKeyMaterial(ctx, item.id, wrapped, nonce); err != nil {
			return fmt.Errorf("persist wrapped key %s: %w", item.id, err)
		}
	}

	if len(legacy) > 0 {
		log.Printf("migrated %d legacy key rows to wrapped storage", len(legacy))
	}
	return nil
}

func withRequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s target=%s", r.Method, r.URL.Path, r.Header.Get("X-Amz-Target"))
		next.ServeHTTP(w, r)
	})
}

func hasAccessKey(authHeader, accessKey string) bool {
	if accessKey == "" {
		return true
	}
	needle := "Credential=" + accessKey + "/"
	return strings.Contains(authHeader, needle)
}

func canonicalContext(ctx map[string]string) []byte {
	if len(ctx) == 0 {
		return nil
	}
	keys := make([]string, 0, len(ctx))
	for k := range ctx {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(ctx[k])
		b.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return sum[:]
}

func encryptBlob(masterKey []byte, keyID string, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	raw := make([]byte, 0, len(nonce)+len(ciphertext))
	raw = append(raw, nonce...)
	raw = append(raw, ciphertext...)
	return encodeCipherBlob(keyID, raw), nil
}

func encryptLegacyBlob(masterKey, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	out := make([]byte, 0, len(nonce)+len(ciphertext))
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

func decryptBlob(masterKey, blob, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(blob) <= nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce := blob[:nonceSize]
	ciphertext := blob[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, aad)
}

func decodeCipherBlob(blob []byte) (string, []byte, error) {
	if len(blob) < 2 || blob[0] != cipherBlobVersionV1 {
		return "", blob, nil
	}
	keyLen := int(blob[1])
	if len(blob) < 2+keyLen {
		return "", blob, nil
	}
	keyID := string(blob[2 : 2+keyLen])
	raw := blob[2+keyLen:]
	if len(raw) < 12+16 {
		return "", blob, nil
	}
	return keyID, raw, nil
}

func encodeCipherBlob(keyID string, raw []byte) []byte {
	if keyID == "" {
		return raw
	}
	keyBytes := []byte(keyID)
	if len(keyBytes) > 255 {
		return raw
	}
	out := make([]byte, 0, 2+len(keyBytes)+len(raw))
	out = append(out, cipherBlobVersionV1)
	out = append(out, byte(len(keyBytes)))
	out = append(out, keyBytes...)
	out = append(out, raw...)
	return out
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

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envDurationOrDefault(key string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Printf("invalid duration for %s=%q, using default %s", key, v, fallback)
		return fallback
	}
	return d
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// hashAuditRecord computes the chain hash for an audit record. When key is
// non-empty it produces an HMAC-SHA256 (authenticity: an attacker with DB write
// access cannot forge a valid chain without the key); otherwise it falls back to
// a plain SHA-256 chain (integrity only).
func hashAuditRecord(key []byte, prevHash string, event auditEvent, ts string) string {
	payload := []byte(strings.Join([]string{prevHash, event.Action, event.KeyID, event.Result, event.ErrorType, event.Actor, ts}, "|"))
	if len(key) > 0 {
		mac := hmac.New(sha256.New, key)
		mac.Write(payload)
		return hex.EncodeToString(mac.Sum(nil))
	}
	h := sha256.Sum256(payload)
	return hex.EncodeToString(h[:])
}

func deriveDeterministicLegacyKeyID(masterKey []byte) string {
	sum := sha256.Sum256(masterKey)
	return hex.EncodeToString(sum[:8])
}

func deriveWrappingKey(legacyMasterKey []byte) []byte {
	seed := append([]byte("go-kms-wrap-v1|"), legacyMasterKey...)
	sum := sha256.Sum256(seed)
	out := make([]byte, 32)
	copy(out, sum[:])
	return out
}

func compareSecret(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (s *server) authorizeKeyAction(ctx context.Context, r *http.Request, key kmsKey, action string) error {
	policy, err := s.store.GetKeyPolicy(ctx, key.ID, "default")
	if err != nil {
		return err
	}
	allowed, err := policyAllows(policy, requestPrincipal(r), action, key.ARN, s.cfg.defaultDenyPolicy)
	if err != nil {
		return err
	}
	if !allowed {
		return errAccessDenied
	}
	return nil
}

func requestPrincipal(r *http.Request) string {
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

func defaultKeyPolicy(key kmsKey) string {
	policy := map[string]any{
		"Version": "2012-10-17",
		"Id":      "go-kms-default-policy-" + key.ID,
		"Statement": []map[string]any{
			{
				"Sid":       "EnableRootPermissions",
				"Effect":    "Allow",
				"Principal": "*",
				"Action":    "kms:*",
				"Resource":  "*",
			},
		},
	}
	b, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}
