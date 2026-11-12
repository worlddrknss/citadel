// Package server is Citadel's HTTP server: routing, middleware and the
// handlers for the AWS-compatible APIs (KMS, Secrets Manager, SSM Parameter
// Store, ACM, ACM PCA, STS), the ACME endpoints and the native /v1 API used by
// the web console. Handlers are grouped into files by service.
package server

import (
	"context"
	"errors"
	"fmt"
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

// AppName is the user-facing product name used in logs and UI.
const AppName = "Citadel"

var (
	errAccessDenied = errors.New("access denied")
)

// Server serves Citadel's APIs from a store.Store. Build one with New.
type Server struct {
	cfg            config.Config
	store          store.Store
	acmeChallenges *acmeChallengeStore
	// acmeHTTPClient, when set, is used by the Let's Encrypt ACME client. It
	// allows trusting a private or test ACME CA (e.g. Pebble). When nil the
	// default HTTP client (public trust store) is used.
	acmeHTTPClient *http.Client
	// pki holds the ACME server and its state, built on first use.
	pki pkiRuntime
	// webFS is the built web console served under /app/; nil when absent.
	webFS fs.FS

	secretsOnce sync.Once
	secretsSvcV *secretsService

	authOnce sync.Once
	authV    *authState
	// jobs runs periodic background jobs; see jobRunner. Nil in servers
	// built without New.
	jobs *jobRunner

	audit auditRuntime
	obs   observabilityRuntime
}

// secretsSvc returns the shared protocol-free secrets service, lazily binding
// it to the server's store on first use.
func (s *Server) secretsSvc() *secretsService {
	s.secretsOnce.Do(func() {
		s.secretsSvcV = newSecretsService(s.store)
	})
	return s.secretsSvcV
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
	envUsers := make(map[string]store.UIUser, len(cfg.UIUsers))
	for name, u := range cfg.UIUsers {
		envUsers[name] = u
	}
	if mergedUsers, err := mergeDBUIUsers(ctx, st, cfg.UIUsers); err != nil {
		log.Printf("warning: failed to load admin users from database: %v", err)
	} else {
		cfg.UIUsers = mergedUsers
	}

	_, dbBacked := st.(*postgres.Store)
	posture, err := config.CheckSecurityPosture(cfg, dbBacked)
	if err != nil {
		return nil, fmt.Errorf("refusing to start: %w", err)
	}
	if cfg.InsecureDev {
		log.Printf("WARNING: KMS_INSECURE_DEV=true — authentication is DISABLED. Never use this outside local development.")
	}

	s := &Server{cfg: cfg, store: st, acmeChallenges: newACMEChallengeStore(), webFS: webFS, jobs: newJobRunner()}
	s.authV = newAuthState()
	s.authV.envUsers = envUsers
	if len(cfg.UIUsers) > 0 {
		s.authV.bootstrapped.Store(true)
	}
	if posture.Bootstrap {
		log.Printf("No console users exist: %s is in bootstrap mode and its API is closed until setup completes. Open %s to create the organization and the first admin.", AppName, bootstrapURL(cfg))
		s.initBootstrapToken()
	}
	s.jobs.Every("console-session-purge", 10*time.Minute, s.purgeExpiredSessions)
	s.jobs.Every("sts-session-purge", 15*time.Minute, s.purgeExpiredSTSSessions)
	s.jobs.Every("secrets-purge", secretsPurgeInterval, s.purgeExpiredSecretsJob)
	s.startAuditStreamJob()
	return s, nil
}

// Start runs the server's background jobs until ctx is cancelled.
func (s *Server) Start(ctx context.Context) { s.jobs.Start(ctx) }

// Wait blocks until the background jobs have stopped after the Start
// context was cancelled.
func (s *Server) Wait() { s.jobs.Wait() }

// bootstrapURL is the console URL logged in bootstrap mode.
func bootstrapURL(cfg config.Config) string {
	scheme := "http"
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		scheme = "https"
	}
	host := cfg.Addr
	if strings.HasPrefix(host, ":") {
		host = "localhost" + host
	}
	return scheme + "://" + host + "/app/"
}

// handler returns the HTTP handler serving every route, wrapped in the
// middleware chain.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)

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
	s.registerKMSRoutes(mux)
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
	s.registerAuditRoutes(mux)
	mux.HandleFunc("GET /v1/change-requests", s.handleV1ListChangeRequests)
	mux.HandleFunc("POST /v1/change-requests", s.handleV1CreateChangeRequest)
	mux.HandleFunc("POST /v1/change-requests/approve", s.handleV1ApproveChangeRequest)
	mux.HandleFunc("POST /v1/change-requests/reject", s.handleV1RejectChangeRequest)
	s.registerSecretsRoutes(mux)

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

	s.registerAuthRoutes(mux)
	s.registerIdentityRoutes(mux)

	// Modern Svelte single-page control plane, embedded into the binary.
	mux.Handle("/app/", http.HandlerFunc(s.handleApp))
	mux.Handle("/app", http.RedirectHandler("/app/", http.StatusMovedPermanently))

	// PKI: ACME server (RFC 8555), ACME settings and EAB keys, generated-key issuance.
	s.registerPKIRoutes(mux)

	// Public HTTP-01 validation endpoint for the Let's Encrypt ACME *client*.
	// Must be reachable unauthenticated so the ACME CA can verify domain control.
	mux.HandleFunc("GET /.well-known/acme-challenge/{token}", s.handleACMEChallengeToken)

	// Public CRL distribution point. Certificate Revocation Lists are intended
	// to be fetched anonymously by relying parties, so this is served
	// unauthenticated in binary DER form at the conventional .crl path.
	mux.HandleFunc("GET /crl/{ca_id}", s.handleCRLDownload)

	// Middleware chain (outermost first): panic recovery, security headers,
	// request logging, audit context, CSRF checks, the bootstrap-mode gate.
	return withPanicRecovery(s.withSecurityHeaders(s.withObservability(s.withAuditContext(s.withCSRFProtection(s.withBootstrapGate(mux))))))
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
