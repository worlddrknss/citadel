// Package config loads Citadel's configuration from KMS_* environment
// variables and checks that it is safe to run with.
package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/arn"
	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// Config is the process configuration, read once at startup by Load.
type Config struct {
	Addr              string
	DBConnString      string
	ExpectedAccessKey string
	SecretAccessKey   string
	// InsecureDev disables every authentication check (AWS SigV4, console
	// login). Local development only; set with KMS_INSECURE_DEV=true.
	InsecureDev       bool
	DefaultDenyPolicy bool
	WrappingKey       []byte
	LegacyWrappingKey []byte
	AuditHMACKey      []byte
	UIUsers           map[string]store.UIUser
	UISecureCookies   bool
	SessionIdleTTL    time.Duration
	SessionAbsTTL     time.Duration
	TLSCertFile       string
	TLSKeyFile        string

	AWSRegion    string
	AWSAccountID string

	LegacyKeyID     string
	LegacyMasterKey []byte
	// LegacyKeyARN overrides the ARN of the bootstrapped legacy key
	// (KMS_KEY_ARN); empty means derive it from the deployment identity.
	LegacyKeyARN string

	// PprofAddr enables the loopback pprof listener (KMS_PPROF_ADDR).
	PprofAddr string
}

// MinSecretAccessKeyLen is the shortest static secret accepted. See Load.
const MinSecretAccessKeyLen = 20

// CheckSecurityPosture refuses configurations that would leave Citadel open.
// Outside insecure dev mode the console needs at least one user, and the AWS
// APIs need a source of credentials to verify signatures against.
func CheckSecurityPosture(cfg Config, dbBacked bool) error {
	if cfg.InsecureDev {
		return nil
	}
	if len(cfg.UIUsers) == 0 {
		return errors.New("no console users are configured: set KMS_UI_USERS_JSON or KMS_UI_PASSWORD (or KMS_INSECURE_DEV=true for local development)")
	}
	if !dbBacked && cfg.ExpectedAccessKey == "" {
		return errors.New("the in-memory store has no access keys: set KMS_ACCESS_KEY_ID and KMS_SECRET_ACCESS_KEY, use KMS_DB_URL, or set KMS_INSECURE_DEV=true for local development")
	}
	return nil
}

// Load reads the configuration from the environment and validates it.
func Load() (Config, error) {
	cfg := Config{
		Addr:         envOrDefault("KMS_LISTEN_ADDR", ":8080"),
		DBConnString: os.Getenv("KMS_DB_URL"),
	}

	cfg.ExpectedAccessKey = strings.TrimSpace(os.Getenv("KMS_ACCESS_KEY_ID"))
	cfg.SecretAccessKey = os.Getenv("KMS_SECRET_ACCESS_KEY")
	if (cfg.ExpectedAccessKey == "") != (cfg.SecretAccessKey == "") {
		return Config{}, errors.New("KMS_ACCESS_KEY_ID and KMS_SECRET_ACCESS_KEY must be set together")
	}
	// SigV4's first HMAC key is "AWS4"+secret. FIPS 140-3 forbids HMAC keys
	// under 112 bits, so a short secret would fail every request; AWS-issued
	// and Citadel-issued secrets are 40 characters.
	if cfg.SecretAccessKey != "" && len(cfg.SecretAccessKey) < MinSecretAccessKeyLen {
		return Config{}, fmt.Errorf("KMS_SECRET_ACCESS_KEY must be at least %d characters", MinSecretAccessKeyLen)
	}
	cfg.InsecureDev = strings.EqualFold(os.Getenv("KMS_INSECURE_DEV"), "true")
	if v := os.Getenv("KMS_SIGV4_STRICT"); v != "" {
		log.Printf("warning: KMS_SIGV4_STRICT is no longer read; SigV4 is always verified unless KMS_INSECURE_DEV=true")
	}
	cfg.DefaultDenyPolicy = strings.EqualFold(envOrDefault("KMS_POLICY_DEFAULT_DENY", "false"), "true")
	// Session cookies are Secure unless explicitly turned off, or in insecure
	// dev mode where the console is usually served over plain http://localhost.
	secureDefault := "true"
	if cfg.InsecureDev {
		secureDefault = "false"
	}
	cfg.UISecureCookies = strings.EqualFold(envOrDefault("KMS_UI_SECURE_COOKIES", secureDefault), "true")
	cfg.SessionIdleTTL = envDurationOrDefault("KMS_UI_SESSION_IDLE_TTL", 30*time.Minute)
	cfg.SessionAbsTTL = envDurationOrDefault("KMS_UI_SESSION_MAX_TTL", 12*time.Hour)
	cfg.TLSCertFile = os.Getenv("KMS_TLS_CERT_FILE")
	cfg.TLSKeyFile = os.Getenv("KMS_TLS_KEY_FILE")
	cfg.PprofAddr = strings.TrimSpace(os.Getenv("KMS_PPROF_ADDR"))

	cfg.AWSRegion = strings.TrimSpace(envOrDefault("KMS_AWS_REGION", arn.DefaultRegion))
	cfg.AWSAccountID = strings.TrimSpace(os.Getenv("KMS_AWS_ACCOUNT_ID"))

	if hmacKeyB64 := os.Getenv("KMS_AUDIT_HMAC_KEY_B64"); hmacKeyB64 != "" {
		hmacKey, err := base64.StdEncoding.DecodeString(hmacKeyB64)
		if err != nil {
			return Config{}, fmt.Errorf("decode KMS_AUDIT_HMAC_KEY_B64: %w", err)
		}
		cfg.AuditHMACKey = hmacKey
	}

	masterKeyB64 := os.Getenv("KMS_MASTER_KEY_B64")
	if masterKeyB64 != "" {
		masterKey, err := base64.StdEncoding.DecodeString(masterKeyB64)
		if err != nil {
			return Config{}, fmt.Errorf("decode KMS_MASTER_KEY_B64: %w", err)
		}
		if len(masterKey) != 32 {
			return Config{}, errors.New("KMS_MASTER_KEY_B64 must decode to exactly 32 bytes")
		}
		cfg.LegacyMasterKey = masterKey
		cfg.LegacyKeyID = os.Getenv("KMS_KEY_ID")
		cfg.LegacyKeyARN = os.Getenv("KMS_KEY_ARN")
	}

	wrappingKeyB64 := os.Getenv("KMS_WRAPPING_KEY_B64")
	if wrappingKeyB64 != "" {
		wrappingKey, err := base64.StdEncoding.DecodeString(wrappingKeyB64)
		if err != nil {
			return Config{}, fmt.Errorf("decode KMS_WRAPPING_KEY_B64: %w", err)
		}
		if len(wrappingKey) != 32 {
			return Config{}, errors.New("KMS_WRAPPING_KEY_B64 must decode to exactly 32 bytes")
		}
		cfg.WrappingKey = wrappingKey
	}
	if len(cfg.WrappingKey) == 0 && len(cfg.LegacyMasterKey) == 32 {
		cfg.WrappingKey = cryptoutil.DeriveWrappingKeyHKDF(cfg.LegacyMasterKey)
		// Retain the previous (v1) derivation so key material wrapped before the
		// HKDF upgrade can still be unwrapped.
		cfg.LegacyWrappingKey = cryptoutil.DeriveWrappingKey(cfg.LegacyMasterKey)
	}

	if cfg.DBConnString == "" && len(cfg.LegacyMasterKey) == 0 {
		return Config{}, errors.New("set KMS_DB_URL, or provide legacy KMS_MASTER_KEY_B64")
	}
	if cfg.DBConnString != "" && len(cfg.WrappingKey) != 32 {
		return Config{}, errors.New("set KMS_WRAPPING_KEY_B64 (or KMS_MASTER_KEY_B64 for derived wrapping key) when using KMS_DB_URL")
	}

	uiUsers, err := loadUIUsersFromEnv()
	if err != nil {
		return Config{}, err
	}
	cfg.UIUsers = uiUsers

	return cfg, nil
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

func loadUIUsersFromEnv() (map[string]store.UIUser, error) {
	if raw := strings.TrimSpace(os.Getenv("KMS_UI_USERS_JSON")); raw != "" {
		var users []store.UIUser
		if err := json.Unmarshal([]byte(raw), &users); err != nil {
			return nil, errors.New("decode KMS_UI_USERS_JSON: invalid JSON")
		}
		return normalizeUIUsers(users)
	}
	password := os.Getenv("KMS_UI_PASSWORD")
	if strings.TrimSpace(password) == "" {
		return nil, nil
	}
	return normalizeUIUsers([]store.UIUser{{
		Username:    envOrDefault("KMS_UI_USERNAME", "admin"),
		Password:    password,
		Role:        envOrDefault("KMS_UI_ROLE", "admin"),
		DisplayName: envOrDefault("KMS_UI_DISPLAY_NAME", "Admin"),
		Accounts:    splitCommaList(envOrDefault("KMS_UI_ACCOUNTS", os.Getenv("KMS_UI_TENANTS"))),
	}})
}

func normalizeUIUsers(users []store.UIUser) (map[string]store.UIUser, error) {
	out := make(map[string]store.UIUser, len(users))
	for _, user := range users {
		user.Username = strings.TrimSpace(user.Username)
		user.Password = strings.TrimSpace(user.Password)
		user.PasswordHash = strings.TrimSpace(user.PasswordHash)
		user.Role = store.NormalizeUIRole(user.Role)
		if user.DisplayName == "" {
			user.DisplayName = user.Username
		}
		user.Accounts = store.NormalizeAccounts(user.Accounts)
		if user.Username == "" || (user.Password == "" && user.PasswordHash == "") {
			return nil, errors.New("ui users require username and password (or passwordHash)")
		}
		out[user.Username] = user
	}
	return out, nil
}

func splitCommaList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return strings.Split(raw, ",")
}
