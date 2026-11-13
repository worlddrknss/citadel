package citadel

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// ---- Parameters -------------------------------------------------------------

// Parameter types and tiers.
const (
	ParameterString       = "String"
	ParameterStringList   = "StringList"
	ParameterSecureString = "SecureString"
	TierStandard          = "Standard"
	TierAdvanced          = "Advanced"
)

// Parameter describes a parameter. Listings include Value for String and
// StringList parameters, never for SecureString.
type Parameter struct {
	Name         string    `json:"name"`
	Type         string    `json:"type"`
	Tier         string    `json:"tier"`
	Version      int64     `json:"version"`
	Description  string    `json:"description"`
	KMSKeyID     string    `json:"kmsKeyId,omitempty"`
	LastModified time.Time `json:"lastModified"`
	Value        string    `json:"value,omitempty"`
}

// ListParameters returns every parameter in the key's account.
func (c *Client) ListParameters(ctx context.Context) ([]Parameter, error) {
	var out struct {
		Parameters []Parameter `json:"parameters"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/parameters", nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Parameters, nil
}

// GetParameter returns a parameter and its value, SecureString values
// decrypted. version 0 means the latest. Revealing a SecureString follows
// the same viewer rule as GetSecret.
func (c *Client) GetParameter(ctx context.Context, name string, version int64) (*Parameter, error) {
	q := url.Values{"name": {name}}
	if version > 0 {
		q.Set("version", strconv.FormatInt(version, 10))
	}
	var out struct {
		Parameter Parameter `json:"parameter"`
		Value     string    `json:"value"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/parameters/value", q, nil, &out); err != nil {
		return nil, err
	}
	out.Parameter.Value = out.Value
	return &out.Parameter, nil
}

// PutParameterInput is a parameter to create or overwrite.
type PutParameterInput struct {
	Name string `json:"name"`
	// Type defaults to String.
	Type  string `json:"type,omitempty"`
	Value string `json:"value"`
	// KMSKeyID is the key for SecureString values (default: the account
	// default key).
	KMSKeyID string `json:"kmsKeyId,omitempty"`
	// Tier defaults to Standard (4 KB values); Advanced allows 8 KB.
	Tier        string `json:"tier,omitempty"`
	Description string `json:"description,omitempty"`
	// Overwrite must be true to replace an existing parameter; otherwise
	// the call fails with already_exists.
	Overwrite bool `json:"overwrite,omitempty"`
}

// PutParameter creates or (with Overwrite) replaces a parameter.
func (c *Client) PutParameter(ctx context.Context, in PutParameterInput) (*Parameter, error) {
	var out struct {
		Parameter Parameter `json:"parameter"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/parameters", nil, in, &out); err != nil {
		return nil, err
	}
	return &out.Parameter, nil
}

// DeleteParameter deletes a parameter and its history.
func (c *Client) DeleteParameter(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, "/v1/parameters", url.Values{"name": {name}}, nil, nil)
}

// ParameterVersion is one entry in a parameter's history.
type ParameterVersion struct {
	Name        string    `json:"name"`
	Version     int64     `json:"version"`
	Type        string    `json:"type"`
	Tier        string    `json:"tier"`
	Description string    `json:"description"`
	Labels      []string  `json:"labels"`
	ModifiedAt  time.Time `json:"modifiedAt"`
}

// ParameterHistory returns a parameter's versions (values not included).
func (c *Client) ParameterHistory(ctx context.Context, name string) ([]ParameterVersion, error) {
	var out struct {
		History []ParameterVersion `json:"history"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/parameters/history", url.Values{"name": {name}}, nil, &out); err != nil {
		return nil, err
	}
	return out.History, nil
}

// ---- KMS --------------------------------------------------------------------

// Key is a KMS key.
type Key struct {
	KeyID        string     `json:"keyId"`
	ARN          string     `json:"arn"`
	Description  string     `json:"description"`
	Enabled      bool       `json:"enabled"`
	KeyUsage     string     `json:"keyUsage"`
	KeySpec      string     `json:"keySpec"`
	CreatedAt    time.Time  `json:"createdAt"`
	DeletionDate *time.Time `json:"deletionDate,omitempty"`
	Aliases      []string   `json:"aliases"`
	// Managed marks the account's immutable default key.
	Managed bool   `json:"managed"`
	Origin  string `json:"origin"`
}

// ListKeys returns the KMS keys in the key's account.
func (c *Client) ListKeys(ctx context.Context) ([]Key, error) {
	var out struct {
		Keys []Key `json:"keys"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/kms/keys", nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Keys, nil
}

// EncryptOutput is the result of Encrypt.
type EncryptOutput struct {
	KeyID               string `json:"keyId"`
	CiphertextBlob      []byte `json:"ciphertextBlob"`
	EncryptionAlgorithm string `json:"encryptionAlgorithm"`
}

// Encrypt encrypts plaintext (at most 4 KB) under keyID (an ID, ARN or
// "alias/name"). encryptionContext, when non-nil, must be passed again to
// Decrypt. Requires the editor role.
func (c *Client) Encrypt(ctx context.Context, keyID string, plaintext []byte, encryptionContext map[string]string) (*EncryptOutput, error) {
	body := map[string]any{"keyId": keyID, "plaintext": plaintext}
	if encryptionContext != nil {
		body["encryptionContext"] = encryptionContext
	}
	var out EncryptOutput
	if err := c.do(ctx, http.MethodPost, "/v1/kms/encrypt", nil, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Decrypt decrypts a ciphertext from Encrypt. Unlike AWS KMS, keyID is
// required.
func (c *Client) Decrypt(ctx context.Context, keyID string, ciphertext []byte, encryptionContext map[string]string) ([]byte, error) {
	body := map[string]any{"keyId": keyID, "ciphertextBlob": ciphertext}
	if encryptionContext != nil {
		body["encryptionContext"] = encryptionContext
	}
	var out struct {
		Plaintext []byte `json:"plaintext"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/kms/decrypt", nil, body, &out); err != nil {
		return nil, err
	}
	return out.Plaintext, nil
}

// ---- Certificates -----------------------------------------------------------

// Certificate sources, as returned in CertificateSummary.Source.
const (
	SourceCA          = "pca-ca"
	SourceCertificate = "pca-cert"
	SourceLetsEncrypt = "lets-encrypt"
)

// CertificateSummary is one row of ListCertificates: a private CA, a
// certificate it issued, or a Let's Encrypt certificate.
type CertificateSummary struct {
	Source       string     `json:"source"`
	ID           string     `json:"id"`
	Subject      string     `json:"subject"`
	CommonName   string     `json:"commonName,omitempty"`
	Serial       string     `json:"serial,omitempty"`
	KeyAlgorithm string     `json:"keyAlgorithm,omitempty"`
	Status       string     `json:"status"`
	NotBefore    *time.Time `json:"notBefore,omitempty"`
	NotAfter     *time.Time `json:"notAfter,omitempty"`
	CAType       string     `json:"caType,omitempty"`
	ParentCAID   string     `json:"parentCaId,omitempty"`
	IssuerCAID   string     `json:"issuerCaId,omitempty"`
	Template     string     `json:"template,omitempty"`
	RevokedAt    *time.Time `json:"revokedAt,omitempty"`
	IsCA         bool       `json:"isCA,omitempty"`
	ExpiringSoon bool       `json:"expiringSoon"`
}

// ListCertificates returns CAs, issued certificates and Let's Encrypt
// certificates (no PEM; see GetCertificate).
func (c *Client) ListCertificates(ctx context.Context) ([]CertificateSummary, error) {
	var out struct {
		Certificates []CertificateSummary `json:"certificates"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/certificates", nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Certificates, nil
}

// Certificate is a certificate's detail, including its PEM.
type Certificate struct {
	Source             string     `json:"source"`
	ID                 string     `json:"id"`
	Status             string     `json:"status"`
	Subject            string     `json:"subject"`
	Issuer             string     `json:"issuer"`
	Serial             string     `json:"serial"`
	NotBefore          *time.Time `json:"notBefore,omitempty"`
	NotAfter           *time.Time `json:"notAfter,omitempty"`
	KeyAlgorithm       string     `json:"keyAlgorithm,omitempty"`
	SignatureAlgorithm string     `json:"signatureAlgorithm,omitempty"`
	SANs               []string   `json:"sans,omitempty"`
	IsCA               bool       `json:"isCA"`
	Template           string     `json:"template,omitempty"`
	RevokedAt          *time.Time `json:"revokedAt,omitempty"`
	RevocationReason   string     `json:"revocationReason,omitempty"`
	PEM                string     `json:"pem,omitempty"`
	// ChainPEM is the issuing CA's certificate.
	ChainPEM string `json:"chainPem,omitempty"`
}

// GetCertificate returns one certificate; source is a Source constant.
func (c *Client) GetCertificate(ctx context.Context, source, id string) (*Certificate, error) {
	var out Certificate
	if err := c.do(ctx, http.MethodGet, "/v1/certificates/detail", url.Values{"source": {source}, "id": {id}}, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// IssueCertificateInput signs a CSR with a private CA.
type IssueCertificateInput struct {
	// CA is the CA's ID or ARN.
	CA     string `json:"caArn"`
	CSRPEM string `json:"csrPem"`
	// ValidityDays is 1-3650 (default 365).
	ValidityDays int `json:"validityDays,omitempty"`
	// OverrideCommonName replaces the CSR's common name.
	OverrideCommonName string `json:"overrideCommonName,omitempty"`
	// SANNames is a comma, semicolon or space separated list of DNS
	// names and IP addresses.
	SANNames string `json:"sanNames,omitempty"`
	// Template is "server" (default) or "client".
	Template string `json:"template,omitempty"`
}

// IssueCertificate signs a CSR and returns the issued certificate (fetched
// with GetCertificate after issuance). Requires the editor role.
func (c *Client) IssueCertificate(ctx context.Context, in IssueCertificateInput) (*Certificate, error) {
	var out struct {
		CertID string `json:"certId"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/certificates/issue", nil, in, &out); err != nil {
		return nil, err
	}
	return c.GetCertificate(ctx, SourceCertificate, out.CertID)
}

// Key algorithms for IssueGeneratedCertificate.
const (
	KeyECP256  = "EC_prime256v1"
	KeyECP384  = "EC_secp384r1"
	KeyRSA2048 = "RSA_2048"
	KeyRSA3072 = "RSA_3072"
	KeyRSA4096 = "RSA_4096"
)

// IssueGeneratedCertificateInput has Citadel generate the key pair.
type IssueGeneratedCertificateInput struct {
	CAID         string   `json:"caId"`
	CommonName   string   `json:"commonName,omitempty"`
	SANs         []string `json:"sans,omitempty"`
	KeyAlgorithm string   `json:"keyAlgorithm"`
	Template     string   `json:"template,omitempty"`
	ValidityDays int      `json:"validityDays,omitempty"`
}

// GeneratedCertificate holds a new certificate and its private key, which
// the server returns only this once.
type GeneratedCertificate struct {
	CertID         string `json:"certId"`
	CertificatePEM string `json:"certificatePem"`
	ChainPEM       string `json:"chainPem"`
	// PrivateKeyPEM is PKCS#8.
	PrivateKeyPEM string `json:"privateKeyPem"`
}

// IssueGeneratedCertificate issues a certificate for a key pair Citadel
// generates. Requires the editor role.
func (c *Client) IssueGeneratedCertificate(ctx context.Context, in IssueGeneratedCertificateInput) (*GeneratedCertificate, error) {
	var out GeneratedCertificate
	if err := c.do(ctx, http.MethodPost, "/v1/certificates/issue/generate", nil, in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Workload identity ------------------------------------------------------

// WorkloadTokenInput requests an OIDC ID token for a workload identity
// client that authenticates with access keys.
type WorkloadTokenInput struct {
	ClientID string `json:"clientId"`
	Audience string `json:"audience"`
	// TTL is rounded down to seconds; zero uses the client's default. At
	// most one hour.
	TTL time.Duration `json:"-"`
}

// WorkloadToken is a signed OIDC ID token (JWT).
type WorkloadToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
	TokenType string    `json:"tokenType"`
}

// IssueWorkloadToken mints an ID token for the client, authenticating with
// this client's access key; the key's owner must be one of the client's
// allowed users.
func (c *Client) IssueWorkloadToken(ctx context.Context, in WorkloadTokenInput) (*WorkloadToken, error) {
	body := map[string]any{"clientId": in.ClientID, "audience": in.Audience}
	if secs := int(in.TTL / time.Second); secs > 0 {
		body["ttlSeconds"] = secs
	}
	var out WorkloadToken
	if err := c.do(ctx, http.MethodPost, "/v1/workload-identity/token", nil, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
