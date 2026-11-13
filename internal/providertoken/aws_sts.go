package providertoken

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/sigv4"
)

// DefaultSTSEndpoint is AWS's global STS endpoint.
const DefaultSTSEndpoint = "https://sts.amazonaws.com/"

// AssumeRole duration bounds (AWS's; the role's own maximum may be lower).
const (
	MinSTSDuration     = 15 * time.Minute
	MaxSTSDuration     = 12 * time.Hour
	DefaultSTSDuration = time.Hour
)

// maxSessionPolicyBytes is AWS's limit on the plaintext inline session
// policy.
const maxSessionPolicyBytes = 2048

// AWSCredentials are AWS access keys. SessionToken is set for temporary
// credentials. Expiration is zero for long-term keys.
type AWSCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

// String redacts the secret parts.
func (c AWSCredentials) String() string {
	return "providertoken.AWSCredentials{AccessKeyID:" + c.AccessKeyID + ", SecretAccessKey:" + redacted + "}"
}

// GoString redacts the secret parts under %#v.
func (c AWSCredentials) GoString() string { return c.String() }

// ProcessJSON renders the credentials in the AWS CLI credential_process
// format (Version 1), the Value of an aws_sts Token.
func (c AWSCredentials) ProcessJSON() (string, error) {
	doc := struct {
		Version         int    `json:"Version"`
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		SessionToken    string `json:"SessionToken,omitempty"`
		Expiration      string `json:"Expiration,omitempty"`
	}{Version: 1, AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken}
	if !c.Expiration.IsZero() {
		doc.Expiration = c.Expiration.UTC().Format(time.RFC3339)
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return "", errors.New("providertoken: aws_sts: encoding credentials failed")
	}
	return string(b), nil
}

// AWSSTSConfig configures AssumeRole against real AWS STS or Citadel's own
// STS endpoint.
type AWSSTSConfig struct {
	// Endpoint is the STS endpoint; empty means DefaultSTSEndpoint. For
	// Citadel's own STS use its public URL.
	Endpoint string
	// Region is the SigV4 signing region; empty means us-east-1.
	Region string
	// Source signs the AssumeRole call (stored long-term keys, or temporary
	// ones with a session token).
	Source AWSCredentials
	// RoleARN is the role to assume.
	RoleARN string
	// ExternalID is sent when the role's trust policy requires one.
	ExternalID string
	// SessionName is the default RoleSessionName; empty means "citadel-agent".
	SessionName string
	// SessionPolicy is the default inline session policy. A grant's
	// Params.SessionPolicy may not replace it (policies cannot be
	// intersected client side, so a second policy is refused).
	SessionPolicy string
	// Duration is the default session length; zero means DefaultSTSDuration.
	Duration time.Duration
	// MaxDuration caps any requested Duration; zero means MaxSTSDuration.
	MaxDuration time.Duration
	// Timeout bounds the HTTP call; zero means DefaultTimeout.
	Timeout time.Duration
	// AllowInsecureHTTP permits an http:// endpoint (development only).
	AllowInsecureHTTP bool
	// Now overrides the clock (tests).
	Now func() time.Time
}

// AWSSTS mints temporary AWS credentials with AssumeRole. It reads
// Params.SessionName, Params.SessionPolicy and Params.Duration.
type AWSSTS struct {
	cfg      AWSSTSConfig
	endpoint *url.URL
	client   *http.Client
}

var (
	roleARNRE     = regexp.MustCompile(`^arn:[a-z0-9-]+:iam::[0-9]{12}:role/[\w+=,.@/-]{1,512}$`)
	sessionNameRE = regexp.MustCompile(`^[\w+=,.@-]{2,64}$`)
	externalIDRE  = regexp.MustCompile(`^[\w+=,.@:/-]+$`)
	regionRE      = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
)

// NewAWSSTS validates cfg and returns a minter that calls STS through client.
func NewAWSSTS(cfg AWSSTSConfig, client *http.Client) (*AWSSTS, error) {
	c, err := noRedirectClient(KindAWSSTS, client)
	if err != nil {
		return nil, err
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = DefaultSTSEndpoint
	}
	u, err := checkEndpoint(KindAWSSTS, cfg.Endpoint, cfg.AllowInsecureHTTP)
	if err != nil {
		return nil, err
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	if !regionRE.MatchString(cfg.Region) {
		return nil, errors.New("providertoken: aws_sts: invalid region")
	}
	if cfg.Source.AccessKeyID == "" || cfg.Source.SecretAccessKey == "" {
		return nil, errors.New("providertoken: aws_sts: source credentials are required")
	}
	if len(cfg.Source.SecretAccessKey) < sigv4.MinSecretKeyLen {
		return nil, errors.New("providertoken: aws_sts: source secret access key is too short")
	}
	if !roleARNRE.MatchString(cfg.RoleARN) {
		return nil, errors.New("providertoken: aws_sts: invalid role ARN")
	}
	if cfg.ExternalID != "" && (len(cfg.ExternalID) < 2 || len(cfg.ExternalID) > 1224 || !externalIDRE.MatchString(cfg.ExternalID)) {
		return nil, errors.New("providertoken: aws_sts: invalid external ID")
	}
	if cfg.SessionName == "" {
		cfg.SessionName = "citadel-agent"
	}
	if !sessionNameRE.MatchString(cfg.SessionName) {
		return nil, errors.New("providertoken: aws_sts: invalid session name")
	}
	if err := checkSessionPolicy(cfg.SessionPolicy); err != nil {
		return nil, err
	}
	if cfg.MaxDuration == 0 {
		cfg.MaxDuration = MaxSTSDuration
	}
	if cfg.MaxDuration < MinSTSDuration || cfg.MaxDuration > MaxSTSDuration {
		return nil, errors.New("providertoken: aws_sts: max duration must be between 15m and 12h")
	}
	if cfg.Duration == 0 {
		cfg.Duration = min(DefaultSTSDuration, cfg.MaxDuration)
	}
	if cfg.Duration < MinSTSDuration || cfg.Duration > cfg.MaxDuration {
		return nil, errors.New("providertoken: aws_sts: duration out of range")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &AWSSTS{cfg: cfg, endpoint: u, client: c}, nil
}

func checkSessionPolicy(p string) error {
	if p == "" {
		return nil
	}
	if len(p) > maxSessionPolicyBytes {
		return errors.New("providertoken: aws_sts: session policy exceeds 2048 bytes")
	}
	if !json.Valid([]byte(p)) {
		return errors.New("providertoken: aws_sts: session policy is not valid JSON")
	}
	return nil
}

// AssumedRole is the result of AssumeRole.
type AssumedRole struct {
	Credentials   AWSCredentials
	AssumedARN    string
	AssumedRoleID string
}

// AssumeRole calls STS and returns the temporary credentials.
func (a *AWSSTS) AssumeRole(ctx context.Context, p Params) (AssumedRole, error) {
	sessionName := a.cfg.SessionName
	if p.SessionName != "" {
		if !sessionNameRE.MatchString(p.SessionName) {
			return AssumedRole{}, errors.New("providertoken: aws_sts: invalid session name")
		}
		sessionName = p.SessionName
	}
	policy := a.cfg.SessionPolicy
	if p.SessionPolicy != "" {
		if policy != "" && p.SessionPolicy != policy {
			return AssumedRole{}, errors.New("providertoken: aws_sts: a session policy is already configured for this credential")
		}
		if err := checkSessionPolicy(p.SessionPolicy); err != nil {
			return AssumedRole{}, err
		}
		policy = p.SessionPolicy
	}
	duration := a.cfg.Duration
	if p.Duration != 0 {
		if p.Duration < MinSTSDuration || p.Duration > a.cfg.MaxDuration {
			return AssumedRole{}, errors.New("providertoken: aws_sts: duration out of range")
		}
		duration = p.Duration
	}

	form := url.Values{}
	form.Set("Action", "AssumeRole")
	form.Set("Version", "2011-06-15")
	form.Set("RoleArn", a.cfg.RoleARN)
	form.Set("RoleSessionName", sessionName)
	form.Set("DurationSeconds", strconv.FormatInt(int64(duration/time.Second), 10))
	if a.cfg.ExternalID != "" {
		form.Set("ExternalId", a.cfg.ExternalID)
	}
	if policy != "" {
		form.Set("Policy", policy)
	}
	body := []byte(form.Encode())

	ctx, cancel := withTimeout(ctx, a.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return AssumedRole{}, errors.New("providertoken: aws_sts: building request failed")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("Accept", "text/xml")
	src := sigv4.SigningCredentials{AccessKeyID: a.cfg.Source.AccessKeyID, SecretAccessKey: a.cfg.Source.SecretAccessKey, SessionToken: a.cfg.Source.SessionToken}
	if err := sigv4.SignRequest(req, sigv4.HashPayload(body), src, a.cfg.Region, "sts", a.cfg.Now()); err != nil {
		return AssumedRole{}, errors.New("providertoken: aws_sts: signing request failed")
	}
	resp, respBody, err := do(KindAWSSTS, a.client, req)
	if err != nil {
		return AssumedRole{}, err
	}
	if resp.StatusCode != http.StatusOK {
		var e stsErrorResponse
		_ = xml.Unmarshal(respBody, &e)
		return AssumedRole{}, &ProviderError{Kind: KindAWSSTS, Status: resp.StatusCode, Code: safeCode(e.Error.Code)}
	}
	var out stsAssumeRoleResponse
	if err := xml.Unmarshal(respBody, &out); err != nil {
		return AssumedRole{}, errors.New("providertoken: aws_sts: malformed AssumeRole response")
	}
	c := out.Result.Credentials
	if c.AccessKeyID == "" || c.SecretAccessKey == "" || c.SessionToken == "" {
		return AssumedRole{}, errors.New("providertoken: aws_sts: AssumeRole response is missing credentials")
	}
	exp, err := time.Parse(time.RFC3339, strings.TrimSpace(c.Expiration))
	if err != nil {
		return AssumedRole{}, errors.New("providertoken: aws_sts: AssumeRole response has an invalid expiration")
	}
	return AssumedRole{
		Credentials:   AWSCredentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken, Expiration: exp.UTC()},
		AssumedARN:    out.Result.AssumedRoleUser.Arn,
		AssumedRoleID: out.Result.AssumedRoleUser.AssumedRoleID,
	}, nil
}

// Mint assumes the role and returns the credentials as a credential_process
// JSON document. Metadata carries the access key ID (not secret) and the
// assumed role ARN and ID.
func (a *AWSSTS) Mint(ctx context.Context, p Params) (Token, error) {
	r, err := a.AssumeRole(ctx, p)
	if err != nil {
		return Token{}, err
	}
	v, err := r.Credentials.ProcessJSON()
	if err != nil {
		return Token{}, err
	}
	return Token{
		Value:     v,
		ExpiresAt: r.Credentials.Expiration,
		Kind:      KindAWSSTS,
		Metadata: map[string]string{
			"accessKeyId":    r.Credentials.AccessKeyID,
			"assumedRoleArn": r.AssumedARN,
			"assumedRoleId":  r.AssumedRoleID,
			"roleArn":        a.cfg.RoleARN,
		},
	}, nil
}

type stsAssumeRoleResponse struct {
	XMLName xml.Name `xml:"AssumeRoleResponse"`
	Result  struct {
		Credentials struct {
			AccessKeyID     string `xml:"AccessKeyId"`
			SecretAccessKey string `xml:"SecretAccessKey"`
			SessionToken    string `xml:"SessionToken"`
			Expiration      string `xml:"Expiration"`
		} `xml:"Credentials"`
		AssumedRoleUser struct {
			Arn           string `xml:"Arn"`
			AssumedRoleID string `xml:"AssumedRoleId"`
		} `xml:"AssumedRoleUser"`
	} `xml:"AssumeRoleResult"`
}

type stsErrorResponse struct {
	Error struct {
		Code string `xml:"Code"`
	} `xml:"Error"`
}

// maxSignedBody caps the body SignAWSRequest reads to hash.
const maxSignedBody = 10 << 20

// SignAWSRequest signs an outbound AWS API request server-side with
// (typically temporary) credentials, for brokered calls where the agent
// never sees the keys. The body is read, hashed and replaced so the request
// can still be sent; bodies over 10 MiB are refused. For S3 the payload is
// signed as well (no UNSIGNED-PAYLOAD).
func SignAWSRequest(req *http.Request, creds AWSCredentials, region, service string, now time.Time) error {
	if req == nil {
		return errors.New("providertoken: aws_sts: nil request")
	}
	if !regionRE.MatchString(region) || !regionRE.MatchString(service) {
		return errors.New("providertoken: aws_sts: invalid region or service")
	}
	if !creds.Expiration.IsZero() && !now.Before(creds.Expiration) {
		return errors.New("providertoken: aws_sts: credentials have expired")
	}
	var body []byte
	if req.Body != nil && req.Body != http.NoBody {
		b, err := io.ReadAll(io.LimitReader(req.Body, maxSignedBody+1))
		_ = req.Body.Close()
		if err != nil {
			return errors.New("providertoken: aws_sts: reading request body failed")
		}
		if len(b) > maxSignedBody {
			return fmt.Errorf("providertoken: aws_sts: request body exceeds %d bytes", maxSignedBody)
		}
		body = b
		req.Body = io.NopCloser(bytes.NewReader(b))
		req.ContentLength = int64(len(b))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
	}
	sc := sigv4.SigningCredentials{AccessKeyID: creds.AccessKeyID, SecretAccessKey: creds.SecretAccessKey, SessionToken: creds.SessionToken}
	if err := sigv4.SignRequest(req, sigv4.HashPayload(body), sc, region, service, now); err != nil {
		return errors.New("providertoken: aws_sts: signing request failed")
	}
	return nil
}
