// Package citadel is the Go SDK for Citadel's native /v1 API, the
// protocol-clean JSON API described by docs/openapi.yaml (and served by every
// Citadel server at GET /v1/openapi.yaml). It is separate from Citadel's
// AWS-compatible APIs, for which the AWS SDK works unchanged.
//
// The client authenticates with an access key (created in the console under
// Account, or with the createAccessKey operation), sent as
// "Authorization: Bearer <accessKeyId>:<secret>". A key acts with its owner's
// role in the key's account, never more.
//
// Every method takes a context for cancellation and deadlines. Failed
// requests return an *APIError carrying the HTTP status and the API's stable
// error code; see IsNotFound and the other helpers. Rate-limited (429) and
// transient server failures are retried with exponential backoff and jitter.
//
// The package uses only the Go standard library.
package citadel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Version is the SDK version, sent in the User-Agent header.
const Version = "2.1.0"

// Environment variables read by New when the Config leaves a field empty.
const (
	EnvURL             = "CITADEL_URL"
	EnvAccessKeyID     = "CITADEL_ACCESS_KEY_ID"
	EnvSecretAccessKey = "CITADEL_SECRET_ACCESS_KEY"
	// EnvAgentToken is an AI agent's token (cagt_...), used when no access
	// key is configured.
	EnvAgentToken = "CITADEL_AGENT_TOKEN"
)

// DefaultBaseURL is used when neither Config.BaseURL nor CITADEL_URL is set.
const DefaultBaseURL = "http://localhost:8080"

// Config configures a Client. The zero value reads everything from the
// environment and uses the defaults.
type Config struct {
	// BaseURL is the Citadel server, e.g. "https://citadel.example.com".
	// Defaults to $CITADEL_URL, then DefaultBaseURL.
	BaseURL string
	// AccessKeyID and SecretAccessKey are the access key to authenticate
	// with. Default to $CITADEL_ACCESS_KEY_ID and $CITADEL_SECRET_ACCESS_KEY.
	AccessKeyID     string
	SecretAccessKey string
	// AgentToken authenticates as an AI agent instead (only the Agent API
	// accepts it). Defaults to $CITADEL_AGENT_TOKEN when no access key is
	// configured.
	AgentToken string
	// Timeout bounds each HTTP attempt (default 30s). The context passed to
	// a method bounds the whole call, retries included.
	Timeout time.Duration
	// MaxRetries is how many times a retryable failure is retried (default
	// 3). Set a negative value to disable retries.
	MaxRetries int
	// RetryBaseDelay and RetryMaxDelay shape the exponential backoff
	// (defaults 200ms and 5s). Delays use full jitter; a Retry-After header
	// from the server takes precedence, capped at RetryMaxDelay.
	RetryBaseDelay time.Duration
	RetryMaxDelay  time.Duration
	// HTTPClient replaces the default client. Its Timeout is left as is;
	// Config.Timeout then applies per attempt through the request context.
	HTTPClient *http.Client
	// UserAgent is appended to the SDK's User-Agent.
	UserAgent string
}

// Client calls the Citadel native API. It is safe for concurrent use.
type Client struct {
	baseURL    string
	token      string
	timeout    time.Duration
	maxRetries int
	baseDelay  time.Duration
	maxDelay   time.Duration
	http       *http.Client
	userAgent  string
	// sleep waits between retries; tests replace it.
	sleep func(context.Context, time.Duration) error
}

// ErrNoCredentials is returned by New when no access key is configured.
var ErrNoCredentials = errors.New("citadel: no access key: set Config.AccessKeyID and Config.SecretAccessKey, or " + EnvAccessKeyID + " and " + EnvSecretAccessKey)

// New returns a Client for cfg, filling empty fields from the environment
// and defaults.
func New(cfg Config) (*Client, error) {
	base := firstNonEmpty(cfg.BaseURL, os.Getenv(EnvURL), DefaultBaseURL)
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("citadel: invalid base URL %q", base)
	}
	token := ""
	if agent := strings.TrimSpace(cfg.AgentToken); agent != "" {
		token = agent
	} else {
		id := firstNonEmpty(cfg.AccessKeyID, os.Getenv(EnvAccessKeyID))
		secret := firstNonEmpty(cfg.SecretAccessKey, os.Getenv(EnvSecretAccessKey))
		switch {
		case id != "" && secret != "":
			if strings.Contains(id, ":") {
				return nil, errors.New("citadel: access key ID must not contain ':'")
			}
			token = id + ":" + secret
		case strings.TrimSpace(os.Getenv(EnvAgentToken)) != "":
			token = strings.TrimSpace(os.Getenv(EnvAgentToken))
		default:
			return nil, ErrNoCredentials
		}
	}
	c := &Client{
		baseURL:    strings.TrimRight(base, "/"),
		token:      token,
		timeout:    cfg.Timeout,
		maxRetries: cfg.MaxRetries,
		baseDelay:  cfg.RetryBaseDelay,
		maxDelay:   cfg.RetryMaxDelay,
		http:       cfg.HTTPClient,
		userAgent:  "citadel-go/" + Version,
		sleep:      sleepContext,
	}
	if cfg.UserAgent != "" {
		c.userAgent += " " + cfg.UserAgent
	}
	if c.timeout <= 0 {
		c.timeout = 30 * time.Second
	}
	switch {
	case c.maxRetries == 0:
		c.maxRetries = 3
	case c.maxRetries < 0:
		c.maxRetries = 0
	}
	if c.baseDelay <= 0 {
		c.baseDelay = 200 * time.Millisecond
	}
	if c.maxDelay <= 0 {
		c.maxDelay = 5 * time.Second
	}
	if c.http == nil {
		c.http = &http.Client{}
	}
	return c, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// BaseURL returns the server the client talks to.
func (c *Client) BaseURL() string { return c.baseURL }

// do sends one API call, retrying as described on Config, and decodes a 2xx
// JSON response into out (when non-nil).
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return fmt.Errorf("citadel: encode request: %w", err)
		}
	}
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	for attempt := 0; ; attempt++ {
		resp, err := c.attempt(ctx, method, u, payload)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// Transport failures may have reached the server; retry only
			// requests that are safe to repeat.
			if attempt < c.maxRetries && safeMethod(method) {
				if werr := c.sleep(ctx, c.backoff(attempt, 0)); werr != nil {
					return werr
				}
				continue
			}
			return fmt.Errorf("citadel: %s %s: %w", method, path, err)
		}
		if resp.status/100 == 2 {
			if out == nil || len(resp.body) == 0 {
				return nil
			}
			if err := json.Unmarshal(resp.body, out); err != nil {
				return fmt.Errorf("citadel: decode %s %s response: %w", method, path, err)
			}
			return nil
		}
		apiErr := newAPIError(method, path, resp)
		if attempt < c.maxRetries && retryable(method, resp.status) {
			if werr := c.sleep(ctx, c.backoff(attempt, apiErr.RetryAfter)); werr != nil {
				return werr
			}
			continue
		}
		return apiErr
	}
}

type rawResponse struct {
	status int
	header http.Header
	body   []byte
}

func (c *Client) attempt(ctx context.Context, method, u string, payload []byte) (*rawResponse, error) {
	actx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	var rd io.Reader
	if payload != nil {
		rd = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(actx, method, u, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	return &rawResponse{status: resp.StatusCode, header: resp.Header, body: body}, nil
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead
}

// retryable reports whether a failed response is worth retrying. 429, 502,
// 503 and 504 mean the request was not processed and are retried for every
// method; a 500 is retried only for reads, since a write may have happened.
func retryable(method string, status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	case http.StatusInternalServerError:
		return safeMethod(method)
	}
	return false
}

// backoff is the delay before retry number attempt+1: full jitter over an
// exponentially growing window, or the server's Retry-After when given.
func (c *Client) backoff(attempt int, retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		return min(retryAfter, c.maxDelay)
	}
	window := c.baseDelay << min(attempt, 16)
	if window <= 0 || window > c.maxDelay {
		window = c.maxDelay
	}
	return time.Duration(rand.Int64N(int64(window)) + 1)
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// Me describes the authenticated caller.
type Me struct {
	Username    string   `json:"username"`
	DisplayName string   `json:"displayName"`
	Role        string   `json:"role"`
	AccountID   string   `json:"accountId"`
	Accounts    []string `json:"accounts"`
}

// Me returns the caller the access key authenticates as (for an access key,
// the username is the key ID and the role is its owner's role).
func (c *Client) Me(ctx context.Context) (*Me, error) {
	var out Me
	if err := c.do(ctx, http.MethodGet, "/v1/me", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
