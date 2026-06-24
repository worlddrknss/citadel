// Package citadel is a minimal native SDK for the Citadel /v1 API (PLAN.md §6
// P9). It speaks the protocol-clean JSON surface — not the AWS dialect — and
// authenticates with a native bearer token (a machine identity access key in
// the form "<accessKeyId>:<secret>").
//
// This is intentionally small: it demonstrates the native programmatic path and
// gives downstream tools (including a future External Secrets Operator provider)
// a typed client to build on, without pulling in the AWS SDK.
package citadel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is a native Citadel API client.
type Client struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

// New returns a Client for the given base URL (e.g. "https://citadel.example.com")
// and native bearer token ("<accessKeyId>:<secret>").
func New(baseURL, token string) *Client {
	return &Client{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		Token:      token,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// APIError is returned for non-2xx responses from the native API.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("citadel: %d %s: %s", e.Status, e.Code, e.Message)
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	u := c.BaseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return &APIError{Status: resp.StatusCode, Code: e.Error, Message: e.Message}
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// Project is a project and its environments.
type Project struct {
	Slug         string   `json:"slug"`
	Environments []string `json:"environments"`
}

// ListProjects returns the projects visible to the token's account.
func (c *Client) ListProjects(ctx context.Context) ([]Project, error) {
	var out struct {
		Projects []Project `json:"projects"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/projects", nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Projects, nil
}

// PutSecret creates or updates a single item.
func (c *Client) PutSecret(ctx context.Context, project, env, path, key, value string) error {
	body := map[string]string{"project": project, "env": env, "path": path, "key": key, "value": value}
	return c.do(ctx, http.MethodPost, "/v1/secrets", nil, body, nil)
}

// GetSecret reveals the value of a single item. When resolve is true, ${KEY}
// references in the value are expanded server-side.
func (c *Client) GetSecret(ctx context.Context, project, env, path, key string, resolve bool) (string, error) {
	q := url.Values{"project": {project}, "env": {env}, "path": {path}, "key": {key}}
	if resolve {
		q.Set("resolve", "true")
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/secrets/value", q, nil, &out); err != nil {
		return "", err
	}
	return out.Value, nil
}

// ErrNotConfigured is returned by identity helpers that are scaffolded but not
// yet wired to a concrete provider.
var ErrNotConfigured = errors.New("citadel: native OIDC identity is not configured")
