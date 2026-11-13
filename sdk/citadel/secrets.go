package citadel

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Project is a project and its environments.
type Project struct {
	Slug string `json:"slug"`
	// Name is the display name, when one was set.
	Name         string   `json:"name,omitempty"`
	Environments []string `json:"environments"`
	// EnvironmentCounts is the number of live secrets per environment.
	EnvironmentCounts map[string]int `json:"environmentCounts"`
}

// ListProjects returns the projects in the key's account.
func (c *Client) ListProjects(ctx context.Context) ([]Project, error) {
	var out struct {
		Projects []Project `json:"projects"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/projects", nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Projects, nil
}

// CreateProject registers an empty project. name is an optional display name.
// Requires the editor role.
func (c *Client) CreateProject(ctx context.Context, slug, name string) error {
	return c.do(ctx, http.MethodPost, "/v1/projects", nil, map[string]string{"slug": slug, "name": name}, nil)
}

// DeleteProject removes a project that holds no secrets.
func (c *Client) DeleteProject(ctx context.Context, project string) error {
	return c.do(ctx, http.MethodDelete, "/v1/projects", url.Values{"project": {project}}, nil, nil)
}

// CreateEnvironment registers an empty environment in project.
func (c *Client) CreateEnvironment(ctx context.Context, project, slug, name string) error {
	return c.do(ctx, http.MethodPost, "/v1/environments", nil, map[string]string{"project": project, "slug": slug, "name": name}, nil)
}

// DeleteEnvironment removes an environment that holds no secrets.
func (c *Client) DeleteEnvironment(ctx context.Context, project, env string) error {
	return c.do(ctx, http.MethodDelete, "/v1/environments", url.Values{"project": {project}, "env": {env}}, nil, nil)
}

// CreateFolder registers a (possibly empty) folder such as "api/db".
func (c *Client) CreateFolder(ctx context.Context, project, env, path string) error {
	return c.do(ctx, http.MethodPost, "/v1/folders", nil, map[string]string{"project": project, "env": env, "path": path}, nil)
}

// DeleteFolder removes a folder that holds no secrets.
func (c *Client) DeleteFolder(ctx context.Context, project, env, path string) error {
	return c.do(ctx, http.MethodDelete, "/v1/folders", url.Values{"project": {project}, "env": {env}, "path": {path}}, nil, nil)
}

// SecretRef addresses one secret: project, environment, folder path ("" or
// "/" for the root, "api/db" for a nested folder) and key. Every segment
// must match [A-Za-z0-9_.-]+.
type SecretRef struct {
	Project string
	Env     string
	Path    string
	Key     string
}

func (r SecretRef) query() url.Values {
	q := url.Values{"project": {r.Project}, "env": {r.Env}, "key": {r.Key}}
	if r.Path != "" {
		q.Set("path", r.Path)
	}
	return q
}

// SecretItem describes a secret in a listing. Listings never include values.
type SecretItem struct {
	Project   string    `json:"project"`
	Env       string    `json:"env"`
	Path      string    `json:"path"`
	Key       string    `json:"key"`
	ARN       string    `json:"arn"`
	UpdatedAt time.Time `json:"updatedAt"`
	// DeletionDate is set while the secret is scheduled for deletion.
	DeletionDate *time.Time `json:"deletionDate,omitempty"`
	// Version is the number of stored versions.
	Version     int    `json:"version,omitempty"`
	UpdatedBy   string `json:"updatedBy,omitempty"`
	Tags        []Tag  `json:"tags"`
	RotationDue bool   `json:"rotationDue,omitempty"`
}

// Tag is a key/value tag.
type Tag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// SecretListing is one folder level: its subfolders and its secrets.
type SecretListing struct {
	Project string `json:"project"`
	Env     string `json:"env"`
	Path    string `json:"path"`
	// Folders are the immediate subfolder names.
	Folders []string     `json:"folders"`
	Items   []SecretItem `json:"items"`
	// Shadowed lists objects stored at a subfolder's own name.
	Shadowed []SecretItem `json:"shadowed"`
	// FolderCounts is the number of secrets under each subfolder.
	FolderCounts map[string]int `json:"folderCounts"`
}

// ListSecrets lists one folder level (path "" is the root). It does not
// recurse; walk Folders for a tree.
func (c *Client) ListSecrets(ctx context.Context, project, env, path string) (*SecretListing, error) {
	q := url.Values{"project": {project}, "env": {env}}
	if path != "" {
		q.Set("path", path)
	}
	var out SecretListing
	if err := c.do(ctx, http.MethodGet, "/v1/secrets", q, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetSecretOptions selects a version and reference resolution.
type GetSecretOptions struct {
	// VersionID or VersionStage (e.g. "AWSPREVIOUS") selects a version;
	// by default the current one.
	VersionID    string
	VersionStage string
	// Resolve expands ${KEY} references in the value server-side.
	Resolve bool
}

// SecretValue is a revealed secret.
type SecretValue struct {
	Key       string `json:"key"`
	VersionID string `json:"versionId"`
	Resolved  bool   `json:"resolved"`
	// Value is the string value; BinaryValue is set instead for binary
	// secrets.
	Value       string `json:"value"`
	BinaryValue []byte `json:"binaryValue,omitempty"`
}

// GetSecret reveals a secret's value (opts may be nil). Viewers get a
// reveal_forbidden error unless the account lets viewers reveal values.
// The read is audited.
func (c *Client) GetSecret(ctx context.Context, ref SecretRef, opts *GetSecretOptions) (*SecretValue, error) {
	q := ref.query()
	if opts != nil {
		if opts.VersionID != "" {
			q.Set("versionId", opts.VersionID)
		}
		if opts.VersionStage != "" {
			q.Set("versionStage", opts.VersionStage)
		}
		if opts.Resolve {
			q.Set("resolve", "true")
		}
	}
	var out SecretValue
	if err := c.do(ctx, http.MethodGet, "/v1/secrets/value", q, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PutSecretInput is a secret to create or update.
type PutSecretInput struct {
	Project string `json:"project"`
	Env     string `json:"env"`
	Path    string `json:"path,omitempty"`
	Key     string `json:"key"`
	Value   string `json:"value"`
	// KMSKeyID encrypts a new secret under this key instead of the
	// account default.
	KMSKeyID string `json:"kmsKeyId,omitempty"`
}

// PutSecretResult reports whether the secret was created (true) or a new
// version was added (false).
type PutSecretResult struct {
	Project string `json:"project"`
	Env     string `json:"env"`
	Path    string `json:"path"`
	Key     string `json:"key"`
	Created bool   `json:"created"`
}

// PutSecret creates a secret or adds a new version. In an environment with
// an approval policy it fails with approval_required (see
// IsApprovalRequired). Requires the editor role.
func (c *Client) PutSecret(ctx context.Context, in PutSecretInput) (*PutSecretResult, error) {
	var out PutSecretResult
	if err := c.do(ctx, http.MethodPost, "/v1/secrets", nil, in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteSecretOptions controls the recovery window.
type DeleteSecretOptions struct {
	// Force deletes immediately, without a recovery window.
	Force bool
	// RecoveryWindowDays overrides the default recovery window.
	RecoveryWindowDays int
}

// DeleteSecret schedules a secret for deletion (opts may be nil). Until the
// recovery window ends RestoreSecret brings it back.
func (c *Client) DeleteSecret(ctx context.Context, ref SecretRef, opts *DeleteSecretOptions) error {
	q := ref.query()
	if opts != nil {
		if opts.Force {
			q.Set("force", "true")
		}
		if opts.RecoveryWindowDays > 0 {
			q.Set("recoveryWindowDays", strconv.Itoa(opts.RecoveryWindowDays))
		}
	}
	return c.do(ctx, http.MethodDelete, "/v1/secrets", q, nil, nil)
}

// RestoreSecret cancels a pending deletion.
func (c *Client) RestoreSecret(ctx context.Context, ref SecretRef) error {
	return c.do(ctx, http.MethodPost, "/v1/secrets/restore", ref.query(), nil, nil)
}

// SecretVersion is one stored version of a secret.
type SecretVersion struct {
	VersionID string    `json:"versionId"`
	Stages    []string  `json:"stages"`
	CreatedAt time.Time `json:"createdAt"`
	// Version is the version's ordinal, from 1.
	Version   int    `json:"version"`
	CreatedBy string `json:"createdBy,omitempty"`
}

// ListSecretVersions returns a secret's versions (values not included).
func (c *Client) ListSecretVersions(ctx context.Context, ref SecretRef) ([]SecretVersion, error) {
	var out struct {
		Versions []SecretVersion `json:"versions"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/secrets/versions", ref.query(), nil, &out); err != nil {
		return nil, err
	}
	return out.Versions, nil
}
