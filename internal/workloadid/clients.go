package workloadid

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// AuthMethod is how a client's workloads authenticate to the token endpoint.
type AuthMethod string

const (
	// AuthAccessKey: the host authenticates the request with Citadel
	// credentials (for example a SigV4-signed request or an access key)
	// through an AuthenticatorFunc.
	AuthAccessKey AuthMethod = "access_key"
	// AuthKubernetes: the workload presents a Kubernetes service account
	// token, checked with the cluster's TokenReview API.
	AuthKubernetes AuthMethod = "kubernetes"
)

// KubernetesConfig describes the cluster trusted by a kubernetes client.
type KubernetesConfig struct {
	// APIServer is the cluster API base URL (https).
	APIServer string `json:"api_server"`
	// CA is the PEM bundle that signs the API server certificate. Empty means
	// the system roots.
	CA string `json:"ca,omitempty"`
	// Audiences the service account token must be valid for (passed to
	// TokenReview and checked in its response). Strongly recommended: use a
	// dedicated audience such as "citadel" via projected tokens.
	Audiences []string `json:"audiences,omitempty"`
	// Namespaces allowed; empty means any. "*" also means any.
	Namespaces []string `json:"namespaces,omitempty"`
	// ServiceAccounts allowed, as "namespace/name" or "name" (any allowed
	// namespace); empty means any.
	ServiceAccounts []string `json:"service_accounts,omitempty"`
}

// Client is a registered workload identity client: who may obtain tokens,
// for which audiences, and what subject they get.
type Client struct {
	ID         string `json:"id"`
	AccountRef string `json:"account_ref"`
	Name       string `json:"name"`
	// AllowedAudiences is the exact list of aud values tokens may carry.
	AllowedAudiences []string `json:"allowed_audiences"`
	// TTL is the default and maximum token lifetime for this client
	// (clamped to the issuer's MaxTTL). Zero means the issuer default.
	TTL time.Duration `json:"ttl"`
	// SubjectTemplate renders the sub claim, e.g.
	// "account:{account}:client:{client}" (the default) or
	// "system:serviceaccount:{namespace}:{service_account}". Placeholders:
	// {account}, {client}, and any workload attribute name.
	SubjectTemplate string            `json:"subject_template"`
	AuthMethod      AuthMethod        `json:"auth_method"`
	Kubernetes      *KubernetesConfig `json:"kubernetes,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// DefaultSubjectTemplate is used when a client has no template.
const DefaultSubjectTemplate = "account:{account}:client:{client}"

var (
	idPattern          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	placeholderPattern = regexp.MustCompile(`\{([A-Za-z0-9_.-]*)\}`)
)

// Validate checks a client definition.
func (c *Client) Validate() error {
	if !idPattern.MatchString(c.ID) {
		return fmt.Errorf("workloadid: client ID %q must match %s", c.ID, idPattern)
	}
	if c.AccountRef == "" {
		return errors.New("workloadid: client account is required")
	}
	if len(c.AllowedAudiences) == 0 {
		return errors.New("workloadid: client needs at least one allowed audience")
	}
	for _, a := range c.AllowedAudiences {
		if a == "" || len(a) > 512 || strings.ContainsAny(a, "\x00\r\n") {
			return fmt.Errorf("workloadid: invalid audience %q", a)
		}
	}
	if c.TTL < 0 {
		return errors.New("workloadid: client TTL must not be negative")
	}
	tmpl := c.SubjectTemplate
	if tmpl == "" {
		tmpl = DefaultSubjectTemplate
	}
	for _, m := range placeholderPattern.FindAllStringSubmatch(tmpl, -1) {
		if m[1] == "" {
			return errors.New("workloadid: empty placeholder in subject template")
		}
	}
	if strings.Count(tmpl, "{") != strings.Count(tmpl, "}") {
		return errors.New("workloadid: unbalanced braces in subject template")
	}
	switch c.AuthMethod {
	case AuthAccessKey:
		if c.Kubernetes != nil {
			return errors.New("workloadid: kubernetes settings on an access_key client")
		}
	case AuthKubernetes:
		k := c.Kubernetes
		if k == nil || k.APIServer == "" {
			return errors.New("workloadid: kubernetes client needs an API server")
		}
		u, err := url.Parse(k.APIServer)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("workloadid: invalid API server URL %q", k.APIServer)
		}
		if len(k.Audiences) == 0 {
			// Without a dedicated audience the workload would hand Citadel a
			// token that is also valid against the cluster API.
			return errors.New("workloadid: kubernetes client needs at least one token audience")
		}
	default:
		return fmt.Errorf("workloadid: unknown auth method %q", c.AuthMethod)
	}
	return nil
}

// ClientStore persists clients. Implementations must be safe for concurrent
// use. A Postgres implementation would key on ID with an index on
// AccountRef, store the slices and Kubernetes settings as JSONB, and map
// unique violations to ErrClientExists.
type ClientStore interface {
	Create(ctx context.Context, c Client) (Client, error)
	Get(ctx context.Context, id string) (Client, error)
	// List returns the clients of accountRef ("" lists every client),
	// ordered by ID.
	List(ctx context.Context, accountRef string) ([]Client, error)
	Update(ctx context.Context, c Client) (Client, error)
	Delete(ctx context.Context, id string) error
}

var (
	ErrClientNotFound = errors.New("workloadid: client not found")
	ErrClientExists   = errors.New("workloadid: client already exists")
)

// MemoryClientStore is an in-memory ClientStore.
type MemoryClientStore struct {
	mu      sync.RWMutex
	now     func() time.Time
	clients map[string]Client
}

// NewMemoryClientStore returns an empty store; now defaults to time.Now.
func NewMemoryClientStore(now func() time.Time) *MemoryClientStore {
	if now == nil {
		now = time.Now
	}
	return &MemoryClientStore{now: now, clients: map[string]Client{}}
}

func cloneClient(c Client) Client {
	c.AllowedAudiences = append([]string(nil), c.AllowedAudiences...)
	if c.Kubernetes != nil {
		k := *c.Kubernetes
		k.Audiences = append([]string(nil), k.Audiences...)
		k.Namespaces = append([]string(nil), k.Namespaces...)
		k.ServiceAccounts = append([]string(nil), k.ServiceAccounts...)
		c.Kubernetes = &k
	}
	return c
}

// Create implements ClientStore.
func (s *MemoryClientStore) Create(_ context.Context, c Client) (Client, error) {
	if err := c.Validate(); err != nil {
		return Client{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[c.ID]; ok {
		return Client{}, ErrClientExists
	}
	now := s.now().UTC()
	c.CreatedAt, c.UpdatedAt = now, now
	s.clients[c.ID] = cloneClient(c)
	return cloneClient(c), nil
}

// Get implements ClientStore.
func (s *MemoryClientStore) Get(_ context.Context, id string) (Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.clients[id]
	if !ok {
		return Client{}, ErrClientNotFound
	}
	return cloneClient(c), nil
}

// List implements ClientStore.
func (s *MemoryClientStore) List(_ context.Context, accountRef string) ([]Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Client
	for _, c := range s.clients {
		if accountRef == "" || c.AccountRef == accountRef {
			out = append(out, cloneClient(c))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Update implements ClientStore. CreatedAt and AccountRef are preserved.
func (s *MemoryClientStore) Update(_ context.Context, c Client) (Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.clients[c.ID]
	if !ok {
		return Client{}, ErrClientNotFound
	}
	c.AccountRef = old.AccountRef
	if err := c.Validate(); err != nil {
		return Client{}, err
	}
	c.CreatedAt, c.UpdatedAt = old.CreatedAt, s.now().UTC()
	s.clients[c.ID] = cloneClient(c)
	return cloneClient(c), nil
}

// Delete implements ClientStore.
func (s *MemoryClientStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[id]; !ok {
		return ErrClientNotFound
	}
	delete(s.clients, id)
	return nil
}
