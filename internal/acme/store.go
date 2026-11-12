package acme

import (
	"context"
	"slices"
	"sync"
	"time"
)

// Store persists ACME state. It must be safe for concurrent use and, for a
// multi-replica deployment, shared between replicas (nonces in particular).
//
// Update methods implement optimistic concurrency: the stored object's
// Version must equal the argument's Version, otherwise ErrStale is returned.
// On success the store increments the Version both in storage and in the
// argument. Create methods set Version to 1. Get methods return copies that
// the caller may modify freely.
type Store interface {
	// AddNonce records a freshly issued nonce.
	AddNonce(ctx context.Context, nonce string, expires time.Time) error
	// ConsumeNonce atomically removes the nonce and reports whether it
	// existed and had not expired at now.
	ConsumeNonce(ctx context.Context, nonce string, now time.Time) (bool, error)

	// CreateAccount returns ErrDuplicate if KeyThumbprint is in use.
	CreateAccount(ctx context.Context, a *Account) error
	GetAccount(ctx context.Context, id string) (*Account, error)
	GetAccountByThumbprint(ctx context.Context, thumbprint string) (*Account, error)
	// UpdateAccount also re-indexes KeyThumbprint (key rollover) and
	// returns ErrDuplicate if the new thumbprint belongs to another account.
	UpdateAccount(ctx context.Context, a *Account) error

	// CreateOrder stores an order and its new authorizations atomically.
	CreateOrder(ctx context.Context, o *Order, authzs []*Authorization) error
	GetOrder(ctx context.Context, id string) (*Order, error)
	UpdateOrder(ctx context.Context, o *Order) error
	// ListOrderIDs returns the IDs of an account's orders, oldest first.
	ListOrderIDs(ctx context.Context, accountID string) ([]string, error)
	// CountPendingOrders counts the account's orders whose stored status is
	// pending or ready and that have not expired at now.
	CountPendingOrders(ctx context.Context, accountID string, now time.Time) (int, error)

	GetAuthorization(ctx context.Context, id string) (*Authorization, error)
	UpdateAuthorization(ctx context.Context, a *Authorization) error
	// FindValidAuthorization returns a valid, unexpired authorization held
	// by the account for the identifier, or ErrNotFound.
	FindValidAuthorization(ctx context.Context, accountID string, id Identifier, now time.Time) (*Authorization, error)

	// CreateCertificate returns ErrDuplicate if Serial is in use.
	CreateCertificate(ctx context.Context, c *Certificate) error
	GetCertificate(ctx context.Context, id string) (*Certificate, error)
	GetCertificateBySerial(ctx context.Context, serial string) (*Certificate, error)
	UpdateCertificate(ctx context.Context, c *Certificate) error
}

// MemoryStore is an in-memory, concurrency-safe Store. It is suitable for a
// single replica and for tests.
type MemoryStore struct {
	mu         sync.Mutex
	nonces     map[string]time.Time
	accounts   map[string]*Account
	byThumb    map[string]string
	orders     map[string]*Order
	orderIDs   map[string][]string
	authzs     map[string]*Authorization
	certs      map[string]*Certificate
	certSerial map[string]string
	lastPrune  time.Time
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		nonces:     map[string]time.Time{},
		accounts:   map[string]*Account{},
		byThumb:    map[string]string{},
		orders:     map[string]*Order{},
		orderIDs:   map[string][]string{},
		authzs:     map[string]*Authorization{},
		certs:      map[string]*Certificate{},
		certSerial: map[string]string{},
	}
}

var _ Store = (*MemoryStore)(nil)

func (m *MemoryStore) AddNonce(_ context.Context, nonce string, expires time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if now.Sub(m.lastPrune) > time.Minute {
		for n, exp := range m.nonces {
			if now.After(exp) {
				delete(m.nonces, n)
			}
		}
		m.lastPrune = now
	}
	m.nonces[nonce] = expires
	return nil
}

func (m *MemoryStore) ConsumeNonce(_ context.Context, nonce string, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	exp, ok := m.nonces[nonce]
	if !ok {
		return false, nil
	}
	delete(m.nonces, nonce)
	return !now.After(exp), nil
}

func copyAccount(a *Account) *Account {
	c := *a
	c.Contact = slices.Clone(a.Contact)
	c.KeyJWK = slices.Clone(a.KeyJWK)
	return &c
}

func copyProblem(p *Problem) *Problem {
	if p == nil {
		return nil
	}
	c := *p
	c.Subproblems = slices.Clone(p.Subproblems)
	c.Algorithms = slices.Clone(p.Algorithms)
	if p.Identifier != nil {
		id := *p.Identifier
		c.Identifier = &id
	}
	return &c
}

func copyOrder(o *Order) *Order {
	c := *o
	c.Identifiers = slices.Clone(o.Identifiers)
	c.AuthzIDs = slices.Clone(o.AuthzIDs)
	c.Error = copyProblem(o.Error)
	return &c
}

func copyAuthz(a *Authorization) *Authorization {
	c := *a
	c.Challenges = slices.Clone(a.Challenges)
	for i := range c.Challenges {
		c.Challenges[i].Error = copyProblem(c.Challenges[i].Error)
	}
	return &c
}

func copyCert(c *Certificate) *Certificate {
	n := *c
	n.ChainPEM = slices.Clone(c.ChainPEM)
	n.LeafDER = slices.Clone(c.LeafDER)
	return &n
}

func (m *MemoryStore) CreateAccount(_ context.Context, a *Account) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byThumb[a.KeyThumbprint]; ok {
		return ErrDuplicate
	}
	if _, ok := m.accounts[a.ID]; ok {
		return ErrDuplicate
	}
	a.Version = 1
	m.accounts[a.ID] = copyAccount(a)
	m.byThumb[a.KeyThumbprint] = a.ID
	return nil
}

func (m *MemoryStore) GetAccount(_ context.Context, id string) (*Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.accounts[id]
	if !ok {
		return nil, ErrNotFound
	}
	return copyAccount(a), nil
}

func (m *MemoryStore) GetAccountByThumbprint(_ context.Context, thumbprint string) (*Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byThumb[thumbprint]
	if !ok {
		return nil, ErrNotFound
	}
	return copyAccount(m.accounts[id]), nil
}

func (m *MemoryStore) UpdateAccount(_ context.Context, a *Account) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.accounts[a.ID]
	if !ok {
		return ErrNotFound
	}
	if cur.Version != a.Version {
		return ErrStale
	}
	if a.KeyThumbprint != cur.KeyThumbprint {
		if owner, ok := m.byThumb[a.KeyThumbprint]; ok && owner != a.ID {
			return ErrDuplicate
		}
		delete(m.byThumb, cur.KeyThumbprint)
		m.byThumb[a.KeyThumbprint] = a.ID
	}
	a.Version++
	m.accounts[a.ID] = copyAccount(a)
	return nil
}

func (m *MemoryStore) CreateOrder(_ context.Context, o *Order, authzs []*Authorization) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.orders[o.ID]; ok {
		return ErrDuplicate
	}
	for _, az := range authzs {
		if _, ok := m.authzs[az.ID]; ok {
			return ErrDuplicate
		}
	}
	for _, az := range authzs {
		az.Version = 1
		m.authzs[az.ID] = copyAuthz(az)
	}
	o.Version = 1
	m.orders[o.ID] = copyOrder(o)
	m.orderIDs[o.AccountID] = append(m.orderIDs[o.AccountID], o.ID)
	return nil
}

func (m *MemoryStore) GetOrder(_ context.Context, id string) (*Order, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.orders[id]
	if !ok {
		return nil, ErrNotFound
	}
	return copyOrder(o), nil
}

func (m *MemoryStore) UpdateOrder(_ context.Context, o *Order) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.orders[o.ID]
	if !ok {
		return ErrNotFound
	}
	if cur.Version != o.Version {
		return ErrStale
	}
	o.Version++
	m.orders[o.ID] = copyOrder(o)
	return nil
}

func (m *MemoryStore) ListOrderIDs(_ context.Context, accountID string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.orderIDs[accountID]), nil
}

func (m *MemoryStore) CountPendingOrders(_ context.Context, accountID string, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, id := range m.orderIDs[accountID] {
		o := m.orders[id]
		if (o.Status == StatusPending || o.Status == StatusReady) && now.Before(o.Expires) {
			n++
		}
	}
	return n, nil
}

func (m *MemoryStore) GetAuthorization(_ context.Context, id string) (*Authorization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.authzs[id]
	if !ok {
		return nil, ErrNotFound
	}
	return copyAuthz(a), nil
}

func (m *MemoryStore) UpdateAuthorization(_ context.Context, a *Authorization) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.authzs[a.ID]
	if !ok {
		return ErrNotFound
	}
	if cur.Version != a.Version {
		return ErrStale
	}
	a.Version++
	m.authzs[a.ID] = copyAuthz(a)
	return nil
}

func (m *MemoryStore) FindValidAuthorization(_ context.Context, accountID string, id Identifier, now time.Time) (*Authorization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.authzs {
		if a.AccountID == accountID && a.Identifier == id && a.Status == StatusValid && now.Before(a.Expires) {
			return copyAuthz(a), nil
		}
	}
	return nil, ErrNotFound
}

func (m *MemoryStore) CreateCertificate(_ context.Context, c *Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.certs[c.ID]; ok {
		return ErrDuplicate
	}
	if _, ok := m.certSerial[c.Serial]; ok {
		return ErrDuplicate
	}
	c.Version = 1
	m.certs[c.ID] = copyCert(c)
	m.certSerial[c.Serial] = c.ID
	return nil
}

func (m *MemoryStore) GetCertificate(_ context.Context, id string) (*Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.certs[id]
	if !ok {
		return nil, ErrNotFound
	}
	return copyCert(c), nil
}

func (m *MemoryStore) GetCertificateBySerial(_ context.Context, serial string) (*Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.certSerial[serial]
	if !ok {
		return nil, ErrNotFound
	}
	return copyCert(m.certs[id]), nil
}

func (m *MemoryStore) UpdateCertificate(_ context.Context, c *Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.certs[c.ID]
	if !ok {
		return ErrNotFound
	}
	if cur.Version != c.Version {
		return ErrStale
	}
	if cur.Serial != c.Serial {
		return ErrDuplicate
	}
	c.Version++
	m.certs[c.ID] = copyCert(c)
	return nil
}
