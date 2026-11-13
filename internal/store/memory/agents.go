package memory

import (
	"context"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// memAgents is the in-memory agent state.
type memAgents struct {
	agents      map[string]store.Agent        // agentID -> agent
	tokens      map[string]store.AgentToken   // tokenID -> token
	bindings    map[string]store.AgentBinding // bindingID -> binding
	credentials map[string]store.AgentCredential
	grants      map[string]store.AgentGrant // grantID -> grant
	settings    map[string]store.AgentSettings
	requests    map[string]store.AgentAccessRequest // requestID -> request
	leases      map[string]store.AgentLease         // leaseID -> lease
}

func credKey(accountID, name string) string { return accountID + "\x00" + name }

// agentsLocked returns the agent state, creating it on first use. s.mu must
// be held.
func (s *Store) agentsLocked() *memAgents {
	if s.agents == nil {
		s.agents = &memAgents{
			agents: map[string]store.Agent{}, tokens: map[string]store.AgentToken{}, bindings: map[string]store.AgentBinding{},
			credentials: map[string]store.AgentCredential{}, grants: map[string]store.AgentGrant{}, settings: map[string]store.AgentSettings{},
			requests: map[string]store.AgentAccessRequest{}, leases: map[string]store.AgentLease{},
		}
	}
	return s.agents
}

func cloneAgent(a store.Agent) store.Agent {
	a.Labels = maps.Clone(a.Labels)
	a.LastUsedAt, a.StatusChangedAt = cloneTime(a.LastUsedAt), cloneTime(a.StatusChangedAt)
	return a
}

func cloneToken(t store.AgentToken) store.AgentToken {
	t.ExpiresAt, t.RevokedAt, t.LastUsedAt = cloneTime(t.ExpiresAt), cloneTime(t.RevokedAt), cloneTime(t.LastUsedAt)
	return t
}

func cloneCredential(c store.AgentCredential) store.AgentCredential {
	c.AllowedHosts, c.AllowedMethods = slices.Clone(c.AllowedHosts), slices.Clone(c.AllowedMethods)
	c.AllowedPathPrefixes, c.AllowedCIDRs = slices.Clone(c.AllowedPathPrefixes), slices.Clone(c.AllowedCIDRs)
	return c
}

func cloneGrant(g store.AgentGrant) store.AgentGrant {
	g.Actions, g.WindowDays = slices.Clone(g.Actions), slices.Clone(g.WindowDays)
	g.NotBefore, g.NotAfter = cloneTime(g.NotBefore), cloneTime(g.NotAfter)
	if g.RequiresApproval != nil {
		v := *g.RequiresApproval
		g.RequiresApproval = &v
	}
	if g.LeaseTTLSeconds != nil {
		v := *g.LeaseTTLSeconds
		g.LeaseTTLSeconds = &v
	}
	return g
}

func (m *memAgents) agentIn(accountID, agentID string) (store.Agent, bool) {
	a, ok := m.agents[agentID]
	if !ok || a.AccountID != accountID {
		return store.Agent{}, false
	}
	return a, true
}

func (s *Store) CreateAgent(_ context.Context, a store.Agent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.agentsLocked()
	if _, dup := m.agents[a.AgentID]; dup {
		return store.ErrAgentExists
	}
	for _, o := range m.agents {
		if o.AccountID == a.AccountID && strings.EqualFold(o.Name, a.Name) {
			return store.ErrAgentExists
		}
	}
	m.agents[a.AgentID] = cloneAgent(a)
	return nil
}

func (s *Store) GetAgent(_ context.Context, accountID, agentID string) (store.Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agentsLocked().agentIn(accountID, agentID)
	if !ok {
		return store.Agent{}, store.ErrAgentNotFound
	}
	return cloneAgent(a), nil
}

func (s *Store) LookupAgent(_ context.Context, agentID string) (store.Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agentsLocked().agents[agentID]
	if !ok {
		return store.Agent{}, store.ErrAgentNotFound
	}
	return cloneAgent(a), nil
}

func (s *Store) ListAgents(_ context.Context, accountID string) ([]store.Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []store.Agent{}
	for _, a := range s.agentsLocked().agents {
		if a.AccountID == accountID {
			out = append(out, cloneAgent(a))
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

func (s *Store) UpdateAgent(_ context.Context, a store.Agent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.agentsLocked()
	cur, ok := m.agentIn(a.AccountID, a.AgentID)
	if !ok {
		return store.ErrAgentNotFound
	}
	for _, o := range m.agents {
		if o.AgentID != a.AgentID && o.AccountID == a.AccountID && strings.EqualFold(o.Name, a.Name) {
			return store.ErrAgentExists
		}
	}
	cur.Name, cur.Description, cur.Owner, cur.Labels, cur.UpdatedAt = a.Name, a.Description, a.Owner, maps.Clone(a.Labels), a.UpdatedAt
	cur.RequireFederation = a.RequireFederation
	m.agents[a.AgentID] = cur
	return nil
}

func (s *Store) SetAgentStatus(_ context.Context, accountID, agentID, status, by, reason string, at time.Time) (store.Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.agentsLocked()
	a, ok := m.agentIn(accountID, agentID)
	if !ok {
		return store.Agent{}, store.ErrAgentNotFound
	}
	if a.Status == store.AgentStatusRevoked {
		return store.Agent{}, store.ErrAgentRevoked
	}
	a.Status, a.StatusChangedBy, a.StatusReason, a.UpdatedAt = status, by, reason, at
	a.StatusChangedAt = &at
	m.agents[agentID] = a
	if status == store.AgentStatusRevoked {
		for id, t := range m.tokens {
			if t.AgentID == agentID && t.RevokedAt == nil {
				t.RevokedAt, t.RevokedBy = &at, by
				m.tokens[id] = t
			}
		}
	}
	return cloneAgent(a), nil
}

func (s *Store) DeleteAgent(_ context.Context, accountID, agentID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.agentsLocked()
	if _, ok := m.agentIn(accountID, agentID); !ok {
		return store.ErrAgentNotFound
	}
	delete(m.agents, agentID)
	for id, t := range m.tokens {
		if t.AgentID == agentID {
			delete(m.tokens, id)
		}
	}
	for id, b := range m.bindings {
		if b.AgentID == agentID {
			delete(m.bindings, id)
		}
	}
	for id, g := range m.grants {
		if g.AgentID == agentID {
			delete(m.grants, id)
		}
	}
	for id, r := range m.requests {
		if r.AgentID == agentID {
			delete(m.requests, id)
		}
	}
	for id, l := range m.leases {
		if l.AgentID == agentID {
			delete(m.leases, id)
		}
	}
	return nil
}

func (s *Store) TouchAgentUsed(_ context.Context, accountID, agentID, tokenID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.agentsLocked()
	a, ok := m.agentIn(accountID, agentID)
	if !ok {
		return store.ErrAgentNotFound
	}
	a.LastUsedAt = &at
	m.agents[agentID] = a
	if t, ok := m.tokens[tokenID]; ok && tokenID != "" && t.AgentID == agentID {
		t.LastUsedAt = &at
		m.tokens[tokenID] = t
	}
	return nil
}

func (s *Store) CreateAgentToken(_ context.Context, t store.AgentToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.agentsLocked()
	if _, ok := m.agentIn(t.AccountID, t.AgentID); !ok {
		return store.ErrAgentNotFound
	}
	m.tokens[t.TokenID] = cloneToken(t)
	return nil
}

func sortTokens(out []store.AgentToken) {
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].TokenID < out[j].TokenID
	})
}

func (s *Store) ListAgentTokens(_ context.Context, accountID, agentID string) ([]store.AgentToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []store.AgentToken{}
	for _, t := range s.agentsLocked().tokens {
		if t.AccountID == accountID && t.AgentID == agentID {
			out = append(out, cloneToken(t))
		}
	}
	sortTokens(out)
	return out, nil
}

func (s *Store) FindAgentTokens(_ context.Context, agentID, hint string) ([]store.AgentToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []store.AgentToken{}
	for _, t := range s.agentsLocked().tokens {
		if t.AgentID == agentID && t.Hint == hint {
			out = append(out, cloneToken(t))
		}
	}
	sortTokens(out)
	return out, nil
}

func (s *Store) RevokeAgentToken(_ context.Context, accountID, agentID, tokenID, by string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.agentsLocked()
	t, ok := m.tokens[tokenID]
	if !ok || t.AccountID != accountID || t.AgentID != agentID {
		return store.ErrAgentTokenNotFound
	}
	if t.RevokedAt == nil {
		t.RevokedAt, t.RevokedBy = &at, by
		m.tokens[tokenID] = t
	}
	return nil
}

func (s *Store) CreateAgentBinding(_ context.Context, b store.AgentBinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.agentsLocked()
	if _, ok := m.agentIn(b.AccountID, b.AgentID); !ok {
		return store.ErrAgentNotFound
	}
	for _, o := range m.bindings {
		if o.AgentID == b.AgentID && o.Issuer == b.Issuer && o.Subject == b.Subject && o.Audience == b.Audience {
			return store.ErrAgentBindingExists
		}
	}
	m.bindings[b.BindingID] = b
	return nil
}

func sortBindings(out []store.AgentBinding) {
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].BindingID < out[j].BindingID
	})
}

func (s *Store) ListAgentBindings(_ context.Context, accountID, agentID string) ([]store.AgentBinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []store.AgentBinding{}
	for _, b := range s.agentsLocked().bindings {
		if b.AccountID == accountID && b.AgentID == agentID {
			out = append(out, b)
		}
	}
	sortBindings(out)
	return out, nil
}

func (s *Store) FindAgentBindings(_ context.Context, issuer, subject string) ([]store.AgentBinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []store.AgentBinding{}
	for _, b := range s.agentsLocked().bindings {
		if b.Issuer == issuer && b.Subject == subject {
			out = append(out, b)
		}
	}
	sortBindings(out)
	return out, nil
}

func (s *Store) DeleteAgentBinding(_ context.Context, accountID, agentID, bindingID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.agentsLocked()
	b, ok := m.bindings[bindingID]
	if !ok || b.AccountID != accountID || b.AgentID != agentID {
		return store.ErrAgentBindingNotFound
	}
	delete(m.bindings, bindingID)
	return nil
}

func (s *Store) CreateAgentCredential(_ context.Context, c store.AgentCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.agentsLocked()
	k := credKey(c.AccountID, c.Name)
	if _, dup := m.credentials[k]; dup {
		return store.ErrAgentCredentialExists
	}
	m.credentials[k] = cloneCredential(c)
	return nil
}

func (s *Store) UpdateAgentCredential(_ context.Context, c store.AgentCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.agentsLocked()
	k := credKey(c.AccountID, c.Name)
	cur, ok := m.credentials[k]
	if !ok {
		return store.ErrAgentCredentialNotFound
	}
	c.CreatedAt, c.CreatedBy = cur.CreatedAt, cur.CreatedBy
	m.credentials[k] = cloneCredential(c)
	return nil
}

func (s *Store) GetAgentCredential(_ context.Context, accountID, name string) (store.AgentCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.agentsLocked().credentials[credKey(accountID, name)]
	if !ok {
		return store.AgentCredential{}, store.ErrAgentCredentialNotFound
	}
	return cloneCredential(c), nil
}

func (s *Store) ListAgentCredentials(_ context.Context, accountID string) ([]store.AgentCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []store.AgentCredential{}
	for _, c := range s.agentsLocked().credentials {
		if c.AccountID == accountID {
			out = append(out, cloneCredential(c))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) DeleteAgentCredential(_ context.Context, accountID, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.agentsLocked()
	k := credKey(accountID, name)
	if _, ok := m.credentials[k]; !ok {
		return store.ErrAgentCredentialNotFound
	}
	for _, g := range m.grants {
		if g.AccountID == accountID && g.Credential == name {
			return store.ErrAgentCredentialInUse
		}
	}
	delete(m.credentials, k)
	return nil
}

func (s *Store) PutAgentGrant(_ context.Context, g store.AgentGrant) (store.AgentGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.agentsLocked()
	if _, ok := m.agentIn(g.AccountID, g.AgentID); !ok {
		return store.AgentGrant{}, store.ErrAgentNotFound
	}
	if _, ok := m.credentials[credKey(g.AccountID, g.Credential)]; !ok {
		return store.AgentGrant{}, store.ErrAgentCredentialNotFound
	}
	for id, o := range m.grants {
		if o.AccountID == g.AccountID && o.AgentID == g.AgentID && o.Credential == g.Credential {
			g.GrantID, g.CreatedAt, g.CreatedBy = o.GrantID, o.CreatedAt, o.CreatedBy
			m.grants[id] = cloneGrant(g)
			return cloneGrant(g), nil
		}
	}
	m.grants[g.GrantID] = cloneGrant(g)
	return cloneGrant(g), nil
}

func (s *Store) ListAgentGrants(_ context.Context, accountID, agentID string) ([]store.AgentGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []store.AgentGrant{}
	for _, g := range s.agentsLocked().grants {
		if g.AccountID == accountID && (agentID == "" || g.AgentID == agentID) {
			out = append(out, cloneGrant(g))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].AgentID != out[j].AgentID {
			return out[i].AgentID < out[j].AgentID
		}
		return out[i].Credential < out[j].Credential
	})
	return out, nil
}

func (s *Store) DeleteAgentGrant(_ context.Context, accountID, agentID, grantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.agentsLocked()
	g, ok := m.grants[grantID]
	if !ok || g.AccountID != accountID || g.AgentID != agentID {
		return store.ErrAgentGrantNotFound
	}
	delete(m.grants, grantID)
	return nil
}

func (s *Store) GetAgentSettings(_ context.Context, accountID string) (store.AgentSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.agentsLocked().settings[accountID]
	if !ok {
		return store.AgentSettings{AccountID: accountID}, nil
	}
	st.SuspendedAt = cloneTime(st.SuspendedAt)
	return st, nil
}

func (s *Store) PutAgentSettings(_ context.Context, st store.AgentSettings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st.SuspendedAt = cloneTime(st.SuspendedAt)
	s.agentsLocked().settings[st.AccountID] = st
	return nil
}
