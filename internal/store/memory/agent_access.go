package memory

import (
	"context"
	"slices"
	"sort"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// Agent access requests and leases (2.3). Everything runs under s.mu, so
// opening, deciding and consuming are trivially atomic.

func cloneAccessRequest(r store.AgentAccessRequest) store.AgentAccessRequest {
	r.Actions = slices.Clone(r.Actions)
	r.DecidedAt = cloneTime(r.DecidedAt)
	return r
}

func cloneLease(l store.AgentLease) store.AgentLease {
	l.Actions = slices.Clone(l.Actions)
	if l.UsesLeft != nil {
		v := *l.UsesLeft
		l.UsesLeft = &v
	}
	l.LastUsedAt, l.EndedAt = cloneTime(l.LastUsedAt), cloneTime(l.EndedAt)
	return l
}

func (s *Store) OpenAgentAccessRequest(_ context.Context, r store.AgentAccessRequest, now time.Time) (store.AgentAccessRequest, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.agentsLocked()
	if _, ok := m.agentIn(r.AccountID, r.AgentID); !ok {
		return store.AgentAccessRequest{}, false, store.ErrAgentNotFound
	}
	key := store.AgentActionsKey(r.Actions)
	for id, cur := range m.requests {
		if cur.AccountID != r.AccountID || cur.AgentID != r.AgentID || cur.Credential != r.Credential ||
			cur.TaskID != r.TaskID || store.AgentActionsKey(cur.Actions) != key || cur.Status != store.AgentRequestPending {
			continue
		}
		if !now.Before(cur.ExpiresAt) {
			cur.Status = store.AgentRequestExpired
			m.requests[id] = cur
			continue
		}
		return cloneAccessRequest(cur), false, nil
	}
	r.Actions = slices.Compact(slices.Sorted(slices.Values(r.Actions)))
	m.requests[r.RequestID] = cloneAccessRequest(r)
	return cloneAccessRequest(r), true, nil
}

func (s *Store) GetAgentAccessRequest(_ context.Context, accountID, requestID string) (store.AgentAccessRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.agentsLocked().requests[requestID]
	if !ok || r.AccountID != accountID {
		return store.AgentAccessRequest{}, store.ErrAgentAccessRequestNotFound
	}
	return cloneAccessRequest(r), nil
}

func (s *Store) ListAgentAccessRequests(_ context.Context, accountID string, f store.AgentAccessRequestFilter) ([]store.AgentAccessRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []store.AgentAccessRequest{}
	for _, r := range s.agentsLocked().requests {
		if r.AccountID != accountID || (f.AgentID != "" && r.AgentID != f.AgentID) {
			continue
		}
		if f.Pending && r.EffectiveStatus(f.Now) != store.AgentRequestPending {
			continue
		}
		out = append(out, cloneAccessRequest(r))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].RequestID > out[j].RequestID
	})
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) CountPendingAgentAccessRequests(_ context.Context, accountID, agentID string, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.agentsLocked().requests {
		if r.AccountID == accountID && r.AgentID == agentID && r.EffectiveStatus(now) == store.AgentRequestPending {
			n++
		}
	}
	return n, nil
}

func (s *Store) DecideAgentAccessRequest(_ context.Context, accountID, requestID string, d store.AgentAccessDecision) (store.AgentAccessRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.agentsLocked()
	r, ok := m.requests[requestID]
	if !ok || r.AccountID != accountID {
		return store.AgentAccessRequest{}, store.ErrAgentAccessRequestNotFound
	}
	if r.EffectiveStatus(d.At) != store.AgentRequestPending {
		return store.AgentAccessRequest{}, store.ErrAgentAccessRequestDecided
	}
	at := d.At
	r.Status, r.DecidedAt, r.DecidedBy, r.DecisionComment = d.Status, &at, d.By, d.Comment
	if d.Lease != nil {
		l := cloneLease(*d.Lease)
		l.RequestID = r.RequestID
		m.leases[l.LeaseID] = l
		r.Scope, r.LeaseID = l.Scope, l.LeaseID
	}
	m.requests[requestID] = r
	return cloneAccessRequest(r), nil
}

func (s *Store) CancelAgentAccessRequests(_ context.Context, accountID, agentID, by, comment string, at time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.agentsLocked()
	n := 0
	for id, r := range m.requests {
		if r.AccountID == accountID && r.AgentID == agentID && r.EffectiveStatus(at) == store.AgentRequestPending {
			t := at
			r.Status, r.DecidedAt, r.DecidedBy, r.DecisionComment = store.AgentRequestCancelled, &t, by, comment
			m.requests[id] = r
			n++
		}
	}
	return n, nil
}

func (s *Store) CreateAgentLease(_ context.Context, l store.AgentLease) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.agentsLocked()
	if _, ok := m.agentIn(l.AccountID, l.AgentID); !ok {
		return store.ErrAgentNotFound
	}
	m.leases[l.LeaseID] = cloneLease(l)
	return nil
}

func (s *Store) GetAgentLease(_ context.Context, accountID, leaseID string) (store.AgentLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.agentsLocked().leases[leaseID]
	if !ok || l.AccountID != accountID {
		return store.AgentLease{}, store.ErrAgentLeaseNotFound
	}
	return cloneLease(l), nil
}

func (s *Store) ListAgentLeases(_ context.Context, accountID, agentID string, activeOnly bool, now time.Time) ([]store.AgentLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []store.AgentLease{}
	for _, l := range s.agentsLocked().leases {
		if l.AccountID != accountID || (agentID != "" && l.AgentID != agentID) || (activeOnly && !l.Active(now)) {
			continue
		}
		out = append(out, cloneLease(l))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].LeaseID > out[j].LeaseID
	})
	if len(out) > 500 {
		out = out[:500]
	}
	return out, nil
}

// leaseMatches reports whether l can serve m.
func leaseMatches(l store.AgentLease, m store.AgentLeaseMatch) bool {
	return l.AccountID == m.AccountID && l.AgentID == m.AgentID && l.Credential == m.Credential && l.HasAction(m.Action) &&
		l.Active(m.Now) && (l.Scope != store.AgentLeaseTask || l.TaskID == m.TaskID)
}

// bestLeaseLocked picks the lease ConsumeAgentLease would use.
func (m *memAgents) bestLeaseLocked(match store.AgentLeaseMatch) (store.AgentLease, bool) {
	var (
		best  store.AgentLease
		found bool
	)
	for _, l := range m.leases {
		if !leaseMatches(l, match) {
			continue
		}
		if !found || leaseBefore(l, best) {
			best, found = l, true
		}
	}
	return best, found
}

// leaseBefore orders leases for use: unlimited uses first, then the one
// expiring soonest, then by ID.
func leaseBefore(a, b store.AgentLease) bool {
	if (a.UsesLeft == nil) != (b.UsesLeft == nil) {
		return a.UsesLeft == nil
	}
	if !a.ExpiresAt.Equal(b.ExpiresAt) {
		return a.ExpiresAt.Before(b.ExpiresAt)
	}
	return a.LeaseID < b.LeaseID
}

func (s *Store) FindAgentLease(_ context.Context, match store.AgentLeaseMatch) (store.AgentLease, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.agentsLocked().bestLeaseLocked(match)
	return cloneLease(l), ok, nil
}

func (s *Store) ConsumeAgentLease(_ context.Context, match store.AgentLeaseMatch) (store.AgentLease, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.agentsLocked()
	l, ok := m.bestLeaseLocked(match)
	if !ok {
		return store.AgentLease{}, false, nil
	}
	if l.UsesLeft != nil {
		v := *l.UsesLeft - 1
		l.UsesLeft = &v
	}
	at := match.Now
	l.UseCount++
	l.LastUsedAt = &at
	m.leases[l.LeaseID] = l
	return cloneLease(l), true, nil
}

func (s *Store) EndAgentLease(_ context.Context, accountID, leaseID, by, reason string, at time.Time) (store.AgentLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.agentsLocked()
	l, ok := m.leases[leaseID]
	if !ok || l.AccountID != accountID {
		return store.AgentLease{}, store.ErrAgentLeaseNotFound
	}
	if !l.Active(at) {
		return store.AgentLease{}, store.ErrAgentLeaseEnded
	}
	t := at
	l.EndedAt, l.EndedBy, l.EndedReason = &t, by, reason
	m.leases[leaseID] = l
	return cloneLease(l), nil
}

func (s *Store) EndAgentLeases(_ context.Context, accountID, agentID, by, reason string, at time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.agentsLocked()
	n := 0
	for id, l := range m.leases {
		if l.AccountID != accountID || (agentID != "" && l.AgentID != agentID) || !l.Active(at) {
			continue
		}
		t := at
		l.EndedAt, l.EndedBy, l.EndedReason = &t, by, reason
		m.leases[id] = l
		n++
	}
	return n, nil
}
