package memory

import (
	"context"
	"sort"

	"github.com/worlddrknss/citadel/internal/store"
)

// memAnomalies holds agent anomaly settings and detected anomalies. All
// access is under Store.mu.
type memAnomalies struct {
	settings  map[string]store.AgentAnomalySettings // account\x00agent -> settings
	anomalies []store.AgentAnomaly
}

func (s *Store) anomaliesLocked() *memAnomalies {
	if s.anomalies == nil {
		s.anomalies = &memAnomalies{settings: map[string]store.AgentAnomalySettings{}}
	}
	return s.anomalies
}

func (s *Store) GetAgentAnomalySettings(_ context.Context, accountID, agentID string) (store.AgentAnomalySettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.anomaliesLocked().settings[credKey(accountID, agentID)]; ok {
		return st, nil
	}
	return store.AgentAnomalySettings{AccountID: accountID, AgentID: agentID}, nil
}

func (s *Store) PutAgentAnomalySettings(_ context.Context, st store.AgentAnomalySettings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.agentsLocked().agentIn(st.AccountID, st.AgentID); !ok {
		return store.ErrAgentNotFound
	}
	st.UpdatedAt = st.UpdatedAt.UTC()
	s.anomaliesLocked().settings[credKey(st.AccountID, st.AgentID)] = st
	return nil
}

func (s *Store) RecordAgentAnomaly(_ context.Context, a store.AgentAnomaly) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.agentsLocked().agentIn(a.AccountID, a.AgentID); !ok {
		return store.ErrAgentNotFound
	}
	m := s.anomaliesLocked()
	a.Hour, a.DetectedAt = a.Hour.UTC(), a.DetectedAt.UTC()
	for _, o := range m.anomalies {
		if o.AccountID == a.AccountID && o.AgentID == a.AgentID && o.Kind == a.Kind && o.Hour.Equal(a.Hour) {
			return store.ErrAgentAnomalyDuplicate
		}
	}
	m.anomalies = append(m.anomalies, a)
	return nil
}

func (s *Store) MarkAgentAnomalySuspended(_ context.Context, accountID, anomalyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.anomaliesLocked()
	for i := range m.anomalies {
		if m.anomalies[i].AccountID == accountID && m.anomalies[i].AnomalyID == anomalyID {
			m.anomalies[i].Suspended = true
		}
	}
	return nil
}

func (s *Store) ListAgentAnomalies(_ context.Context, accountID, agentID string, limit int) ([]store.AgentAnomaly, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	out := []store.AgentAnomaly{}
	for _, a := range s.anomaliesLocked().anomalies {
		if a.AccountID == accountID && a.AgentID == agentID {
			out = append(out, a)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].DetectedAt.Equal(out[j].DetectedAt) {
			return out[i].DetectedAt.After(out[j].DetectedAt)
		}
		return out[i].AnomalyID < out[j].AnomalyID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
