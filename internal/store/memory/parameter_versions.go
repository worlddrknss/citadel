package memory

import (
	"context"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// UpdateParameter implements store.ParameterVersionStore.
func (s *Store) UpdateParameter(ctx context.Context, rec store.ParameterRecord, expectedVersion int64) (store.ParameterRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.paramLocked(ctx, rec.Name)
	if !ok {
		return store.ParameterRecord{}, store.ErrParameterNotFound
	}
	if p.rec.Version != expectedVersion {
		return store.ParameterRecord{}, store.ErrParameterVersionConflict
	}
	now := time.Now().UTC()
	rec.Version = p.rec.Version + 1
	rec.CreatedAt = p.rec.CreatedAt
	rec.UpdatedAt = now
	p.rec = rec
	p.history = append(p.history, store.ParameterHistoryEntry{
		Name:        rec.Name,
		Version:     rec.Version,
		Type:        rec.Type,
		Value:       rec.Value,
		IsEncrypted: rec.IsEncrypted,
		KMSKeyID:    rec.KMSKeyID,
		Tier:        rec.Tier,
		Description: rec.Description,
		ModifiedAt:  now,
	})
	return rec, nil
}

// UnlabelParameterVersion implements store.ParameterVersionStore.
func (s *Store) UnlabelParameterVersion(ctx context.Context, name string, version int64, labels []string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.paramLocked(ctx, name)
	if !ok {
		return nil, store.ErrParameterNotFound
	}
	for i := range p.history {
		if p.history[i].Version != version {
			continue
		}
		removed := []string{}
		for _, l := range labels {
			if store.ContainsString(p.history[i].Labels, l) && !store.ContainsString(removed, l) {
				removed = append(removed, l)
				p.history[i].Labels = store.RemoveLabel(p.history[i].Labels, l)
			}
		}
		return removed, nil
	}
	return nil, store.ErrParameterNotFound
}
