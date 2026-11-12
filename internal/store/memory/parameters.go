package memory

import (
	"context"
	"sort"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// memParameter is the in-memory representation including history and tags.
type memParameter struct {
	rec     store.ParameterRecord
	history []store.ParameterHistoryEntry
	tags    []store.ParamTag
}

func (s *Store) PutParameter(ctx context.Context, rec store.ParameterRecord, overwrite bool) (store.ParameterRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.params == nil {
		s.params = map[string]*memParameter{}
	}
	now := time.Now().UTC()
	existing, ok := s.params[rec.Name]
	if ok {
		if !overwrite {
			return store.ParameterRecord{}, store.ErrParameterExists
		}
		rec.Version = existing.rec.Version + 1
		rec.CreatedAt = existing.rec.CreatedAt
	} else {
		rec.Version = 1
		rec.CreatedAt = now
		existing = &memParameter{}
		s.params[rec.Name] = existing
	}
	rec.UpdatedAt = now
	existing.rec = rec
	existing.history = append(existing.history, store.ParameterHistoryEntry{
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

func (s *Store) GetParameter(ctx context.Context, name string) (store.ParameterRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.params[name]
	if !ok {
		return store.ParameterRecord{}, store.ErrParameterNotFound
	}
	return p.rec, nil
}

func (s *Store) ListParameters(ctx context.Context) ([]store.ParameterRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []store.ParameterRecord
	for _, p := range s.params {
		out = append(out, p.rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) DeleteParameter(ctx context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.params[name]; !ok {
		return store.ErrParameterNotFound
	}
	delete(s.params, name)
	return nil
}

func (s *Store) GetParameterHistory(ctx context.Context, name string) ([]store.ParameterHistoryEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.params[name]
	if !ok {
		return nil, store.ErrParameterNotFound
	}
	out := make([]store.ParameterHistoryEntry, len(p.history))
	copy(out, p.history)
	return out, nil
}

func (s *Store) LabelParameterVersion(ctx context.Context, name string, version int64, labels []string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.params[name]
	if !ok {
		return nil, store.ErrParameterNotFound
	}
	if version == 0 {
		version = p.rec.Version
	}
	var target *store.ParameterHistoryEntry
	for i := range p.history {
		if p.history[i].Version == version {
			target = &p.history[i]
			break
		}
	}
	if target == nil {
		return nil, store.ErrParameterNotFound
	}
	for _, lbl := range labels {
		for i := range p.history {
			if p.history[i].Version != version {
				p.history[i].Labels = store.RemoveLabel(p.history[i].Labels, lbl)
			}
		}
	}
	target.Labels = store.MergeLabels(target.Labels, labels)
	return target.Labels, nil
}

func (s *Store) TagParameter(ctx context.Context, name string, tags []store.ParamTag) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.params[name]
	if !ok {
		return store.ErrParameterNotFound
	}
	for _, t := range tags {
		replaced := false
		for i := range p.tags {
			if p.tags[i].Key == t.Key {
				p.tags[i].Value = t.Value
				replaced = true
				break
			}
		}
		if !replaced {
			p.tags = append(p.tags, t)
		}
	}
	return nil
}

func (s *Store) UntagParameter(ctx context.Context, name string, keys []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.params[name]
	if !ok {
		return store.ErrParameterNotFound
	}
	for _, k := range keys {
		filtered := p.tags[:0]
		for _, t := range p.tags {
			if t.Key != k {
				filtered = append(filtered, t)
			}
		}
		p.tags = filtered
	}
	return nil
}

func (s *Store) ListParameterTags(ctx context.Context, name string) ([]store.ParamTag, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.params[name]
	if !ok {
		return nil, store.ErrParameterNotFound
	}
	out := make([]store.ParamTag, len(p.tags))
	copy(out, p.tags)
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}
