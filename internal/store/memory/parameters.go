package memory

import (
	"context"
	"sort"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// memParameter is the in-memory representation including history and tags.
type memParameter struct {
	account string
	rec     store.ParameterRecord
	history []store.ParameterHistoryEntry
	tags    []store.ParamTag
}

// memParamKey scopes a parameter name to its account, so two accounts can
// hold the same name and never see each other's parameters.
func memParamKey(account, name string) string {
	return account + "\x00" + name
}

// paramLocked returns the caller account's parameter. The caller holds s.mu.
func (s *Store) paramLocked(ctx context.Context, name string) (*memParameter, bool) {
	p, ok := s.params[memParamKey(s.accountForContext(ctx), name)]
	return p, ok
}

func (s *Store) PutParameter(ctx context.Context, rec store.ParameterRecord, overwrite bool) (store.ParameterRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.params == nil {
		s.params = map[string]*memParameter{}
	}
	now := time.Now().UTC()
	account := s.accountForContext(ctx)
	existing, ok := s.params[memParamKey(account, rec.Name)]
	if ok {
		if !overwrite {
			return store.ParameterRecord{}, store.ErrParameterExists
		}
		rec.Version = existing.rec.Version + 1
		rec.CreatedAt = existing.rec.CreatedAt
	} else {
		rec.Version = 1
		rec.CreatedAt = now
		existing = &memParameter{account: account}
		s.params[memParamKey(account, rec.Name)] = existing
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
	p, ok := s.paramLocked(ctx, name)
	if !ok {
		return store.ParameterRecord{}, store.ErrParameterNotFound
	}
	return p.rec, nil
}

func (s *Store) ListParameters(ctx context.Context) ([]store.ParameterRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	account := s.accountForContext(ctx)
	var out []store.ParameterRecord
	for _, p := range s.params {
		if p.account == account {
			out = append(out, p.rec)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) DeleteParameter(ctx context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := memParamKey(s.accountForContext(ctx), name)
	if _, ok := s.params[key]; !ok {
		return store.ErrParameterNotFound
	}
	delete(s.params, key)
	return nil
}

func (s *Store) GetParameterHistory(ctx context.Context, name string) ([]store.ParameterHistoryEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.paramLocked(ctx, name)
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
	p, ok := s.paramLocked(ctx, name)
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
	p, ok := s.paramLocked(ctx, name)
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
	p, ok := s.paramLocked(ctx, name)
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
	p, ok := s.paramLocked(ctx, name)
	if !ok {
		return nil, store.ErrParameterNotFound
	}
	out := make([]store.ParamTag, len(p.tags))
	copy(out, p.tags)
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}
