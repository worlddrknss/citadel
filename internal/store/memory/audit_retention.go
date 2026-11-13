package memory

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// memRetention is the in-memory retention bookkeeping. Guarded by Store.mu.
type memRetention struct {
	settings map[string]store.AuditRetentionSetting
	anchors  map[string]store.AuditAnchor

	holder     string
	leaseUntil time.Time
	run        store.AuditPruneRun
}

// retention returns the lazily created bookkeeping. Callers hold s.mu.
func (s *Store) retention() *memRetention {
	st := s.auditState()
	if st.retention == nil {
		st.retention = &memRetention{settings: map[string]store.AuditRetentionSetting{}, anchors: map[string]store.AuditAnchor{}}
	}
	return st.retention
}

func (s *Store) GetAuditRetention(_ context.Context, accountID string) (store.AuditRetentionSetting, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.retention().settings[accountID]; ok {
		d := *v.Days
		v.Days = &d
		return v, nil
	}
	return store.AuditRetentionSetting{AccountID: accountID}, nil
}

func (s *Store) PutAuditRetention(_ context.Context, v store.AuditRetentionSetting) error {
	if v.AccountID == "" {
		return errors.New("account is required")
	}
	if v.Days != nil && !store.ValidAuditRetentionDays(*v.Days) {
		return errors.New("retention days out of range")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.retention()
	if v.Days == nil {
		delete(r.settings, v.AccountID)
		return nil
	}
	d := *v.Days
	v.Days = &d
	v.UpdatedAt = time.Now().UTC()
	r.settings[v.AccountID] = v
	return nil
}

func (s *Store) ListAuditRetention(_ context.Context) ([]store.AuditRetentionSetting, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]store.AuditRetentionSetting, 0, len(s.retention().settings))
	for _, v := range s.retention().settings {
		d := *v.Days
		v.Days = &d
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AccountID < out[j].AccountID })
	return out, nil
}

func (s *Store) AuditAccounts(_ context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.auditState().heads))
	for acct := range s.auditState().heads {
		out = append(out, acct)
	}
	sort.Strings(out)
	return out, nil
}

func (s *Store) GetAuditAnchor(_ context.Context, accountID string) (store.AuditAnchor, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.retention().anchors[accountID]
	return a, ok, nil
}

func (s *Store) AuditRetentionStats(_ context.Context, accountID string, cutoff *time.Time) (store.AuditRetentionStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := store.AuditRetentionStats{TableBytes: -1, TableRows: int64(len(s.audit))}
	for _, rec := range s.audit {
		if rec.AccountID != accountID {
			continue
		}
		out.Events++
		if out.Oldest.IsZero() || rec.CreatedAt.Before(out.Oldest) {
			out.Oldest = rec.CreatedAt
		}
		if cutoff != nil && rec.CreatedAt.Before(*cutoff) {
			out.Prunable++
		}
	}
	return out, nil
}

// PruneAuditEvents deletes a batch of accountID's oldest events. The store
// mutex makes it atomic with respect to appends and other prunes.
func (s *Store) PruneAuditEvents(_ context.Context, accountID string, cutoff time.Time, limit int) (store.AuditPruneResult, error) {
	if limit <= 0 {
		return store.AuditPruneResult{}, errors.New("limit must be positive")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.auditState()
	r := s.retention()
	anchor, hasAnchor := r.anchors[accountID]
	res := store.AuditPruneResult{Anchor: anchor}
	if hasAnchor && !store.AuditAnchorValid(st.key, anchor) {
		res.Stop = store.AuditPruneStopBadAnchor
		return res, nil
	}
	head, ok := st.heads[accountID]
	if !ok {
		return res, nil
	}
	after := int64(0)
	if hasAnchor {
		after = anchor.ChainSeq
	}
	var recs []store.AuditRecord
	for _, rec := range s.audit {
		if rec.AccountID == accountID && rec.ChainSeq > after {
			recs = append(recs, rec)
		}
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].ChainSeq < recs[j].ChainSeq })
	if len(recs) > limit {
		recs = recs[:limit]
	}
	undelivered := map[int64]bool{}
	for _, it := range st.outbox {
		if !it.dead {
			undelivered[it.eventID] = true
		}
	}
	cands := make([]store.AuditPruneCandidate, len(recs))
	for i, rec := range recs {
		cands[i] = store.AuditPruneCandidate{Record: rec, Undelivered: undelivered[rec.ID]}
		if rec.Result == store.AuditResultPending && rec.CorrelationID != "" {
			for _, o := range s.audit {
				if o.AccountID == accountID && o.CorrelationID == rec.CorrelationID &&
					o.Result != store.AuditResultPending && !o.CreatedAt.Before(cutoff) {
					cands[i].OutcomeInWindow = true
					break
				}
			}
		}
	}
	n, stop := store.AuditPrunePrefix(st.key, anchor, hasAnchor, cands, cutoff, head.ChainSeq)
	res.Stop = stop
	if n == 0 {
		return res, nil
	}
	last := recs[n-1]
	gone := map[int64]bool{}
	for _, rec := range recs[:n] {
		gone[rec.ID] = true
	}
	kept := s.audit[:0]
	for _, rec := range s.audit {
		if !gone[rec.ID] {
			kept = append(kept, rec)
		}
	}
	s.audit = kept
	outbox := st.outbox[:0]
	for _, it := range st.outbox {
		if !gone[it.eventID] {
			outbox = append(outbox, it)
		}
	}
	st.outbox = outbox
	anchor = store.AuditAnchor{
		AccountID:    accountID,
		ChainSeq:     last.ChainSeq,
		EventID:      last.ID,
		EventHash:    last.EventHash,
		PrunedBefore: last.CreatedAt,
		PrunedEvents: anchor.PrunedEvents + int64(n),
		UpdatedAt:    time.Now().UTC().Truncate(time.Microsecond),
	}
	anchor.MAC = store.AuditAnchorMAC(st.key, anchor)
	r.anchors[accountID] = anchor
	res.Pruned, res.Anchor = int64(n), anchor
	return res, nil
}

func (s *Store) ClaimAuditPruneRun(_ context.Context, holder string, now time.Time, lease time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.retention()
	if r.holder != "" && r.holder != holder && now.Before(r.leaseUntil) {
		return false, nil
	}
	r.holder, r.leaseUntil = holder, now.Add(lease)
	r.run.StartedAt = now.UTC()
	return true, nil
}

func (s *Store) FinishAuditPruneRun(_ context.Context, holder string, run store.AuditPruneRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.retention()
	if r.holder != holder {
		return nil
	}
	r.leaseUntil = time.Time{}
	r.run = run
	return nil
}

func (s *Store) GetAuditPruneRun(_ context.Context) (store.AuditPruneRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.retention().run, nil
}

// TamperAuditAnchorForTest rewrites an account's stored anchor in place.
func (s *Store) TamperAuditAnchorForTest(accountID string, mutate func(*store.AuditAnchor)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.retention().anchors[accountID]
	if ok {
		mutate(&a)
		s.retention().anchors[accountID] = a
	}
	return ok
}
