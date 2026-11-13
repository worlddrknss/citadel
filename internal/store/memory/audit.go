package memory

import (
	"context"
	"crypto/rand"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// memAuditState is the in-memory audit chain bookkeeping. Guarded by Store.mu.
type memAuditState struct {
	key           []byte
	heads         map[string]store.AuditChainHead
	verifications map[string]store.AuditVerification
	streams       map[string]store.AuditStreamConfig
	outbox        []*memOutboxItem
	outboxSeq     int64
	retention     *memRetention
}

type memOutboxItem struct {
	id        int64
	eventID   int64
	attempts  int
	next      time.Time
	lastError string
	dead      bool
}

// auditState returns the lazily created bookkeeping. Callers hold s.mu.
func (s *Store) auditState() *memAuditState {
	if s.auditAux == nil {
		st := &memAuditState{
			heads:         map[string]store.AuditChainHead{},
			verifications: map[string]store.AuditVerification{},
			streams:       map[string]store.AuditStreamConfig{},
		}
		// The chain is always keyed: the configured key, else one derived
		// from the store's master key, else a random per-process key (the
		// in-memory log does not outlive the process anyway).
		switch {
		case len(s.AuditHMACKey) > 0:
			st.key = s.AuditHMACKey
		case len(s.DefaultKey.MasterKeyRaw) > 0:
			st.key = cryptoutil.DeriveAuditHMACKey(s.DefaultKey.MasterKeyRaw)
		default:
			st.key = make([]byte, 32)
			_, _ = rand.Read(st.key)
		}
		s.auditAux = st
	}
	return s.auditAux
}

// RecordAudit appends event to its account's chain.
func (s *Store) RecordAudit(ctx context.Context, event store.AuditEvent) error {
	event = store.SanitizeAuditEvent(event)
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.auditState()
	if event.AccountID == "" {
		event.AccountID = s.accountForContext(ctx)
	}
	head := st.heads[event.AccountID]
	s.auditSeq++
	rec := store.AuditRecord{
		ID:          s.auditSeq,
		ChainSeq:    head.ChainSeq + 1,
		HashVersion: store.AuditHashVersion,
		Action:      event.Action,
		KeyID:       event.KeyID,
		Result:      event.Result,
		ErrorType:   event.ErrorType,
		AuditOrigin: event.AuditOrigin,
		PrevHash:    head.HeadHash,
		CreatedAt:   time.Now().UTC().Truncate(time.Microsecond),
	}
	rec.EventHash = store.AuditMAC(st.key, rec)
	s.audit = append(s.audit, rec)
	st.heads[event.AccountID] = store.AuditChainHead{AccountID: event.AccountID, ChainSeq: rec.ChainSeq, HeadHash: rec.EventHash, HeadID: rec.ID}
	if cfg, ok := st.streams[event.AccountID]; ok && cfg.Enabled {
		st.outboxSeq++
		st.outbox = append(st.outbox, &memOutboxItem{id: st.outboxSeq, eventID: rec.ID, next: time.Now()})
	}
	return nil
}

// ListAuditEvents returns the caller account's most recent events.
func (s *Store) ListAuditEvents(ctx context.Context, limit int) ([]store.AuditRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	return s.QueryAuditEvents(ctx, store.AuditQuery{Limit: limit})
}

func containsFold(hay, needle string) bool {
	return strings.Contains(strings.ToLower(hay), strings.ToLower(needle))
}

func auditMatches(rec store.AuditRecord, account string, q store.AuditQuery) bool {
	if rec.AccountID != account {
		return false
	}
	if q.BeforeID > 0 && rec.ID >= q.BeforeID {
		return false
	}
	if q.From != nil && rec.CreatedAt.Before(*q.From) {
		return false
	}
	if q.To != nil && rec.CreatedAt.After(*q.To) {
		return false
	}
	if q.Actor != "" && !containsFold(rec.Actor, q.Actor) && !containsFold(rec.ActorDisplayName, q.Actor) && !containsFold(rec.AccessKeyID, q.Actor) {
		return false
	}
	if q.Action != "" && !containsFold(rec.Action, q.Action) {
		return false
	}
	if q.Resource != "" && !containsFold(rec.Resource, q.Resource) && !containsFold(rec.KeyID, q.Resource) {
		return false
	}
	if q.Correlation != "" && rec.CorrelationID != q.Correlation {
		return false
	}
	if q.Agent != "" && rec.AgentID != q.Agent {
		return false
	}
	if q.Result != "" && store.NormalizeAuditResult(rec.Result, rec.ErrorType) != q.Result {
		return false
	}
	return true
}

// QueryAuditEvents returns the caller account's events matching q, newest first.
func (s *Store) QueryAuditEvents(ctx context.Context, q store.AuditQuery) ([]store.AuditRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.auditState()
	account := s.accountForContext(ctx)
	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}
	out := []store.AuditRecord{}
	skipped := 0
	for i := len(s.audit) - 1; i >= 0 && len(out) < limit; i-- {
		rec := s.audit[i]
		if !auditMatches(rec, account, q) {
			continue
		}
		if skipped < q.Offset {
			skipped++
			continue
		}
		if rec.HashVersion >= store.AuditHashVersion {
			valid := store.AuditMACValid(st.key, rec)
			rec.HashValid = &valid
		}
		out = append(out, rec)
	}
	return out, nil
}

// CountAuditEvents counts the caller account's events matching q (Limit,
// Offset ignored).
func (s *Store) CountAuditEvents(ctx context.Context, q store.AuditQuery) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	account := s.accountForContext(ctx)
	n := 0
	for _, rec := range s.audit {
		if auditMatches(rec, account, q) {
			n++
		}
	}
	return n, nil
}

// ---- chain verification ----------------------------------------------------

func (s *Store) VerifyAuditChain(ctx context.Context, accountID string, full bool) (store.AuditVerification, error) {
	s.mu.Lock()
	key := s.auditState().key
	s.mu.Unlock()
	return store.RunAuditVerification(ctx, s, key, accountID, full, time.Now())
}

func (s *Store) GetAuditVerification(_ context.Context, accountID string) (store.AuditVerification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.auditState().verifications[accountID]
	if !ok {
		return store.AuditVerification{AccountID: accountID, Status: store.AuditChainNever}, nil
	}
	return v, nil
}

func (s *Store) AuditChainHeadFor(_ context.Context, accountID string) (store.AuditChainHead, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.auditState().heads[accountID]
	return h, ok, nil
}

func (s *Store) AuditChainBatch(_ context.Context, accountID string, afterSeq int64, limit int) ([]store.AuditRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []store.AuditRecord
	for _, rec := range s.audit {
		if rec.AccountID == accountID && rec.ChainSeq > afterSeq {
			out = append(out, rec)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ChainSeq < out[j].ChainSeq })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) AuditEventCount(_ context.Context, accountID string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for _, rec := range s.audit {
		if rec.AccountID == accountID {
			n++
		}
	}
	return n, nil
}

func (s *Store) LoadAuditVerification(_ context.Context, accountID string) (store.AuditVerification, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.auditState().verifications[accountID]
	return v, ok, nil
}

func (s *Store) SaveAuditVerification(_ context.Context, v store.AuditVerification) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditState().verifications[v.AccountID] = v
	return nil
}

// TamperAuditForTest lets tests rewrite a stored event in place.
func (s *Store) TamperAuditForTest(id int64, mutate func(*store.AuditRecord)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.audit {
		if s.audit[i].ID == id {
			mutate(&s.audit[i])
			return true
		}
	}
	return false
}

// ---- SIEM stream -----------------------------------------------------------

func (s *Store) GetAuditStreamConfig(_ context.Context, accountID string) (store.AuditStreamConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, ok := s.auditState().streams[accountID]
	if !ok {
		return store.AuditStreamConfig{AccountID: accountID, Format: "json"}, nil
	}
	cfg.TokenSealed = append([]byte(nil), cfg.TokenSealed...)
	return cfg, nil
}

func (s *Store) PutAuditStreamConfig(_ context.Context, cfg store.AuditStreamConfig) error {
	if cfg.AccountID == "" {
		return errors.New("account is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg.TokenSealed = append([]byte(nil), cfg.TokenSealed...)
	cfg.UpdatedAt = time.Now().UTC()
	s.auditState().streams[cfg.AccountID] = cfg
	return nil
}

func (s *Store) ClaimAuditOutbox(_ context.Context, limit int, lease time.Duration) ([]store.AuditOutboxItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.auditState()
	now := time.Now()
	var out []store.AuditOutboxItem
	for _, it := range st.outbox {
		if len(out) >= limit {
			break
		}
		if it.dead || it.next.After(now) {
			continue
		}
		for _, rec := range s.audit {
			if rec.ID == it.eventID {
				it.next = now.Add(lease)
				out = append(out, store.AuditOutboxItem{ID: it.id, Attempts: it.attempts, Event: rec})
				break
			}
		}
	}
	return out, nil
}

func (s *Store) CompleteAuditOutbox(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.auditState()
	for i, it := range st.outbox {
		if it.id == id {
			st.outbox = append(st.outbox[:i], st.outbox[i+1:]...)
			return nil
		}
	}
	return nil
}

func (s *Store) RetryAuditOutbox(_ context.Context, id int64, next time.Time, lastErr string, dead bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, it := range s.auditState().outbox {
		if it.id == id {
			it.attempts++
			it.next = next
			it.lastError = lastErr
			it.dead = dead
		}
	}
	return nil
}
