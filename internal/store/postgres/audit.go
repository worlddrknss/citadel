package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// auditChainKey is the configured audit HMAC key, else one HKDF-derived from
// the wrapping key. Nil only when neither is set, in which case appends fail.
func auditChainKey(opts Options) []byte {
	if len(opts.AuditHMACKey) > 0 {
		return opts.AuditHMACKey
	}
	if len(opts.WrappingKey) > 0 {
		return cryptoutil.DeriveAuditHMACKey(opts.WrappingKey)
	}
	return nil
}

var errNoAuditKey = errors.New("audit chain key is not configured")

// migrateAuditAccounts assigns events that predate account tracking to the
// deployment account when migration 0200 could not (the identity was not
// recorded yet), and gives that account a chain head.
func (s *Store) migrateAuditAccounts(ctx context.Context) error {
	// Runs on every start and is idempotent. Besides events that predate
	// account tracking, it repairs events written by a 1.x replica that kept
	// serving during a rolling upgrade: those rows have no account and no
	// chain position (1.x doesn't know the columns).
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 1. Number unnumbered rows after their account's current maximum.
	if _, err := tx.ExecContext(ctx, `
UPDATE kms_audit_events e SET chain_seq = b.m + n.rn
FROM (SELECT id, account_id, ROW_NUMBER() OVER (PARTITION BY account_id ORDER BY id) AS rn
      FROM kms_audit_events WHERE chain_seq IS NULL) n
JOIN (SELECT account_id, COALESCE(MAX(chain_seq), 0) AS m FROM kms_audit_events GROUP BY account_id) b
  ON b.account_id = n.account_id
WHERE e.id = n.id`); err != nil {
		return fmt.Errorf("number audit events: %w", err)
	}

	// 2. Move unattributed rows into the deployment account, numbered after
	// its existing rows so (account_id, chain_seq) stays unique.
	if _, err := tx.ExecContext(ctx, `
UPDATE kms_audit_events e
SET account_id = $1,
    chain_seq = (SELECT COALESCE(MAX(chain_seq), 0) FROM kms_audit_events WHERE account_id = $1) + m.rn
FROM (SELECT id, ROW_NUMBER() OVER (ORDER BY id) AS rn FROM kms_audit_events WHERE account_id = '') m
WHERE e.id = m.id`, s.accountID); err != nil {
		return fmt.Errorf("attribute audit events: %w", err)
	}

	// Legacy rows (hash_version 1) use the 2.0 result and actor vocabulary.
	if _, err := tx.ExecContext(ctx, `UPDATE kms_audit_events SET result = 'success' WHERE hash_version = 1 AND result = 'ok'`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE kms_audit_events SET actor_type = 'legacy' WHERE hash_version = 1 AND actor_type = ''`); err != nil {
		return err
	}

	// 3. Every chain head points at its account's last event. Advancing it
	// matters: otherwise the next append would reuse a position just taken
	// by a repaired row and fail the unique index.
	if _, err := tx.ExecContext(ctx, `
INSERT INTO audit_chain_heads (account_id, chain_seq, head_hash, head_event_id)
SELECT DISTINCT ON (account_id) account_id, chain_seq, COALESCE(event_hash, ''), id
FROM kms_audit_events
WHERE account_id <> '' AND chain_seq IS NOT NULL
ORDER BY account_id, chain_seq DESC
ON CONFLICT (account_id) DO UPDATE
SET chain_seq = EXCLUDED.chain_seq, head_hash = EXCLUDED.head_hash, head_event_id = EXCLUDED.head_event_id, updated_at = NOW()
WHERE audit_chain_heads.chain_seq < EXCLUDED.chain_seq`); err != nil {
		return fmt.Errorf("advance audit chain heads: %w", err)
	}
	return tx.Commit()
}

// RecordAudit appends event to its account's chain. The chain head row is
// locked FOR UPDATE, so appends to one account are serialized across every
// replica; the unique (account_id, chain_seq) index backs that up. Delivery
// to the account's SIEM stream is queued in the same transaction.
func (s *Store) RecordAudit(ctx context.Context, event store.AuditEvent) error {
	if len(s.auditHMACKey) == 0 {
		return errNoAuditKey
	}
	event = store.SanitizeAuditEvent(event)
	if event.AccountID == "" {
		event.AccountID = s.accountForContext(ctx)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Create the head on first use, from the newest existing event if any.
	if _, err := tx.ExecContext(ctx, `
INSERT INTO audit_chain_heads (account_id, chain_seq, head_hash, head_event_id)
SELECT $1, COALESCE(e.chain_seq, 0), COALESCE(e.event_hash, ''), COALESCE(e.id, 0)
FROM (SELECT 1) one
LEFT JOIN LATERAL (
	SELECT chain_seq, event_hash, id FROM kms_audit_events
	WHERE account_id = $1 AND chain_seq IS NOT NULL ORDER BY chain_seq DESC LIMIT 1
) e ON TRUE
ON CONFLICT (account_id) DO NOTHING`, event.AccountID); err != nil {
		return fmt.Errorf("init audit chain head: %w", err)
	}
	var head store.AuditChainHead
	if err := tx.QueryRowContext(ctx,
		`SELECT chain_seq, head_hash FROM audit_chain_heads WHERE account_id = $1 FOR UPDATE`,
		event.AccountID).Scan(&head.ChainSeq, &head.HeadHash); err != nil {
		return fmt.Errorf("lock audit chain head: %w", err)
	}

	rec := store.AuditRecord{
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
	rec.EventHash = store.AuditMAC(s.auditHMACKey, rec)
	if err := tx.QueryRowContext(ctx, `
INSERT INTO kms_audit_events (account_id, chain_seq, hash_version, action, key_id, result, error_type,
	actor, actor_type, actor_display_name, access_key_id, resource, source_ip, user_agent,
	prev_hash, event_hash, created_at, correlation_id, agent_id, agent_owner, task_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
RETURNING id`,
		rec.AccountID, rec.ChainSeq, rec.HashVersion, rec.Action, rec.KeyID, rec.Result, rec.ErrorType,
		rec.Actor, rec.ActorType, rec.ActorDisplayName, rec.AccessKeyID, rec.Resource, rec.SourceIP, rec.UserAgent,
		rec.PrevHash, rec.EventHash, rec.CreatedAt, rec.CorrelationID, rec.AgentID, rec.AgentOwner, rec.TaskID).Scan(&rec.ID); err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE audit_chain_heads SET chain_seq = $2, head_hash = $3, head_event_id = $4, updated_at = NOW() WHERE account_id = $1`,
		rec.AccountID, rec.ChainSeq, rec.EventHash, rec.ID); err != nil {
		return fmt.Errorf("advance audit chain head: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO audit_stream_outbox (event_id, account_id)
SELECT $1, account_id FROM audit_stream_settings WHERE account_id = $2 AND enabled`,
		rec.ID, rec.AccountID); err != nil {
		return fmt.Errorf("queue audit stream delivery: %w", err)
	}
	return tx.Commit()
}

var auditColumns = prefixColumns("")

// leadingScanner scans extra leading columns before an audit record's.
type leadingScanner struct {
	row  rowScanner
	lead []any
}

func (l leadingScanner) Scan(dest ...any) error {
	return l.row.Scan(append(append([]any{}, l.lead...), dest...)...)
}

func scanAuditRecord(row rowScanner) (store.AuditRecord, error) {
	var r store.AuditRecord
	err := row.Scan(&r.ID, &r.AccountID, &r.ChainSeq, &r.HashVersion, &r.Action, &r.KeyID, &r.Result,
		&r.ErrorType, &r.Actor, &r.ActorType, &r.ActorDisplayName, &r.AccessKeyID, &r.Resource,
		&r.SourceIP, &r.UserAgent, &r.PrevHash, &r.EventHash, &r.CreatedAt, &r.CorrelationID,
		&r.AgentID, &r.AgentOwner, &r.TaskID)
	r.CreatedAt = r.CreatedAt.UTC()
	return r, err
}

// ListAuditEvents returns the caller account's most recent events.
func (s *Store) ListAuditEvents(ctx context.Context, limit int) ([]store.AuditRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	return s.QueryAuditEvents(ctx, store.AuditQuery{Limit: limit})
}

// likeContains builds an ILIKE "contains" pattern with LIKE metacharacters
// escaped.
func likeContains(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(v) + "%"
}

// auditWhere renders q (scoped to account) as a WHERE clause.
func auditWhere(account string, q store.AuditQuery) (string, []any) {
	conds := []string{"account_id = $1"}
	args := []any{account}
	add := func(cond string, v any) {
		args = append(args, v)
		conds = append(conds, strings.ReplaceAll(cond, "?", fmt.Sprintf("$%d", len(args))))
	}
	if q.BeforeID > 0 {
		add("id < ?", q.BeforeID)
	}
	if q.From != nil {
		add("created_at >= ?", q.From.UTC())
	}
	if q.To != nil {
		add("created_at <= ?", q.To.UTC())
	}
	if q.Actor != "" {
		// Every "?" in one condition is the same argument.
		add(`(actor ILIKE ? OR actor_display_name ILIKE ? OR access_key_id ILIKE ?)`, likeContains(q.Actor))
	}
	if q.Action != "" {
		add("action ILIKE ?", likeContains(q.Action))
	}
	if q.Resource != "" {
		add("(resource ILIKE ? OR COALESCE(key_id, '') ILIKE ?)", likeContains(q.Resource))
	}
	if q.Result != "" {
		add("result = ?", q.Result)
	}
	if q.Correlation != "" {
		add("correlation_id = ?", q.Correlation)
	}
	if q.Agent != "" {
		add("agent_id = ?", q.Agent)
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// QueryAuditEvents returns the caller account's events matching q, newest
// first. Every read is scoped to the caller account (or the deployment
// account when the context has none).
func (s *Store) QueryAuditEvents(ctx context.Context, q store.AuditQuery) ([]store.AuditRecord, error) {
	where, args := auditWhere(s.accountForContext(ctx), q)
	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}
	args = append(args, limit, q.Offset)
	query := `SELECT ` + auditColumns + ` FROM kms_audit_events` + where +
		fmt.Sprintf(` ORDER BY id DESC LIMIT $%d OFFSET $%d`, len(args)-1, len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]store.AuditRecord, 0, limit)
	for rows.Next() {
		rec, err := scanAuditRecord(rows)
		if err != nil {
			return nil, err
		}
		if rec.HashVersion >= store.AuditHashVersion {
			valid := store.AuditMACValid(s.auditHMACKey, rec)
			rec.HashValid = &valid
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// CountAuditEvents counts the caller account's events matching q.
func (s *Store) CountAuditEvents(ctx context.Context, q store.AuditQuery) (int, error) {
	where, args := auditWhere(s.accountForContext(ctx), q)
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM kms_audit_events`+where, args...).Scan(&n)
	return n, err
}

// ---- chain verification ----------------------------------------------------

func (s *Store) VerifyAuditChain(ctx context.Context, accountID string, full bool) (store.AuditVerification, error) {
	if len(s.auditHMACKey) == 0 {
		return store.AuditVerification{}, errNoAuditKey
	}
	return store.RunAuditVerification(ctx, s, s.auditHMACKey, accountID, full, time.Now())
}

func (s *Store) GetAuditVerification(ctx context.Context, accountID string) (store.AuditVerification, error) {
	v, ok, err := s.LoadAuditVerification(ctx, accountID)
	if err != nil {
		return store.AuditVerification{}, err
	}
	if !ok {
		return store.AuditVerification{AccountID: accountID, Status: store.AuditChainNever}, nil
	}
	return v, nil
}

func (s *Store) AuditChainHeadFor(ctx context.Context, accountID string) (store.AuditChainHead, bool, error) {
	h := store.AuditChainHead{AccountID: accountID}
	err := s.db.QueryRowContext(ctx,
		`SELECT chain_seq, head_hash, head_event_id FROM audit_chain_heads WHERE account_id = $1`, accountID).
		Scan(&h.ChainSeq, &h.HeadHash, &h.HeadID)
	if errors.Is(err, sql.ErrNoRows) {
		return h, false, nil
	}
	return h, err == nil, err
}

func (s *Store) AuditChainBatch(ctx context.Context, accountID string, afterSeq int64, limit int) ([]store.AuditRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+auditColumns+` FROM kms_audit_events
WHERE account_id = $1 AND chain_seq > $2 ORDER BY chain_seq LIMIT $3`, accountID, afterSeq, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.AuditRecord
	for rows.Next() {
		rec, err := scanAuditRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *Store) AuditEventCount(ctx context.Context, accountID string) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM kms_audit_events WHERE account_id = $1`, accountID).Scan(&n)
	return n, err
}

func (s *Store) LoadAuditVerification(ctx context.Context, accountID string) (store.AuditVerification, bool, error) {
	v := store.AuditVerification{AccountID: accountID}
	err := s.db.QueryRowContext(ctx, `
SELECT status, verified_seq, verified_event_id, verified_hash, head_hash, broken_event_id, broken_seq, total_events, checked_at,
	legacy_events, legacy_link_breaks, first_legacy_break_seq, first_legacy_break_event_id
FROM audit_chain_verifications WHERE account_id = $1`, accountID).
		Scan(&v.Status, &v.VerifiedSeq, &v.VerifiedID, &v.VerifiedHash, &v.HeadHash, &v.BrokenID, &v.BrokenSeq, &v.TotalEvents, &v.CheckedAt,
			&v.LegacyEvents, &v.LegacyLinkBreaks, &v.FirstLegacyBreakSeq, &v.FirstLegacyBreakID)
	if errors.Is(err, sql.ErrNoRows) {
		return v, false, nil
	}
	if err != nil {
		return v, false, err
	}
	v.CheckedAt = v.CheckedAt.UTC()
	return v, true, nil
}

func (s *Store) SaveAuditVerification(ctx context.Context, v store.AuditVerification) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO audit_chain_verifications (account_id, status, verified_seq, verified_event_id, verified_hash, head_hash, broken_event_id, broken_seq, total_events, checked_at,
	legacy_events, legacy_link_breaks, first_legacy_break_seq, first_legacy_break_event_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
ON CONFLICT (account_id) DO UPDATE SET status = EXCLUDED.status, verified_seq = EXCLUDED.verified_seq,
	verified_event_id = EXCLUDED.verified_event_id, verified_hash = EXCLUDED.verified_hash,
	head_hash = EXCLUDED.head_hash, broken_event_id = EXCLUDED.broken_event_id, broken_seq = EXCLUDED.broken_seq,
	total_events = EXCLUDED.total_events, checked_at = EXCLUDED.checked_at,
	legacy_events = EXCLUDED.legacy_events, legacy_link_breaks = EXCLUDED.legacy_link_breaks,
	first_legacy_break_seq = EXCLUDED.first_legacy_break_seq, first_legacy_break_event_id = EXCLUDED.first_legacy_break_event_id`,
		v.AccountID, v.Status, v.VerifiedSeq, v.VerifiedID, v.VerifiedHash, v.HeadHash, v.BrokenID, v.BrokenSeq, v.TotalEvents, v.CheckedAt,
		v.LegacyEvents, v.LegacyLinkBreaks, v.FirstLegacyBreakSeq, v.FirstLegacyBreakID)
	return err
}

// ---- SIEM stream -----------------------------------------------------------

func (s *Store) GetAuditStreamConfig(ctx context.Context, accountID string) (store.AuditStreamConfig, error) {
	cfg := store.AuditStreamConfig{AccountID: accountID, Format: "json"}
	err := s.db.QueryRowContext(ctx, `
SELECT enabled, url, format, token_sealed, updated_by, updated_at FROM audit_stream_settings WHERE account_id = $1`, accountID).
		Scan(&cfg.Enabled, &cfg.URL, &cfg.Format, &cfg.TokenSealed, &cfg.UpdatedBy, &cfg.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return cfg, nil
	}
	return cfg, err
}

func (s *Store) PutAuditStreamConfig(ctx context.Context, cfg store.AuditStreamConfig) error {
	if cfg.AccountID == "" {
		return errors.New("account is required")
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO audit_stream_settings (account_id, enabled, url, format, token_sealed, updated_by, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, NOW())
ON CONFLICT (account_id) DO UPDATE SET enabled = EXCLUDED.enabled, url = EXCLUDED.url, format = EXCLUDED.format,
	token_sealed = EXCLUDED.token_sealed, updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
		cfg.AccountID, cfg.Enabled, cfg.URL, cfg.Format, cfg.TokenSealed, cfg.UpdatedBy)
	return err
}

// ClaimAuditOutbox leases due items with SKIP LOCKED, so replicas running the
// delivery job concurrently never take the same item.
func (s *Store) ClaimAuditOutbox(ctx context.Context, limit int, lease time.Duration) ([]store.AuditOutboxItem, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `
SELECT o.id, o.attempts, `+prefixColumns("e.")+`
FROM audit_stream_outbox o JOIN kms_audit_events e ON e.id = o.event_id
WHERE NOT o.dead AND o.next_attempt_at <= NOW()
ORDER BY o.next_attempt_at, o.id
LIMIT $1
FOR UPDATE OF o SKIP LOCKED`, limit)
	if err != nil {
		return nil, err
	}
	var out []store.AuditOutboxItem
	for rows.Next() {
		var it store.AuditOutboxItem
		rec, err := scanAuditRecord(leadingScanner{rows, []any{&it.ID, &it.Attempts}})
		if err != nil {
			rows.Close()
			return nil, err
		}
		it.Event = rec
		out = append(out, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, it := range out {
		if _, err := tx.ExecContext(ctx, `UPDATE audit_stream_outbox SET next_attempt_at = $2 WHERE id = $1`,
			it.ID, time.Now().UTC().Add(lease)); err != nil {
			return nil, err
		}
	}
	return out, tx.Commit()
}

func prefixColumns(p string) string {
	cols := []string{"id", "account_id", "COALESCE(" + p + "chain_seq, 0)", "hash_version", "action", "COALESCE(" + p + "key_id, '')", "result",
		"COALESCE(" + p + "error_type, '')", "COALESCE(" + p + "actor, '')", "actor_type", "actor_display_name", "access_key_id", "resource",
		"source_ip", "user_agent", "COALESCE(" + p + "prev_hash, '')", "COALESCE(" + p + "event_hash, '')", "created_at", "COALESCE(" + p + "correlation_id, '')",
		"COALESCE(" + p + "agent_id, '')", "COALESCE(" + p + "agent_owner, '')", "COALESCE(" + p + "task_id, '')"}
	for i, c := range cols {
		if !strings.HasPrefix(c, "COALESCE") {
			cols[i] = p + c
		}
	}
	return strings.Join(cols, ", ")
}

func (s *Store) CompleteAuditOutbox(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM audit_stream_outbox WHERE id = $1`, id)
	return err
}

func (s *Store) RetryAuditOutbox(ctx context.Context, id int64, next time.Time, lastErr string, dead bool) error {
	if len(lastErr) > 500 {
		lastErr = lastErr[:500]
	}
	_, err := s.db.ExecContext(ctx, `
UPDATE audit_stream_outbox SET attempts = attempts + 1, next_attempt_at = $2, last_error = $3, dead = $4 WHERE id = $1`,
		id, next.UTC(), lastErr, dead)
	return err
}
