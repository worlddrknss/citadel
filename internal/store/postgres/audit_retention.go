package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"
	"github.com/worlddrknss/citadel/internal/store"
)

// auditPruneLockClass is the first key of the transaction-scoped advisory
// lock PruneAuditEvents takes per account (the second is the account ID's
// hashtext), so only one replica prunes an account at a time. Two-key
// advisory locks don't collide with the single-key locks used elsewhere.
const auditPruneLockClass = 0x41554450 // "AUDP"

func (s *Store) GetAuditRetention(ctx context.Context, accountID string) (store.AuditRetentionSetting, error) {
	v := store.AuditRetentionSetting{AccountID: accountID}
	var days int
	err := s.db.QueryRowContext(ctx,
		`SELECT retention_days, updated_by, updated_at FROM audit_retention_settings WHERE account_id = $1`, accountID).
		Scan(&days, &v.UpdatedBy, &v.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return v, nil
	}
	if err != nil {
		return v, err
	}
	v.Days, v.UpdatedAt = &days, v.UpdatedAt.UTC()
	return v, nil
}

func (s *Store) PutAuditRetention(ctx context.Context, v store.AuditRetentionSetting) error {
	if v.AccountID == "" {
		return errors.New("account is required")
	}
	if v.Days == nil {
		_, err := s.db.ExecContext(ctx, `DELETE FROM audit_retention_settings WHERE account_id = $1`, v.AccountID)
		return err
	}
	if !store.ValidAuditRetentionDays(*v.Days) {
		return errors.New("retention days out of range")
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO audit_retention_settings (account_id, retention_days, updated_by, updated_at) VALUES ($1, $2, $3, NOW())
ON CONFLICT (account_id) DO UPDATE SET retention_days = EXCLUDED.retention_days, updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
		v.AccountID, *v.Days, v.UpdatedBy)
	return err
}

func (s *Store) ListAuditRetention(ctx context.Context) ([]store.AuditRetentionSetting, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT account_id, retention_days, updated_by, updated_at FROM audit_retention_settings ORDER BY account_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.AuditRetentionSetting
	for rows.Next() {
		var v store.AuditRetentionSetting
		var days int
		if err := rows.Scan(&v.AccountID, &days, &v.UpdatedBy, &v.UpdatedAt); err != nil {
			return nil, err
		}
		v.Days, v.UpdatedAt = &days, v.UpdatedAt.UTC()
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) AuditAccounts(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT account_id FROM audit_chain_heads ORDER BY account_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

const anchorColumns = `chain_seq, event_id, event_hash, pruned_before, pruned_events, updated_at, mac`

func scanAnchor(row rowScanner, accountID string) (store.AuditAnchor, error) {
	a := store.AuditAnchor{AccountID: accountID}
	err := row.Scan(&a.ChainSeq, &a.EventID, &a.EventHash, &a.PrunedBefore, &a.PrunedEvents, &a.UpdatedAt, &a.MAC)
	a.PrunedBefore, a.UpdatedAt = a.PrunedBefore.UTC(), a.UpdatedAt.UTC()
	return a, err
}

func (s *Store) GetAuditAnchor(ctx context.Context, accountID string) (store.AuditAnchor, bool, error) {
	a, err := scanAnchor(s.db.QueryRowContext(ctx,
		`SELECT `+anchorColumns+` FROM audit_chain_anchors WHERE account_id = $1`, accountID), accountID)
	if errors.Is(err, sql.ErrNoRows) {
		return store.AuditAnchor{AccountID: accountID}, false, nil
	}
	return a, err == nil, err
}

// AuditRetentionStats reads the account's count and oldest event (index
// scans on (account_id, created_at)) and the table's size from the catalog.
func (s *Store) AuditRetentionStats(ctx context.Context, accountID string, cutoff *time.Time) (store.AuditRetentionStats, error) {
	out := store.AuditRetentionStats{TableBytes: -1, TableRows: -1}
	var oldest sql.NullTime
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), MIN(created_at) FROM kms_audit_events WHERE account_id = $1`, accountID).
		Scan(&out.Events, &oldest); err != nil {
		return out, err
	}
	if oldest.Valid {
		out.Oldest = oldest.Time.UTC()
	}
	if cutoff != nil {
		if err := s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM kms_audit_events WHERE account_id = $1 AND created_at < $2`, accountID, cutoff.UTC()).
			Scan(&out.Prunable); err != nil {
			return out, err
		}
	}
	// to_regclass resolves through search_path, like every other query.
	var bytes, rows sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `
SELECT pg_total_relation_size(c.oid), GREATEST(c.reltuples, 0)::bigint
FROM pg_class c WHERE c.oid = to_regclass('kms_audit_events')`).Scan(&bytes, &rows); err == nil {
		if bytes.Valid {
			out.TableBytes = bytes.Int64
		}
		if rows.Valid {
			out.TableRows = rows.Int64
		}
	}
	return out, nil
}

// PruneAuditEvents deletes one batch of accountID's oldest events in a
// single short transaction:
//
//  1. take the account's prune lock without waiting (another replica holds
//     it: Stop "busy"), and lock the anchor row;
//  2. read the next limit events after the anchor by (account_id, chain_seq)
//     and decide the prefix that may go (store.AuditPrunePrefix);
//  3. delete that chain_seq range, the stream outbox rows of those events
//     (only dead ones can be left), and advance the anchor.
//
// Short lock and statement timeouts keep a slow batch from holding anything
// for long; the caller pauses between batches.
func (s *Store) PruneAuditEvents(ctx context.Context, accountID string, cutoff time.Time, limit int) (store.AuditPruneResult, error) {
	if limit <= 0 {
		return store.AuditPruneResult{}, errors.New("limit must be positive")
	}
	if len(s.auditHMACKey) == 0 {
		return store.AuditPruneResult{}, errNoAuditKey
	}
	cutoff = cutoff.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return store.AuditPruneResult{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SET LOCAL lock_timeout = '5s'`); err != nil {
		return store.AuditPruneResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `SET LOCAL statement_timeout = '60s'`); err != nil {
		return store.AuditPruneResult{}, err
	}
	var locked bool
	if err := tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock($1, hashtext($2))`, auditPruneLockClass, accountID).Scan(&locked); err != nil {
		return store.AuditPruneResult{}, fmt.Errorf("prune lock: %w", err)
	}
	if !locked {
		return store.AuditPruneResult{Stop: store.AuditPruneStopBusy}, nil
	}

	anchor, err := scanAnchor(tx.QueryRowContext(ctx,
		`SELECT `+anchorColumns+` FROM audit_chain_anchors WHERE account_id = $1 FOR UPDATE`, accountID), accountID)
	hasAnchor := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return store.AuditPruneResult{}, fmt.Errorf("read audit anchor: %w", err)
	}
	if !hasAnchor {
		anchor = store.AuditAnchor{AccountID: accountID}
	}
	res := store.AuditPruneResult{Anchor: anchor}
	if hasAnchor && !store.AuditAnchorValid(s.auditHMACKey, anchor) {
		res.Stop = store.AuditPruneStopBadAnchor
		return res, nil
	}
	var headSeq int64
	if err := tx.QueryRowContext(ctx, `SELECT chain_seq FROM audit_chain_heads WHERE account_id = $1`, accountID).Scan(&headSeq); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return res, nil
		}
		return res, fmt.Errorf("read audit chain head: %w", err)
	}

	rows, err := tx.QueryContext(ctx, `SELECT `+auditColumns+` FROM kms_audit_events
WHERE account_id = $1 AND chain_seq > $2 ORDER BY chain_seq LIMIT $3`, accountID, anchor.ChainSeq, limit)
	if err != nil {
		return res, fmt.Errorf("read prune batch: %w", err)
	}
	var cands []store.AuditPruneCandidate
	for rows.Next() {
		rec, err := scanAuditRecord(rows)
		if err != nil {
			rows.Close()
			return res, err
		}
		if !rec.CreatedAt.Before(cutoff) {
			break // the rest is inside the window
		}
		cands = append(cands, store.AuditPruneCandidate{Record: rec})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return res, err
	}
	if len(cands) == 0 {
		return res, nil
	}

	ids := make([]int64, len(cands))
	var correlations []string
	for i, c := range cands {
		ids[i] = c.Record.ID
		if c.Record.Result == store.AuditResultPending && c.Record.CorrelationID != "" {
			correlations = append(correlations, c.Record.CorrelationID)
		}
	}
	if len(correlations) > 0 {
		// Attempts whose outcome is inside the window stay with it.
		inWindow := map[string]bool{}
		crows, err := tx.QueryContext(ctx, `
SELECT DISTINCT correlation_id FROM kms_audit_events
WHERE account_id = $1 AND correlation_id <> '' AND correlation_id = ANY($2)
  AND result <> 'pending' AND created_at >= $3`, accountID, pq.Array(correlations), cutoff)
		if err != nil {
			return res, fmt.Errorf("read attempt outcomes: %w", err)
		}
		for crows.Next() {
			var c string
			if err := crows.Scan(&c); err != nil {
				crows.Close()
				return res, err
			}
			inWindow[c] = true
		}
		crows.Close()
		if err := crows.Err(); err != nil {
			return res, err
		}
		for i := range cands {
			r := cands[i].Record
			cands[i].OutcomeInWindow = r.Result == store.AuditResultPending && inWindow[r.CorrelationID]
		}
	}
	// Events still queued for SIEM delivery stay until delivered.
	orows, err := tx.QueryContext(ctx,
		`SELECT event_id FROM audit_stream_outbox WHERE account_id = $1 AND NOT dead AND event_id = ANY($2)`,
		accountID, pq.Array(ids))
	if err != nil {
		return res, fmt.Errorf("read stream outbox: %w", err)
	}
	undelivered := map[int64]bool{}
	for orows.Next() {
		var id int64
		if err := orows.Scan(&id); err != nil {
			orows.Close()
			return res, err
		}
		undelivered[id] = true
	}
	orows.Close()
	if err := orows.Err(); err != nil {
		return res, err
	}
	for i := range cands {
		cands[i].Undelivered = undelivered[cands[i].Record.ID]
	}

	n, stop := store.AuditPrunePrefix(s.auditHMACKey, anchor, hasAnchor, cands, cutoff, headSeq)
	res.Stop = stop
	if n == 0 {
		return res, nil
	}
	last := cands[n-1].Record
	del, err := tx.ExecContext(ctx,
		`DELETE FROM kms_audit_events WHERE account_id = $1 AND chain_seq > $2 AND chain_seq <= $3`,
		accountID, anchor.ChainSeq, last.ChainSeq)
	if err != nil {
		return res, fmt.Errorf("delete audit events: %w", err)
	}
	if got, err := del.RowsAffected(); err != nil || got != int64(n) {
		// Something else changed the range; leave it all as it was.
		return res, fmt.Errorf("prune deleted %d events, expected %d", got, n)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM audit_stream_outbox WHERE account_id = $1 AND event_id = ANY($2)`,
		accountID, pq.Array(ids[:n])); err != nil {
		return res, fmt.Errorf("delete stream outbox rows: %w", err)
	}
	next := store.AuditAnchor{
		AccountID:    accountID,
		ChainSeq:     last.ChainSeq,
		EventID:      last.ID,
		EventHash:    last.EventHash,
		PrunedBefore: last.CreatedAt,
		PrunedEvents: anchor.PrunedEvents + int64(n),
		UpdatedAt:    time.Now().UTC().Truncate(time.Microsecond),
	}
	next.MAC = store.AuditAnchorMAC(s.auditHMACKey, next)
	if _, err := tx.ExecContext(ctx, `
INSERT INTO audit_chain_anchors (account_id, `+anchorColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (account_id) DO UPDATE SET chain_seq = EXCLUDED.chain_seq, event_id = EXCLUDED.event_id,
	event_hash = EXCLUDED.event_hash, pruned_before = EXCLUDED.pruned_before, pruned_events = EXCLUDED.pruned_events,
	updated_at = EXCLUDED.updated_at, mac = EXCLUDED.mac`,
		accountID, next.ChainSeq, next.EventID, next.EventHash, next.PrunedBefore, next.PrunedEvents, next.UpdatedAt, next.MAC); err != nil {
		return res, fmt.Errorf("advance audit anchor: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return res, err
	}
	res.Pruned, res.Anchor = int64(n), next
	return res, nil
}
