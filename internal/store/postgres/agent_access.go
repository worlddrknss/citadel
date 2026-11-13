package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// Agent access requests and leases (migration 1450_agent_access).
//
// Atomicity: a pending request is unique per (agent, credential, actions,
// task) through a partial unique index, so concurrent opens converge on one
// row; decisions are conditional updates on status = 'pending'; a lease is
// used with a single UPDATE whose target row is chosen and locked by a
// FOR UPDATE subquery and whose own WHERE re-checks the remaining uses, so a
// single-use lease can't be used twice.

const accessRequestCols = `request_id, account_id, agent_id, credential, actions, reason, task_id, duration_seconds, origin, status,
	created_at, expires_at, decided_at, decided_by, decision_comment, scope, lease_id`

func scanAccessRequest(row rowScanner) (store.AgentAccessRequest, error) {
	var (
		r       store.AgentAccessRequest
		actions string
		decided sql.NullTime
	)
	err := row.Scan(&r.RequestID, &r.AccountID, &r.AgentID, &r.Credential, &actions, &r.Reason, &r.TaskID, &r.DurationSeconds, &r.Origin,
		&r.Status, &r.CreatedAt, &r.ExpiresAt, &decided, &r.DecidedBy, &r.DecisionComment, &r.Scope, &r.LeaseID)
	if errors.Is(err, sql.ErrNoRows) {
		return store.AgentAccessRequest{}, store.ErrAgentAccessRequestNotFound
	}
	if err != nil {
		return store.AgentAccessRequest{}, err
	}
	r.Actions = splitActions(actions)
	r.CreatedAt, r.ExpiresAt, r.DecidedAt = r.CreatedAt.UTC(), r.ExpiresAt.UTC(), fromNullTime(decided)
	return r, nil
}

func splitActions(v string) []string {
	if v == "" {
		return []string{}
	}
	return strings.Split(v, ",")
}

func (s *Store) OpenAgentAccessRequest(ctx context.Context, r store.AgentAccessRequest, now time.Time) (store.AgentAccessRequest, bool, error) {
	key := store.AgentActionsKey(r.Actions)
	now = now.UTC()
	// Expire a lapsed pending request for the same key so it no longer
	// holds the unique slot.
	if _, err := s.db.ExecContext(ctx, `UPDATE agent_access_requests SET status = 'expired'
WHERE account_id = $1 AND agent_id = $2 AND credential = $3 AND actions = $4 AND task_id = $5 AND status = 'pending' AND expires_at <= $6`,
		r.AccountID, r.AgentID, r.Credential, key, r.TaskID, now); err != nil {
		return store.AgentAccessRequest{}, false, err
	}
	for attempt := 0; attempt < 3; attempt++ {
		res, err := s.db.ExecContext(ctx, `INSERT INTO agent_access_requests (`+accessRequestCols+`)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending', $10, $11, NULL, '', '', '', '')
ON CONFLICT (account_id, agent_id, credential, actions, task_id) WHERE status = 'pending' DO NOTHING`,
			r.RequestID, r.AccountID, r.AgentID, r.Credential, key, r.Reason, r.TaskID, r.DurationSeconds, r.Origin, r.CreatedAt.UTC(), r.ExpiresAt.UTC())
		if err != nil {
			if idnFKViolation(err) {
				return store.AgentAccessRequest{}, false, store.ErrAgentNotFound
			}
			return store.AgentAccessRequest{}, false, err
		}
		if n, _ := res.RowsAffected(); n == 1 {
			out := r
			out.Actions, out.Status = splitActions(key), store.AgentRequestPending
			out.CreatedAt, out.ExpiresAt = r.CreatedAt.UTC(), r.ExpiresAt.UTC()
			return out, true, nil
		}
		cur, err := scanAccessRequest(s.db.QueryRowContext(ctx, `SELECT `+accessRequestCols+` FROM agent_access_requests
WHERE account_id = $1 AND agent_id = $2 AND credential = $3 AND actions = $4 AND task_id = $5 AND status = 'pending'`,
			r.AccountID, r.AgentID, r.Credential, key, r.TaskID))
		if errors.Is(err, store.ErrAgentAccessRequestNotFound) {
			continue // decided between the insert and the read: try again
		}
		return cur, false, err
	}
	return store.AgentAccessRequest{}, false, errors.New("could not open the access request")
}

func (s *Store) GetAgentAccessRequest(ctx context.Context, accountID, requestID string) (store.AgentAccessRequest, error) {
	return scanAccessRequest(s.db.QueryRowContext(ctx, `SELECT `+accessRequestCols+` FROM agent_access_requests WHERE account_id = $1 AND request_id = $2`,
		accountID, requestID))
}

func (s *Store) ListAgentAccessRequests(ctx context.Context, accountID string, f store.AgentAccessRequestFilter) ([]store.AgentAccessRequest, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	q := `SELECT ` + accessRequestCols + ` FROM agent_access_requests WHERE account_id = $1`
	args := []any{accountID}
	if f.AgentID != "" {
		args = append(args, f.AgentID)
		q += ` AND agent_id = $2`
	}
	if f.Pending {
		args = append(args, f.Now.UTC())
		q += ` AND status = 'pending' AND expires_at > $` + strconv.Itoa(len(args))
	}
	args = append(args, limit)
	q += ` ORDER BY created_at DESC, request_id DESC LIMIT $` + strconv.Itoa(len(args))
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.AgentAccessRequest{}
	for rows.Next() {
		r, err := scanAccessRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) CountPendingAgentAccessRequests(ctx context.Context, accountID, agentID string, now time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_access_requests
WHERE account_id = $1 AND agent_id = $2 AND status = 'pending' AND expires_at > $3`, accountID, agentID, now.UTC()).Scan(&n)
	return n, err
}

func (s *Store) DecideAgentAccessRequest(ctx context.Context, accountID, requestID string, d store.AgentAccessDecision) (out store.AgentAccessRequest, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return store.AgentAccessRequest{}, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	at := d.At.UTC()
	scope, leaseID := "", ""
	if d.Lease != nil {
		scope, leaseID = d.Lease.Scope, d.Lease.LeaseID
	}
	out, err = scanAccessRequest(tx.QueryRowContext(ctx, `UPDATE agent_access_requests
SET status = $3, decided_at = $4, decided_by = $5, decision_comment = $6, scope = $7, lease_id = $8
WHERE account_id = $1 AND request_id = $2 AND status = 'pending' AND expires_at > $4
RETURNING `+accessRequestCols, accountID, requestID, d.Status, at, d.By, d.Comment, scope, leaseID))
	if errors.Is(err, store.ErrAgentAccessRequestNotFound) {
		if _, gerr := s.GetAgentAccessRequest(ctx, accountID, requestID); gerr != nil {
			return store.AgentAccessRequest{}, gerr
		}
		return store.AgentAccessRequest{}, store.ErrAgentAccessRequestDecided
	}
	if err != nil {
		return store.AgentAccessRequest{}, err
	}
	if d.Lease != nil {
		l := *d.Lease
		l.RequestID = requestID
		if err = insertLease(ctx, tx, l); err != nil {
			return store.AgentAccessRequest{}, err
		}
	}
	if err = tx.Commit(); err != nil {
		return store.AgentAccessRequest{}, err
	}
	return out, nil
}

func (s *Store) CancelAgentAccessRequests(ctx context.Context, accountID, agentID, by, comment string, at time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE agent_access_requests SET status = 'cancelled', decided_at = $3, decided_by = $4, decision_comment = $5
WHERE account_id = $1 AND agent_id = $2 AND status = 'pending' AND expires_at > $3`, accountID, agentID, at.UTC(), by, comment)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

const leaseCols = `lease_id, account_id, agent_id, credential, actions, scope, task_id, uses_left, use_count, expires_at, created_at, created_by,
	request_id, last_used_at, ended_at, ended_by, ended_reason`

func scanLease(row rowScanner) (store.AgentLease, error) {
	var (
		l             store.AgentLease
		actions       string
		usesLeft      sql.NullInt64
		lastUsed, end sql.NullTime
	)
	err := row.Scan(&l.LeaseID, &l.AccountID, &l.AgentID, &l.Credential, &actions, &l.Scope, &l.TaskID, &usesLeft, &l.UseCount, &l.ExpiresAt,
		&l.CreatedAt, &l.CreatedBy, &l.RequestID, &lastUsed, &end, &l.EndedBy, &l.EndedReason)
	if errors.Is(err, sql.ErrNoRows) {
		return store.AgentLease{}, store.ErrAgentLeaseNotFound
	}
	if err != nil {
		return store.AgentLease{}, err
	}
	l.Actions = splitActions(actions)
	if usesLeft.Valid {
		v := int(usesLeft.Int64)
		l.UsesLeft = &v
	}
	l.ExpiresAt, l.CreatedAt = l.ExpiresAt.UTC(), l.CreatedAt.UTC()
	l.LastUsedAt, l.EndedAt = fromNullTime(lastUsed), fromNullTime(end)
	return l, nil
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func insertLease(ctx context.Context, db execer, l store.AgentLease) error {
	var uses any
	if l.UsesLeft != nil {
		uses = *l.UsesLeft
	}
	_, err := db.ExecContext(ctx, `INSERT INTO agent_leases (`+leaseCols+`)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
		l.LeaseID, l.AccountID, l.AgentID, l.Credential, store.AgentActionsKey(l.Actions), l.Scope, l.TaskID, uses, l.UseCount,
		l.ExpiresAt.UTC(), l.CreatedAt.UTC(), l.CreatedBy, l.RequestID, agentNullTime(l.LastUsedAt), agentNullTime(l.EndedAt), l.EndedBy, l.EndedReason)
	if idnFKViolation(err) {
		return store.ErrAgentNotFound
	}
	return err
}

func (s *Store) CreateAgentLease(ctx context.Context, l store.AgentLease) error {
	return insertLease(ctx, s.db, l)
}

func (s *Store) GetAgentLease(ctx context.Context, accountID, leaseID string) (store.AgentLease, error) {
	return scanLease(s.db.QueryRowContext(ctx, `SELECT `+leaseCols+` FROM agent_leases WHERE account_id = $1 AND lease_id = $2`, accountID, leaseID))
}

func (s *Store) ListAgentLeases(ctx context.Context, accountID, agentID string, activeOnly bool, now time.Time) ([]store.AgentLease, error) {
	q := `SELECT ` + leaseCols + ` FROM agent_leases WHERE account_id = $1`
	args := []any{accountID}
	if agentID != "" {
		args = append(args, agentID)
		q += ` AND agent_id = $2`
	}
	if activeOnly {
		args = append(args, now.UTC())
		q += ` AND ended_at IS NULL AND expires_at > $` + strconv.Itoa(len(args)) + ` AND (uses_left IS NULL OR uses_left > 0)`
	}
	q += ` ORDER BY created_at DESC, lease_id DESC LIMIT 500`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.AgentLease{}
	for rows.Next() {
		l, err := scanLease(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// leaseCandidates selects the usable leases for a match, best first. The
// action is matched in Go (actions is a short comma list), so the query
// returns the agent's active leases for the credential.
const leaseCandidates = ` FROM agent_leases
WHERE account_id = $1 AND agent_id = $2 AND credential = $3 AND ended_at IS NULL AND expires_at > $4
	AND (uses_left IS NULL OR uses_left > 0)
	AND (scope <> 'task' OR task_id = $5)
	AND ',' || actions || ',' LIKE '%,' || $6 || ',%'`

func (s *Store) FindAgentLease(ctx context.Context, m store.AgentLeaseMatch) (store.AgentLease, bool, error) {
	l, err := scanLease(s.db.QueryRowContext(ctx, `SELECT `+leaseCols+leaseCandidates+`
ORDER BY (uses_left IS NULL) DESC, expires_at, lease_id LIMIT 1`, m.AccountID, m.AgentID, m.Credential, m.Now.UTC(), m.TaskID, m.Action))
	if errors.Is(err, store.ErrAgentLeaseNotFound) {
		return store.AgentLease{}, false, nil
	}
	return l, err == nil, err
}

func (s *Store) ConsumeAgentLease(ctx context.Context, m store.AgentLeaseMatch) (store.AgentLease, bool, error) {
	// The subquery locks the chosen row; a concurrent consumer waits, then
	// re-checks the row (uses_left > 0) and moves on to the next candidate
	// or finds none. The outer WHERE repeats the check for safety.
	l, err := scanLease(s.db.QueryRowContext(ctx, `UPDATE agent_leases
SET uses_left = CASE WHEN uses_left IS NULL THEN NULL ELSE uses_left - 1 END, use_count = use_count + 1, last_used_at = $4
WHERE lease_id = (SELECT lease_id`+leaseCandidates+`
	ORDER BY (uses_left IS NULL) DESC, expires_at, lease_id LIMIT 1 FOR UPDATE)
	AND ended_at IS NULL AND (uses_left IS NULL OR uses_left > 0)
RETURNING `+leaseCols, m.AccountID, m.AgentID, m.Credential, m.Now.UTC(), m.TaskID, m.Action))
	if errors.Is(err, store.ErrAgentLeaseNotFound) {
		return store.AgentLease{}, false, nil
	}
	return l, err == nil, err
}

func (s *Store) EndAgentLease(ctx context.Context, accountID, leaseID, by, reason string, at time.Time) (store.AgentLease, error) {
	l, err := scanLease(s.db.QueryRowContext(ctx, `UPDATE agent_leases SET ended_at = $3, ended_by = $4, ended_reason = $5
WHERE account_id = $1 AND lease_id = $2 AND ended_at IS NULL AND expires_at > $3 AND (uses_left IS NULL OR uses_left > 0)
RETURNING `+leaseCols, accountID, leaseID, at.UTC(), by, reason))
	if errors.Is(err, store.ErrAgentLeaseNotFound) {
		if _, gerr := s.GetAgentLease(ctx, accountID, leaseID); gerr != nil {
			return store.AgentLease{}, gerr
		}
		return store.AgentLease{}, store.ErrAgentLeaseEnded
	}
	return l, err
}

func (s *Store) EndAgentLeases(ctx context.Context, accountID, agentID, by, reason string, at time.Time) (int, error) {
	q := `UPDATE agent_leases SET ended_at = $2, ended_by = $3, ended_reason = $4
WHERE account_id = $1 AND ended_at IS NULL AND expires_at > $2 AND (uses_left IS NULL OR uses_left > 0)`
	args := []any{accountID, at.UTC(), by, reason}
	if agentID != "" {
		q += ` AND agent_id = $5`
		args = append(args, agentID)
	}
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
