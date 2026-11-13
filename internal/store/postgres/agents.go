package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// AI agents (migration 1300_agents). Every query names its account
// explicitly except the authentication lookups, which are keyed by the
// presented agent ID or federation issuer/subject.

func agentJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil || string(b) == "null" {
		return "[]"
	}
	return string(b)
}

func agentStrings(raw string) []string {
	var out []string
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &out)
	}
	if out == nil {
		out = []string{}
	}
	return out
}

func agentNullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC()
}

func fromNullTime(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time.UTC()
	return &v
}

const agentCols = `agent_id, account_id, name, description, owner, status, labels_json, created_at, created_by, updated_at,
	last_used_at, status_changed_at, status_changed_by, status_reason`

func scanAgent(row rowScanner) (store.Agent, error) {
	var (
		a                 store.Agent
		labels            string
		lastUsed, changed sql.NullTime
	)
	err := row.Scan(&a.AgentID, &a.AccountID, &a.Name, &a.Description, &a.Owner, &a.Status, &labels, &a.CreatedAt, &a.CreatedBy,
		&a.UpdatedAt, &lastUsed, &changed, &a.StatusChangedBy, &a.StatusReason)
	if errors.Is(err, sql.ErrNoRows) {
		return store.Agent{}, store.ErrAgentNotFound
	}
	if err != nil {
		return store.Agent{}, err
	}
	_ = json.Unmarshal([]byte(labels), &a.Labels)
	a.CreatedAt, a.UpdatedAt = a.CreatedAt.UTC(), a.UpdatedAt.UTC()
	a.LastUsedAt, a.StatusChangedAt = fromNullTime(lastUsed), fromNullTime(changed)
	return a, nil
}

func labelsJSON(m map[string]string) string {
	if len(m) == 0 {
		return "{}"
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func (s *Store) CreateAgent(ctx context.Context, a store.Agent) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO agents (`+agentCols+`)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		a.AgentID, a.AccountID, a.Name, a.Description, a.Owner, a.Status, labelsJSON(a.Labels), a.CreatedAt.UTC(), a.CreatedBy,
		a.UpdatedAt.UTC(), agentNullTime(a.LastUsedAt), agentNullTime(a.StatusChangedAt), a.StatusChangedBy, a.StatusReason)
	if idnUniqueViolation(err) {
		return store.ErrAgentExists
	}
	return err
}

func (s *Store) GetAgent(ctx context.Context, accountID, agentID string) (store.Agent, error) {
	return scanAgent(s.db.QueryRowContext(ctx, `SELECT `+agentCols+` FROM agents WHERE account_id = $1 AND agent_id = $2`, accountID, agentID))
}

func (s *Store) LookupAgent(ctx context.Context, agentID string) (store.Agent, error) {
	return scanAgent(s.db.QueryRowContext(ctx, `SELECT `+agentCols+` FROM agents WHERE agent_id = $1`, agentID))
}

func (s *Store) ListAgents(ctx context.Context, accountID string) ([]store.Agent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+agentCols+` FROM agents WHERE account_id = $1 ORDER BY lower(name)`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.Agent{}
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) UpdateAgent(ctx context.Context, a store.Agent) error {
	res, err := s.db.ExecContext(ctx, `UPDATE agents SET name = $3, description = $4, owner = $5, labels_json = $6, updated_at = $7
WHERE account_id = $1 AND agent_id = $2`, a.AccountID, a.AgentID, a.Name, a.Description, a.Owner, labelsJSON(a.Labels), a.UpdatedAt.UTC())
	if idnUniqueViolation(err) {
		return store.ErrAgentExists
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrAgentNotFound
	}
	return nil
}

func (s *Store) SetAgentStatus(ctx context.Context, accountID, agentID, status, by, reason string, at time.Time) (out store.Agent, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return store.Agent{}, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	cur, err := scanAgent(tx.QueryRowContext(ctx, `SELECT `+agentCols+` FROM agents WHERE account_id = $1 AND agent_id = $2 FOR UPDATE`, accountID, agentID))
	if err != nil {
		return store.Agent{}, err
	}
	if cur.Status == store.AgentStatusRevoked {
		return store.Agent{}, store.ErrAgentRevoked
	}
	at = at.UTC()
	if _, err = tx.ExecContext(ctx, `UPDATE agents SET status = $3, status_changed_at = $4, status_changed_by = $5, status_reason = $6, updated_at = $4
WHERE account_id = $1 AND agent_id = $2`, accountID, agentID, status, at, by, reason); err != nil {
		return store.Agent{}, err
	}
	if status == store.AgentStatusRevoked {
		if _, err = tx.ExecContext(ctx, `UPDATE agent_tokens SET revoked_at = $3, revoked_by = $4
WHERE account_id = $1 AND agent_id = $2 AND revoked_at IS NULL`, accountID, agentID, at, by); err != nil {
			return store.Agent{}, err
		}
	}
	if err = tx.Commit(); err != nil {
		return store.Agent{}, err
	}
	cur.Status, cur.StatusChangedAt, cur.StatusChangedBy, cur.StatusReason, cur.UpdatedAt = status, &at, by, reason, at
	return cur, nil
}

func (s *Store) DeleteAgent(ctx context.Context, accountID, agentID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM agents WHERE account_id = $1 AND agent_id = $2`, accountID, agentID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrAgentNotFound
	}
	return nil
}

func (s *Store) TouchAgentUsed(ctx context.Context, accountID, agentID, tokenID string, at time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE agents SET last_used_at = $3 WHERE account_id = $1 AND agent_id = $2`, accountID, agentID, at.UTC())
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrAgentNotFound
	}
	if tokenID != "" {
		_, err = s.db.ExecContext(ctx, `UPDATE agent_tokens SET last_used_at = $4 WHERE account_id = $1 AND agent_id = $2 AND token_id = $3`,
			accountID, agentID, tokenID, at.UTC())
	}
	return err
}

const agentTokenCols = `token_id, account_id, agent_id, name, hint, hash, created_at, created_by, expires_at, revoked_at, revoked_by, last_used_at`

func scanAgentTokens(rows *sql.Rows) ([]store.AgentToken, error) {
	defer rows.Close()
	out := []store.AgentToken{}
	for rows.Next() {
		var (
			t                      store.AgentToken
			exp, revoked, lastUsed sql.NullTime
		)
		if err := rows.Scan(&t.TokenID, &t.AccountID, &t.AgentID, &t.Name, &t.Hint, &t.Hash, &t.CreatedAt, &t.CreatedBy,
			&exp, &revoked, &t.RevokedBy, &lastUsed); err != nil {
			return nil, err
		}
		t.CreatedAt = t.CreatedAt.UTC()
		t.ExpiresAt, t.RevokedAt, t.LastUsedAt = fromNullTime(exp), fromNullTime(revoked), fromNullTime(lastUsed)
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) CreateAgentToken(ctx context.Context, t store.AgentToken) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO agent_tokens (`+agentTokenCols+`)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		t.TokenID, t.AccountID, t.AgentID, t.Name, t.Hint, t.Hash, t.CreatedAt.UTC(), t.CreatedBy,
		agentNullTime(t.ExpiresAt), agentNullTime(t.RevokedAt), t.RevokedBy, agentNullTime(t.LastUsedAt))
	if idnFKViolation(err) {
		return store.ErrAgentNotFound
	}
	return err
}

func (s *Store) ListAgentTokens(ctx context.Context, accountID, agentID string) ([]store.AgentToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+agentTokenCols+` FROM agent_tokens WHERE account_id = $1 AND agent_id = $2
ORDER BY created_at DESC, token_id`, accountID, agentID)
	if err != nil {
		return nil, err
	}
	return scanAgentTokens(rows)
}

func (s *Store) FindAgentTokens(ctx context.Context, agentID, hint string) ([]store.AgentToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+agentTokenCols+` FROM agent_tokens WHERE agent_id = $1 AND hint = $2
ORDER BY created_at DESC, token_id`, agentID, hint)
	if err != nil {
		return nil, err
	}
	return scanAgentTokens(rows)
}

func (s *Store) RevokeAgentToken(ctx context.Context, accountID, agentID, tokenID, by string, at time.Time) error {
	var id string
	err := s.db.QueryRowContext(ctx, `UPDATE agent_tokens SET revoked_at = COALESCE(revoked_at, $4),
	revoked_by = CASE WHEN revoked_at IS NULL THEN $5 ELSE revoked_by END
WHERE account_id = $1 AND agent_id = $2 AND token_id = $3 RETURNING token_id`, accountID, agentID, tokenID, at.UTC(), by).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrAgentTokenNotFound
	}
	return err
}

const agentBindingCols = `binding_id, account_id, agent_id, issuer, subject, audience, description, created_at, created_by`

func scanAgentBindings(rows *sql.Rows) ([]store.AgentBinding, error) {
	defer rows.Close()
	out := []store.AgentBinding{}
	for rows.Next() {
		var b store.AgentBinding
		if err := rows.Scan(&b.BindingID, &b.AccountID, &b.AgentID, &b.Issuer, &b.Subject, &b.Audience, &b.Description, &b.CreatedAt, &b.CreatedBy); err != nil {
			return nil, err
		}
		b.CreatedAt = b.CreatedAt.UTC()
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) CreateAgentBinding(ctx context.Context, b store.AgentBinding) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO agent_bindings (`+agentBindingCols+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		b.BindingID, b.AccountID, b.AgentID, b.Issuer, b.Subject, b.Audience, b.Description, b.CreatedAt.UTC(), b.CreatedBy)
	switch {
	case idnUniqueViolation(err):
		return store.ErrAgentBindingExists
	case idnFKViolation(err):
		return store.ErrAgentNotFound
	}
	return err
}

func (s *Store) ListAgentBindings(ctx context.Context, accountID, agentID string) ([]store.AgentBinding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+agentBindingCols+` FROM agent_bindings WHERE account_id = $1 AND agent_id = $2
ORDER BY created_at, binding_id`, accountID, agentID)
	if err != nil {
		return nil, err
	}
	return scanAgentBindings(rows)
}

func (s *Store) FindAgentBindings(ctx context.Context, issuer, subject string) ([]store.AgentBinding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+agentBindingCols+` FROM agent_bindings WHERE issuer = $1 AND subject = $2
ORDER BY created_at, binding_id LIMIT 100`, issuer, subject)
	if err != nil {
		return nil, err
	}
	return scanAgentBindings(rows)
}

func (s *Store) DeleteAgentBinding(ctx context.Context, accountID, agentID, bindingID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM agent_bindings WHERE account_id = $1 AND agent_id = $2 AND binding_id = $3`, accountID, agentID, bindingID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrAgentBindingNotFound
	}
	return nil
}

const agentCredentialCols = `account_id, name, secret_name, kind, description, allowed_hosts, allowed_methods, allowed_path_prefixes,
	header_name, header_prefix, query_param, allow_http, allowed_cidrs, created_at, created_by, updated_at, updated_by`

func scanAgentCredential(row rowScanner) (store.AgentCredential, error) {
	var (
		c                            store.AgentCredential
		hosts, methods, paths, cidrs string
	)
	err := row.Scan(&c.AccountID, &c.Name, &c.SecretName, &c.Kind, &c.Description, &hosts, &methods, &paths,
		&c.HeaderName, &c.HeaderPrefix, &c.QueryParam, &c.AllowHTTP, &cidrs, &c.CreatedAt, &c.CreatedBy, &c.UpdatedAt, &c.UpdatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return store.AgentCredential{}, store.ErrAgentCredentialNotFound
	}
	if err != nil {
		return store.AgentCredential{}, err
	}
	c.AllowedHosts, c.AllowedMethods, c.AllowedPathPrefixes, c.AllowedCIDRs = agentStrings(hosts), agentStrings(methods), agentStrings(paths), agentStrings(cidrs)
	c.CreatedAt, c.UpdatedAt = c.CreatedAt.UTC(), c.UpdatedAt.UTC()
	return c, nil
}

func (s *Store) CreateAgentCredential(ctx context.Context, c store.AgentCredential) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO agent_credentials (`+agentCredentialCols+`)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
		c.AccountID, c.Name, c.SecretName, c.Kind, c.Description, agentJSON(c.AllowedHosts), agentJSON(c.AllowedMethods), agentJSON(c.AllowedPathPrefixes),
		c.HeaderName, c.HeaderPrefix, c.QueryParam, c.AllowHTTP, agentJSON(c.AllowedCIDRs), c.CreatedAt.UTC(), c.CreatedBy, c.UpdatedAt.UTC(), c.UpdatedBy)
	if idnUniqueViolation(err) {
		return store.ErrAgentCredentialExists
	}
	return err
}

func (s *Store) UpdateAgentCredential(ctx context.Context, c store.AgentCredential) error {
	res, err := s.db.ExecContext(ctx, `UPDATE agent_credentials SET secret_name = $3, kind = $4, description = $5, allowed_hosts = $6,
	allowed_methods = $7, allowed_path_prefixes = $8, header_name = $9, header_prefix = $10, query_param = $11, allow_http = $12,
	allowed_cidrs = $13, updated_at = $14, updated_by = $15
WHERE account_id = $1 AND name = $2`,
		c.AccountID, c.Name, c.SecretName, c.Kind, c.Description, agentJSON(c.AllowedHosts), agentJSON(c.AllowedMethods), agentJSON(c.AllowedPathPrefixes),
		c.HeaderName, c.HeaderPrefix, c.QueryParam, c.AllowHTTP, agentJSON(c.AllowedCIDRs), c.UpdatedAt.UTC(), c.UpdatedBy)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrAgentCredentialNotFound
	}
	return nil
}

func (s *Store) GetAgentCredential(ctx context.Context, accountID, name string) (store.AgentCredential, error) {
	return scanAgentCredential(s.db.QueryRowContext(ctx, `SELECT `+agentCredentialCols+` FROM agent_credentials WHERE account_id = $1 AND name = $2`, accountID, name))
}

func (s *Store) ListAgentCredentials(ctx context.Context, accountID string) ([]store.AgentCredential, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+agentCredentialCols+` FROM agent_credentials WHERE account_id = $1 ORDER BY name`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.AgentCredential{}
	for rows.Next() {
		c, err := scanAgentCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) DeleteAgentCredential(ctx context.Context, accountID, name string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM agent_credentials WHERE account_id = $1 AND name = $2`, accountID, name)
	if idnFKViolation(err) {
		return store.ErrAgentCredentialInUse
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrAgentCredentialNotFound
	}
	return nil
}

const agentGrantCols = `grant_id, account_id, agent_id, credential, actions, not_before, not_after, window_start, window_end, window_days,
	timezone, max_uses_per_hour, requires_approval, lease_ttl_seconds, created_at, created_by, updated_at, updated_by`

func scanAgentGrant(row rowScanner) (store.AgentGrant, error) {
	var (
		g             store.AgentGrant
		actions, days string
		nbf, naf      sql.NullTime
		approval      sql.NullBool
		lease         sql.NullInt64
	)
	err := row.Scan(&g.GrantID, &g.AccountID, &g.AgentID, &g.Credential, &actions, &nbf, &naf, &g.WindowStart, &g.WindowEnd, &days,
		&g.Timezone, &g.MaxUsesPerHour, &approval, &lease, &g.CreatedAt, &g.CreatedBy, &g.UpdatedAt, &g.UpdatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return store.AgentGrant{}, store.ErrAgentGrantNotFound
	}
	if err != nil {
		return store.AgentGrant{}, err
	}
	g.Actions, g.WindowDays = agentStrings(actions), agentStrings(days)
	g.NotBefore, g.NotAfter = fromNullTime(nbf), fromNullTime(naf)
	if approval.Valid {
		v := approval.Bool
		g.RequiresApproval = &v
	}
	if lease.Valid {
		v := int(lease.Int64)
		g.LeaseTTLSeconds = &v
	}
	g.CreatedAt, g.UpdatedAt = g.CreatedAt.UTC(), g.UpdatedAt.UTC()
	return g, nil
}

func (s *Store) PutAgentGrant(ctx context.Context, g store.AgentGrant) (store.AgentGrant, error) {
	var approval, lease any
	if g.RequiresApproval != nil {
		approval = *g.RequiresApproval
	}
	if g.LeaseTTLSeconds != nil {
		lease = *g.LeaseTTLSeconds
	}
	out, err := scanAgentGrant(s.db.QueryRowContext(ctx, `INSERT INTO agent_grants (`+agentGrantCols+`)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
ON CONFLICT (account_id, agent_id, credential) DO UPDATE SET actions = EXCLUDED.actions, not_before = EXCLUDED.not_before,
	not_after = EXCLUDED.not_after, window_start = EXCLUDED.window_start, window_end = EXCLUDED.window_end,
	window_days = EXCLUDED.window_days, timezone = EXCLUDED.timezone, max_uses_per_hour = EXCLUDED.max_uses_per_hour,
	requires_approval = EXCLUDED.requires_approval, lease_ttl_seconds = EXCLUDED.lease_ttl_seconds,
	updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by
RETURNING `+agentGrantCols,
		g.GrantID, g.AccountID, g.AgentID, g.Credential, agentJSON(g.Actions), agentNullTime(g.NotBefore), agentNullTime(g.NotAfter),
		g.WindowStart, g.WindowEnd, agentJSON(g.WindowDays), g.Timezone, g.MaxUsesPerHour, approval, lease,
		g.CreatedAt.UTC(), g.CreatedBy, g.UpdatedAt.UTC(), g.UpdatedBy))
	if idnFKViolation(err) {
		// Which reference failed: the agent or the credential.
		if _, gerr := s.GetAgent(ctx, g.AccountID, g.AgentID); gerr != nil {
			return store.AgentGrant{}, store.ErrAgentNotFound
		}
		return store.AgentGrant{}, store.ErrAgentCredentialNotFound
	}
	return out, err
}

func (s *Store) ListAgentGrants(ctx context.Context, accountID, agentID string) ([]store.AgentGrant, error) {
	q := `SELECT ` + agentGrantCols + ` FROM agent_grants WHERE account_id = $1`
	args := []any{accountID}
	if agentID != "" {
		q += ` AND agent_id = $2`
		args = append(args, agentID)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY agent_id, credential`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.AgentGrant{}
	for rows.Next() {
		g, err := scanAgentGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) DeleteAgentGrant(ctx context.Context, accountID, agentID, grantID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM agent_grants WHERE account_id = $1 AND agent_id = $2 AND grant_id = $3`, accountID, agentID, grantID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrAgentGrantNotFound
	}
	return nil
}

func (s *Store) GetAgentSettings(ctx context.Context, accountID string) (store.AgentSettings, error) {
	out := store.AgentSettings{AccountID: accountID}
	var at sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT agents_suspended, suspended_at, suspended_by, reason, updated_at FROM agent_settings WHERE account_id = $1`, accountID).
		Scan(&out.AgentsSuspended, &at, &out.SuspendedBy, &out.Reason, &out.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return store.AgentSettings{}, err
	}
	out.SuspendedAt = fromNullTime(at)
	out.UpdatedAt = out.UpdatedAt.UTC()
	return out, nil
}

func (s *Store) PutAgentSettings(ctx context.Context, st store.AgentSettings) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO agent_settings (account_id, agents_suspended, suspended_at, suspended_by, reason, updated_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (account_id) DO UPDATE SET agents_suspended = EXCLUDED.agents_suspended, suspended_at = EXCLUDED.suspended_at,
	suspended_by = EXCLUDED.suspended_by, reason = EXCLUDED.reason, updated_at = EXCLUDED.updated_at`,
		st.AccountID, st.AgentsSuspended, agentNullTime(st.SuspendedAt), st.SuspendedBy, st.Reason, st.UpdatedAt.UTC())
	return err
}
