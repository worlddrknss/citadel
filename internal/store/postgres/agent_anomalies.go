package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// Agent anomaly settings and detected anomalies (migration
// 1500_agent_minted_anomalies).

// agentAnomalyRetention is how long detected anomalies are kept.
const agentAnomalyRetention = 90 * 24 * time.Hour

func (s *Store) GetAgentAnomalySettings(ctx context.Context, accountID, agentID string) (store.AgentAnomalySettings, error) {
	out := store.AgentAnomalySettings{AccountID: accountID, AgentID: agentID}
	err := s.db.QueryRowContext(ctx, `SELECT alerts_disabled, auto_suspend, updated_at, updated_by FROM agent_anomaly_settings
WHERE account_id = $1 AND agent_id = $2`, accountID, agentID).Scan(&out.AlertsDisabled, &out.AutoSuspend, &out.UpdatedAt, &out.UpdatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return store.AgentAnomalySettings{}, err
	}
	out.UpdatedAt = out.UpdatedAt.UTC()
	return out, nil
}

func (s *Store) PutAgentAnomalySettings(ctx context.Context, st store.AgentAnomalySettings) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO agent_anomaly_settings (account_id, agent_id, alerts_disabled, auto_suspend, updated_at, updated_by)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (account_id, agent_id) DO UPDATE SET alerts_disabled = EXCLUDED.alerts_disabled, auto_suspend = EXCLUDED.auto_suspend,
	updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by`,
		st.AccountID, st.AgentID, st.AlertsDisabled, st.AutoSuspend, st.UpdatedAt.UTC(), st.UpdatedBy)
	if idnFKViolation(err) {
		return store.ErrAgentNotFound
	}
	return err
}

func (s *Store) RecordAgentAnomaly(ctx context.Context, a store.AgentAnomaly) error {
	res, err := s.db.ExecContext(ctx, `INSERT INTO agent_anomalies (anomaly_id, account_id, agent_id, kind, detail, hour, detected_at, suspended)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (account_id, agent_id, kind, hour) DO NOTHING`,
		a.AnomalyID, a.AccountID, a.AgentID, a.Kind, a.Detail, a.Hour.UTC(), a.DetectedAt.UTC(), a.Suspended)
	if idnFKViolation(err) {
		return store.ErrAgentNotFound
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrAgentAnomalyDuplicate
	}
	// Keep the table small: drop this agent's anomalies past retention.
	_, _ = s.db.ExecContext(ctx, `DELETE FROM agent_anomalies WHERE account_id = $1 AND agent_id = $2 AND detected_at < $3`,
		a.AccountID, a.AgentID, a.DetectedAt.Add(-agentAnomalyRetention).UTC())
	return nil
}

func (s *Store) MarkAgentAnomalySuspended(ctx context.Context, accountID, anomalyID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE agent_anomalies SET suspended = TRUE WHERE account_id = $1 AND anomaly_id = $2`, accountID, anomalyID)
	return err
}

func (s *Store) ListAgentAnomalies(ctx context.Context, accountID, agentID string, limit int) ([]store.AgentAnomaly, error) {
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	rows, err := s.db.QueryContext(ctx, `SELECT anomaly_id, kind, detail, hour, detected_at, suspended FROM agent_anomalies
WHERE account_id = $1 AND agent_id = $2 ORDER BY detected_at DESC, anomaly_id LIMIT $3`, accountID, agentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.AgentAnomaly{}
	for rows.Next() {
		a := store.AgentAnomaly{AccountID: accountID, AgentID: agentID}
		if err := rows.Scan(&a.AnomalyID, &a.Kind, &a.Detail, &a.Hour, &a.DetectedAt, &a.Suspended); err != nil {
			return nil, err
		}
		a.Hour, a.DetectedAt = a.Hour.UTC(), a.DetectedAt.UTC()
		out = append(out, a)
	}
	return out, rows.Err()
}
