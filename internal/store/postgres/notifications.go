package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/lib/pq"
	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

const notificationChannelCols = `id, account_id, name, type, enabled, events, url, url_sealed, url_hint, recipients, secret_sealed,
	created_at, created_by, updated_at, updated_by`

func scanNotificationChannel(sc interface{ Scan(...any) error }) (store.NotificationChannel, error) {
	var ch store.NotificationChannel
	var events, recipients pq.StringArray
	err := sc.Scan(&ch.ID, &ch.AccountID, &ch.Name, &ch.Type, &ch.Enabled, &events, &ch.URL, &ch.URLSealed, &ch.URLHint,
		&recipients, &ch.SecretSealed, &ch.CreatedAt, &ch.CreatedBy, &ch.UpdatedAt, &ch.UpdatedBy)
	ch.Events, ch.Recipients = []string(events), []string(recipients)
	ch.CreatedAt, ch.UpdatedAt = ch.CreatedAt.UTC(), ch.UpdatedAt.UTC()
	return ch, err
}

func (s *Store) ListNotificationChannels(ctx context.Context, accountID string) ([]store.NotificationChannel, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+notificationChannelCols+` FROM notification_channels WHERE account_id = $1 ORDER BY name`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.NotificationChannel
	for rows.Next() {
		ch, err := scanNotificationChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ch)
	}
	return out, rows.Err()
}

func (s *Store) GetNotificationChannel(ctx context.Context, accountID, id string) (store.NotificationChannel, error) {
	ch, err := scanNotificationChannel(s.db.QueryRowContext(ctx,
		`SELECT `+notificationChannelCols+` FROM notification_channels WHERE account_id = $1 AND id = $2`, accountID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return store.NotificationChannel{}, store.ErrNotificationChannelNotFound
	}
	return ch, err
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func (s *Store) CreateNotificationChannel(ctx context.Context, ch store.NotificationChannel) error {
	if ch.AccountID == "" || ch.ID == "" {
		return errors.New("account and id are required")
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO notification_channels (id, account_id, name, type, enabled, events, url, url_sealed, url_hint, recipients, secret_sealed,
	created_at, created_by, updated_at, updated_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), $12, NOW(), $12)`,
		ch.ID, ch.AccountID, ch.Name, ch.Type, ch.Enabled, pq.Array(nonNil(ch.Events)), ch.URL, ch.URLSealed, ch.URLHint,
		pq.Array(nonNil(ch.Recipients)), ch.SecretSealed, ch.CreatedBy)
	if isUniqueViolation(err) {
		return store.ErrNotificationChannelExists
	}
	return err
}

func (s *Store) UpdateNotificationChannel(ctx context.Context, ch store.NotificationChannel) error {
	res, err := s.db.ExecContext(ctx, `
UPDATE notification_channels SET name = $3, enabled = $4, events = $5, url = $6, url_sealed = $7, url_hint = $8, recipients = $9,
	secret_sealed = $10, updated_at = NOW(), updated_by = $11
WHERE account_id = $1 AND id = $2`,
		ch.AccountID, ch.ID, ch.Name, ch.Enabled, pq.Array(nonNil(ch.Events)), ch.URL, ch.URLSealed, ch.URLHint,
		pq.Array(nonNil(ch.Recipients)), ch.SecretSealed, ch.UpdatedBy)
	if isUniqueViolation(err) {
		return store.ErrNotificationChannelExists
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotificationChannelNotFound
	}
	return nil
}

func (s *Store) DeleteNotificationChannel(ctx context.Context, accountID, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM notification_channels WHERE account_id = $1 AND id = $2`, accountID, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotificationChannelNotFound
	}
	return nil
}

func (s *Store) EnqueueNotification(ctx context.Context, n store.NotificationEnqueue) (int, error) {
	var res sql.Result
	var err error
	if n.ChannelID != "" {
		res, err = s.db.ExecContext(ctx, `
INSERT INTO notification_outbox (account_id, channel_id, event_id, event_type, payload)
SELECT account_id, id, $3, $4, $5 FROM notification_channels WHERE account_id = $1 AND id = $2`,
			n.AccountID, n.ChannelID, n.EventID, n.EventType, n.Payload)
	} else {
		res, err = s.db.ExecContext(ctx, `
INSERT INTO notification_outbox (account_id, channel_id, event_id, event_type, payload)
SELECT account_id, id, $2, $3, $4 FROM notification_channels WHERE account_id = $1 AND enabled AND $3 = ANY(events)`,
			n.AccountID, n.EventID, n.EventType, n.Payload)
	}
	if err != nil {
		return 0, err
	}
	count, _ := res.RowsAffected()
	return int(count), nil
}

const notificationDeliveryCols = `id, account_id, channel_id, event_id, event_type, payload, status, attempts, last_error, status_code,
	created_at, next_attempt_at, last_attempt_at, delivered_at, lease_token`

func scanNotificationDelivery(sc interface{ Scan(...any) error }) (store.NotificationDelivery, error) {
	var d store.NotificationDelivery
	var next time.Time
	var last, delivered sql.NullTime
	err := sc.Scan(&d.ID, &d.AccountID, &d.ChannelID, &d.EventID, &d.EventType, &d.Payload, &d.Status, &d.Attempts, &d.LastError,
		&d.StatusCode, &d.CreatedAt, &next, &last, &delivered, &d.LeaseToken)
	d.CreatedAt = d.CreatedAt.UTC()
	if d.Status == store.NotificationPending {
		t := next.UTC()
		d.NextAttemptAt = &t
	}
	if last.Valid {
		t := last.Time.UTC()
		d.LastAttemptAt = &t
	}
	if delivered.Valid {
		t := delivered.Time.UTC()
		d.DeliveredAt = &t
	}
	return d, err
}

// ClaimNotificationDeliveries leases due rows with SKIP LOCKED, so workers
// on every replica can run concurrently without taking the same row; the
// lease (a later next_attempt_at and a fresh token) keeps them from taking
// it again until the attempt has had time to finish.
func (s *Store) ClaimNotificationDeliveries(ctx context.Context, limit int, lease time.Duration) ([]store.NotificationDelivery, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `
SELECT `+notificationDeliveryCols+` FROM notification_outbox
WHERE status = 'pending' AND next_attempt_at <= NOW()
ORDER BY next_attempt_at, id
LIMIT $1
FOR UPDATE SKIP LOCKED`, limit)
	if err != nil {
		return nil, err
	}
	var out []store.NotificationDelivery
	for rows.Next() {
		d, err := scanNotificationDelivery(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	until := time.Now().UTC().Add(lease)
	for i := range out {
		out[i].LeaseToken = cryptoutil.RandomHex(16)
		if _, err := tx.ExecContext(ctx, `UPDATE notification_outbox SET next_attempt_at = $2, lease_token = $3 WHERE id = $1`,
			out[i].ID, until, out[i].LeaseToken); err != nil {
			return nil, err
		}
		out[i].NextAttemptAt = &until
	}
	return out, tx.Commit()
}

func (s *Store) CompleteNotificationDelivery(ctx context.Context, id int64, leaseToken string, statusCode int) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE notification_outbox SET status = 'delivered', attempts = attempts + 1, status_code = $3, last_error = '', lease_token = '',
	last_attempt_at = NOW(), delivered_at = NOW()
WHERE id = $1 AND lease_token = $2 AND status = 'pending'`, id, leaseToken, statusCode)
	return err
}

func (s *Store) RetryNotificationDelivery(ctx context.Context, id int64, leaseToken string, next time.Time, lastErr string, statusCode int, dead bool) error {
	status := store.NotificationPending
	if dead {
		status = store.NotificationDead
	}
	_, err := s.db.ExecContext(ctx, `
UPDATE notification_outbox SET status = $3, attempts = attempts + 1, next_attempt_at = $4, last_error = $5, status_code = $6,
	lease_token = '', last_attempt_at = NOW()
WHERE id = $1 AND lease_token = $2 AND status = 'pending'`,
		id, leaseToken, status, next.UTC(), store.TruncateNotificationError(lastErr), statusCode)
	return err
}

func (s *Store) ListNotificationDeliveries(ctx context.Context, accountID, channelID string, limit int) ([]store.NotificationDelivery, error) {
	if limit <= 0 {
		limit = 50
	}
	var rows *sql.Rows
	var err error
	if channelID != "" {
		rows, err = s.db.QueryContext(ctx, `SELECT `+notificationDeliveryCols+` FROM notification_outbox
WHERE account_id = $1 AND channel_id = $2 ORDER BY id DESC LIMIT $3`, accountID, channelID, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `SELECT `+notificationDeliveryCols+` FROM notification_outbox
WHERE account_id = $1 ORDER BY id DESC LIMIT $2`, accountID, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.NotificationDelivery
	for rows.Next() {
		d, err := scanNotificationDelivery(rows)
		if err != nil {
			return nil, err
		}
		d.LeaseToken = ""
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) RequeueNotificationDelivery(ctx context.Context, accountID string, id int64) error {
	res, err := s.db.ExecContext(ctx, `
UPDATE notification_outbox SET status = 'pending', attempts = 0, next_attempt_at = NOW(), lease_token = ''
WHERE account_id = $1 AND id = $2 AND status = 'dead'`, accountID, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotificationDeliveryNotFound
	}
	return nil
}

func (s *Store) PurgeNotificationDeliveries(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM notification_outbox WHERE status IN ('delivered', 'dead') AND created_at < $1`, before.UTC())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
