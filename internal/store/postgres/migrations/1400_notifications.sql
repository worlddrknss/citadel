-- Notification channels and their delivery outbox. Both are new, empty
-- tables, so this migration is instant on any database. Deliveries cascade
-- with their channel.
CREATE TABLE IF NOT EXISTS notification_channels (
	id            TEXT PRIMARY KEY,
	account_id    TEXT NOT NULL,
	name          TEXT NOT NULL,
	type          TEXT NOT NULL,
	enabled       BOOLEAN NOT NULL DEFAULT TRUE,
	events        TEXT[] NOT NULL DEFAULT '{}',
	url           TEXT NOT NULL DEFAULT '',
	url_sealed    BYTEA,
	url_hint      TEXT NOT NULL DEFAULT '',
	recipients    TEXT[] NOT NULL DEFAULT '{}',
	secret_sealed BYTEA,
	created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	created_by    TEXT NOT NULL DEFAULT '',
	updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_by    TEXT NOT NULL DEFAULT '',
	CONSTRAINT notification_channels_name_key UNIQUE (account_id, name)
);

CREATE TABLE IF NOT EXISTS notification_outbox (
	id              BIGSERIAL PRIMARY KEY,
	account_id      TEXT NOT NULL,
	channel_id      TEXT NOT NULL REFERENCES notification_channels (id) ON DELETE CASCADE,
	event_id        TEXT NOT NULL,
	event_type      TEXT NOT NULL,
	payload         TEXT NOT NULL,
	status          TEXT NOT NULL DEFAULT 'pending',
	attempts        INTEGER NOT NULL DEFAULT 0,
	last_error      TEXT NOT NULL DEFAULT '',
	status_code     INTEGER NOT NULL DEFAULT 0,
	lease_token     TEXT NOT NULL DEFAULT '',
	created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	last_attempt_at TIMESTAMPTZ,
	delivered_at    TIMESTAMPTZ
);
-- The worker's claim scans only pending rows.
CREATE INDEX IF NOT EXISTS notification_outbox_due_idx
	ON notification_outbox (next_attempt_at) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS notification_outbox_channel_idx
	ON notification_outbox (account_id, channel_id, id DESC);
CREATE INDEX IF NOT EXISTS notification_outbox_created_idx
	ON notification_outbox (created_at);
