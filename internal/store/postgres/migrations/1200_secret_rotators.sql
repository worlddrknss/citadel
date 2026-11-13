-- Built-in secret rotation: one row per secret with a rotator (or a
-- schedule) configured, and a bounded history of rotation attempts. Both are
-- new, empty tables, so this migration is instant on any database. They
-- reference sm_secrets with cascading keys, so renames and purges carry them.
CREATE TABLE IF NOT EXISTS sm_secret_rotations (
	account_id          TEXT NOT NULL,
	secret_name         TEXT NOT NULL,
	rotator_type        TEXT NOT NULL DEFAULT '',
	config_secret       TEXT NOT NULL DEFAULT '',
	config_json         TEXT NOT NULL DEFAULT '',
	signing_key_sealed  BYTEA,
	schedule_expression TEXT NOT NULL DEFAULT '',
	duration            TEXT NOT NULL DEFAULT '',
	status              TEXT NOT NULL DEFAULT '',
	last_step           TEXT NOT NULL DEFAULT '',
	last_error          TEXT NOT NULL DEFAULT '',
	attempts            INTEGER NOT NULL DEFAULT 0,
	last_attempt_at     TIMESTAMPTZ,
	next_attempt_at     TIMESTAMPTZ,
	last_rotated_at     TIMESTAMPTZ,
	lease_owner         TEXT NOT NULL DEFAULT '',
	lease_until         TIMESTAMPTZ,
	updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_by          TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (account_id, secret_name),
	CONSTRAINT sm_secret_rotations_secret_fkey FOREIGN KEY (account_id, secret_name)
		REFERENCES sm_secrets (account_id, name) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS sm_secret_rotation_history (
	id           BIGSERIAL PRIMARY KEY,
	account_id   TEXT NOT NULL,
	secret_name  TEXT NOT NULL,
	token        TEXT NOT NULL DEFAULT '',
	rotator_type TEXT NOT NULL DEFAULT '',
	trigger      TEXT NOT NULL DEFAULT '',
	status       TEXT NOT NULL DEFAULT '',
	step         TEXT NOT NULL DEFAULT '',
	error        TEXT NOT NULL DEFAULT '',
	actor        TEXT NOT NULL DEFAULT '',
	started_at   TIMESTAMPTZ NOT NULL,
	finished_at  TIMESTAMPTZ NOT NULL,
	CONSTRAINT sm_secret_rotation_history_secret_fkey FOREIGN KEY (account_id, secret_name)
		REFERENCES sm_secrets (account_id, name) ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX IF NOT EXISTS sm_secret_rotation_history_secret_idx
	ON sm_secret_rotation_history (account_id, secret_name, id DESC);
