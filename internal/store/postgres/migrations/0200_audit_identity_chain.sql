-- Audit identity, tenant isolation and per-account hash chains.
--
-- Every event now records its account, who acted (actor, actor type, display
-- name, access key), on what (resource), from where (source IP, user agent),
-- and its position in its account's chain (chain_seq). Rows written before
-- this migration keep hash_version 1 and are verified for linkage only.

ALTER TABLE kms_audit_events ADD COLUMN IF NOT EXISTS account_id TEXT NOT NULL DEFAULT '';
ALTER TABLE kms_audit_events ADD COLUMN IF NOT EXISTS chain_seq BIGINT;
ALTER TABLE kms_audit_events ADD COLUMN IF NOT EXISTS hash_version SMALLINT NOT NULL DEFAULT 1;
ALTER TABLE kms_audit_events ADD COLUMN IF NOT EXISTS resource TEXT NOT NULL DEFAULT '';
ALTER TABLE kms_audit_events ADD COLUMN IF NOT EXISTS actor_type TEXT NOT NULL DEFAULT '';
ALTER TABLE kms_audit_events ADD COLUMN IF NOT EXISTS actor_display_name TEXT NOT NULL DEFAULT '';
ALTER TABLE kms_audit_events ADD COLUMN IF NOT EXISTS access_key_id TEXT NOT NULL DEFAULT '';
ALTER TABLE kms_audit_events ADD COLUMN IF NOT EXISTS source_ip TEXT NOT NULL DEFAULT '';
ALTER TABLE kms_audit_events ADD COLUMN IF NOT EXISTS user_agent TEXT NOT NULL DEFAULT '';

-- Backfill: every pre-existing event belongs to the deployment account. When
-- the deployment identity is not recorded yet, the store backfills on startup.
UPDATE kms_audit_events
SET account_id = (SELECT setting_value FROM kms_settings WHERE setting_key = 'aws_account_id')
WHERE account_id = ''
  AND EXISTS (SELECT 1 FROM kms_settings WHERE setting_key = 'aws_account_id' AND setting_value <> '');

-- The old global chain becomes each account's (in practice the deployment
-- account's) legacy prefix, in insertion order.
UPDATE kms_audit_events e
SET chain_seq = n.seq
FROM (SELECT id, ROW_NUMBER() OVER (PARTITION BY account_id ORDER BY id) AS seq FROM kms_audit_events) n
WHERE e.id = n.id AND e.chain_seq IS NULL;

-- Legacy rows said "ok"; the contract says success | denied | error.
UPDATE kms_audit_events SET result = 'success' WHERE hash_version = 1 AND result = 'ok';
UPDATE kms_audit_events SET result = 'denied'
WHERE hash_version = 1 AND result = 'error' AND error_type ILIKE '%accessdenied%';
UPDATE kms_audit_events SET actor_type = 'legacy' WHERE hash_version = 1 AND actor_type = '';

-- (account_id, chain_seq) unique: two writers can never both extend a chain
-- from the same predecessor, whatever happens to the head row.
CREATE UNIQUE INDEX IF NOT EXISTS kms_audit_events_account_seq ON kms_audit_events (account_id, chain_seq);
-- Listing (newest first) and keyset export within an account.
CREATE INDEX IF NOT EXISTS kms_audit_events_account_id ON kms_audit_events (account_id, id DESC);
-- Time-range filters.
CREATE INDEX IF NOT EXISTS kms_audit_events_account_created ON kms_audit_events (account_id, created_at DESC);
-- Result filter (denied / error triage).
CREATE INDEX IF NOT EXISTS kms_audit_events_account_result ON kms_audit_events (account_id, result, id DESC);

-- One row per account: the tip of its chain. Appends lock it FOR UPDATE, so
-- they are serialized per account across every replica.
CREATE TABLE IF NOT EXISTS audit_chain_heads (
	account_id TEXT PRIMARY KEY,
	chain_seq BIGINT NOT NULL,
	head_hash TEXT NOT NULL,
	head_event_id BIGINT NOT NULL DEFAULT 0,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO audit_chain_heads (account_id, chain_seq, head_hash, head_event_id)
SELECT DISTINCT ON (account_id) account_id, chain_seq, COALESCE(event_hash, ''), id
FROM kms_audit_events
WHERE account_id <> ''
ORDER BY account_id, chain_seq DESC
ON CONFLICT (account_id) DO NOTHING;

-- Remembered verification point per account.
CREATE TABLE IF NOT EXISTS audit_chain_verifications (
	account_id TEXT PRIMARY KEY,
	status TEXT NOT NULL,
	verified_seq BIGINT NOT NULL DEFAULT 0,
	verified_event_id BIGINT NOT NULL DEFAULT 0,
	verified_hash TEXT NOT NULL DEFAULT '',
	head_hash TEXT NOT NULL DEFAULT '',
	broken_event_id BIGINT NOT NULL DEFAULT 0,
	broken_seq BIGINT NOT NULL DEFAULT 0,
	total_events BIGINT NOT NULL DEFAULT 0,
	checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- SIEM streaming settings per account. token_sealed is AES-GCM ciphertext
-- produced by the server; the database never sees the token in clear.
CREATE TABLE IF NOT EXISTS audit_stream_settings (
	account_id TEXT PRIMARY KEY,
	enabled BOOLEAN NOT NULL DEFAULT FALSE,
	url TEXT NOT NULL DEFAULT '',
	format TEXT NOT NULL DEFAULT 'json',
	token_sealed BYTEA,
	updated_by TEXT NOT NULL DEFAULT '',
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Events awaiting delivery. Rows are inserted in the append transaction, so
-- an event is queued if and only if it was recorded.
CREATE TABLE IF NOT EXISTS audit_stream_outbox (
	id BIGSERIAL PRIMARY KEY,
	event_id BIGINT NOT NULL,
	account_id TEXT NOT NULL,
	attempts INTEGER NOT NULL DEFAULT 0,
	next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	last_error TEXT NOT NULL DEFAULT '',
	dead BOOLEAN NOT NULL DEFAULT FALSE,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS audit_stream_outbox_due ON audit_stream_outbox (next_attempt_at) WHERE NOT dead;
