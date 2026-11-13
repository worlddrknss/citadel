-- Audit retention (2.5): per-account retention overrides and the chain
-- anchor each prune advances. Two new, empty tables: no change to
-- kms_audit_events, so this is instant on a large audit log. Pruning uses
-- the existing (account_id, chain_seq) unique index to find and delete the
-- oldest events, and (account_id, created_at) to count what a retention
-- would prune; no new index on the audit table is needed.

-- An account's override of KMS_AUDIT_RETENTION_DAYS. No row: use the
-- deployment default. retention_days 0: keep forever.
CREATE TABLE IF NOT EXISTS audit_retention_settings (
	account_id TEXT PRIMARY KEY,
	retention_days INTEGER NOT NULL CHECK (retention_days = 0 OR retention_days BETWEEN 7 AND 3650),
	updated_by TEXT NOT NULL DEFAULT '',
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The authenticated start of an account's chain after pruning: the position,
-- ID and MAC of the last pruned event, the timestamp everything older than
-- which is gone, and a running count. mac is HMAC-SHA256 over every field
-- (store.AuditAnchorMAC), so an edited or forged anchor fails verification.
CREATE TABLE IF NOT EXISTS audit_chain_anchors (
	account_id TEXT PRIMARY KEY,
	chain_seq BIGINT NOT NULL,
	event_id BIGINT NOT NULL,
	event_hash TEXT NOT NULL,
	pruned_before TIMESTAMPTZ NOT NULL,
	pruned_events BIGINT NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL,
	mac TEXT NOT NULL
);
