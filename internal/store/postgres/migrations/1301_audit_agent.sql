-- Per-agent audit attribution (2.2): the agent an event concerns, its owner
-- and the agent's task ID. Columns with a constant default are a
-- catalog-only change (no table rewrite); existing rows read back as ''.
ALTER TABLE kms_audit_events
	ADD COLUMN IF NOT EXISTS agent_id TEXT NOT NULL DEFAULT '',
	ADD COLUMN IF NOT EXISTS agent_owner TEXT NOT NULL DEFAULT '',
	ADD COLUMN IF NOT EXISTS task_id TEXT NOT NULL DEFAULT '';

-- Partial index for an agent's activity. Every existing row has '' and is
-- left out, so the build is one scan and the index starts empty.
CREATE INDEX IF NOT EXISTS kms_audit_events_agent_idx
	ON kms_audit_events (account_id, agent_id, id DESC) WHERE agent_id <> '';
