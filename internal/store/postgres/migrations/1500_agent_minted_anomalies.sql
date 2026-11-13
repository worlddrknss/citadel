-- AI agents 2.4: login and minted credentials, grant scopes, and anomaly
-- alerts. Adding a column with a constant default is a catalog-only change
-- (no table rewrite), and the new tables start empty, so this migration is
-- instant on any database.
ALTER TABLE agent_credentials
	ADD COLUMN IF NOT EXISTS config TEXT NOT NULL DEFAULT '{}';

ALTER TABLE agent_grants
	ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT '{}';

-- Per-agent anomaly settings; no row means alerts on, auto-suspend off.
CREATE TABLE IF NOT EXISTS agent_anomaly_settings (
	account_id      TEXT NOT NULL,
	agent_id        TEXT NOT NULL,
	alerts_disabled BOOLEAN NOT NULL DEFAULT FALSE,
	auto_suspend    BOOLEAN NOT NULL DEFAULT FALSE,
	updated_at      TIMESTAMPTZ NOT NULL,
	updated_by      TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (account_id, agent_id),
	CONSTRAINT agent_anomaly_settings_agent_fkey FOREIGN KEY (account_id, agent_id)
		REFERENCES agents (account_id, agent_id) ON DELETE CASCADE
);

-- Detected anomalies. The unique (agent, kind, hour) key de-duplicates
-- alerts across replicas: once per kind per agent per hour.
CREATE TABLE IF NOT EXISTS agent_anomalies (
	anomaly_id  TEXT PRIMARY KEY,
	account_id  TEXT NOT NULL,
	agent_id    TEXT NOT NULL,
	kind        TEXT NOT NULL,
	detail      TEXT NOT NULL DEFAULT '',
	hour        TIMESTAMPTZ NOT NULL,
	detected_at TIMESTAMPTZ NOT NULL,
	suspended   BOOLEAN NOT NULL DEFAULT FALSE,
	CONSTRAINT agent_anomalies_agent_fkey FOREIGN KEY (account_id, agent_id)
		REFERENCES agents (account_id, agent_id) ON DELETE CASCADE,
	CONSTRAINT agent_anomalies_dedupe UNIQUE (account_id, agent_id, kind, hour)
);
CREATE INDEX IF NOT EXISTS agent_anomalies_agent_idx ON agent_anomalies (account_id, agent_id, detected_at DESC);
