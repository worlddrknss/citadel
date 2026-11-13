-- Just-in-time agent access (2.3): access requests, leases, and agents that
-- must authenticate with workload identity federation.
--
-- Instant on any database: the new column has a constant default (a
-- catalog-only change, no table rewrite), and the tables and their indexes
-- are new and empty.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS require_federation BOOLEAN NOT NULL DEFAULT FALSE;

-- An agent's request for access. credential is not a foreign key: an agent
-- may ask for a credential that doesn't exist (it must not learn which do),
-- and the request is then refused when someone tries to approve it.
CREATE TABLE IF NOT EXISTS agent_access_requests (
	request_id       TEXT PRIMARY KEY,
	account_id       TEXT NOT NULL,
	agent_id         TEXT NOT NULL,
	credential       TEXT NOT NULL,
	actions          TEXT NOT NULL,
	reason           TEXT NOT NULL DEFAULT '',
	task_id          TEXT NOT NULL DEFAULT '',
	duration_seconds INTEGER NOT NULL DEFAULT 0,
	origin           TEXT NOT NULL,
	status           TEXT NOT NULL DEFAULT 'pending',
	created_at       TIMESTAMPTZ NOT NULL,
	expires_at       TIMESTAMPTZ NOT NULL,
	decided_at       TIMESTAMPTZ,
	decided_by       TEXT NOT NULL DEFAULT '',
	decision_comment TEXT NOT NULL DEFAULT '',
	scope            TEXT NOT NULL DEFAULT '',
	lease_id         TEXT NOT NULL DEFAULT '',
	CONSTRAINT agent_access_requests_agent_fkey FOREIGN KEY (account_id, agent_id)
		REFERENCES agents (account_id, agent_id) ON DELETE CASCADE
);
-- One pending request per agent, credential, actions and task: asking again
-- returns the open one, even under concurrency.
CREATE UNIQUE INDEX IF NOT EXISTS agent_access_requests_pending_idx
	ON agent_access_requests (account_id, agent_id, credential, actions, task_id) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS agent_access_requests_account_idx ON agent_access_requests (account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS agent_access_requests_agent_idx ON agent_access_requests (account_id, agent_id, created_at DESC);

-- Time-boxed access to a credential. uses_left NULL means unlimited uses
-- until expires_at.
CREATE TABLE IF NOT EXISTS agent_leases (
	lease_id     TEXT PRIMARY KEY,
	account_id   TEXT NOT NULL,
	agent_id     TEXT NOT NULL,
	credential   TEXT NOT NULL,
	actions      TEXT NOT NULL,
	scope        TEXT NOT NULL,
	task_id      TEXT NOT NULL DEFAULT '',
	uses_left    INTEGER,
	use_count    INTEGER NOT NULL DEFAULT 0,
	expires_at   TIMESTAMPTZ NOT NULL,
	created_at   TIMESTAMPTZ NOT NULL,
	created_by   TEXT NOT NULL DEFAULT '',
	request_id   TEXT NOT NULL DEFAULT '',
	last_used_at TIMESTAMPTZ,
	ended_at     TIMESTAMPTZ,
	ended_by     TEXT NOT NULL DEFAULT '',
	ended_reason TEXT NOT NULL DEFAULT '',
	CONSTRAINT agent_leases_agent_fkey FOREIGN KEY (account_id, agent_id)
		REFERENCES agents (account_id, agent_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS agent_leases_active_idx
	ON agent_leases (account_id, agent_id, credential, expires_at) WHERE ended_at IS NULL;
CREATE INDEX IF NOT EXISTS agent_leases_account_idx ON agent_leases (account_id, created_at DESC);
