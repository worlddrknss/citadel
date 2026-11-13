-- AI agents (2.2): agents, their bearer tokens, workload identity bindings,
-- credential usage profiles, grants and the per-account kill switch. All new,
-- empty tables, so this migration is instant on any database.
CREATE TABLE IF NOT EXISTS agents (
	agent_id          TEXT PRIMARY KEY,
	account_id        TEXT NOT NULL,
	name              TEXT NOT NULL,
	description       TEXT NOT NULL DEFAULT '',
	owner             TEXT NOT NULL,
	status            TEXT NOT NULL DEFAULT 'active',
	labels_json       TEXT NOT NULL DEFAULT '{}',
	created_at        TIMESTAMPTZ NOT NULL,
	created_by        TEXT NOT NULL DEFAULT '',
	updated_at        TIMESTAMPTZ NOT NULL,
	last_used_at      TIMESTAMPTZ,
	status_changed_at TIMESTAMPTZ,
	status_changed_by TEXT NOT NULL DEFAULT '',
	status_reason     TEXT NOT NULL DEFAULT '',
	CONSTRAINT agents_account_id_unique UNIQUE (account_id, agent_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS agents_account_name_idx ON agents (account_id, lower(name));

CREATE TABLE IF NOT EXISTS agent_tokens (
	token_id     TEXT PRIMARY KEY,
	account_id   TEXT NOT NULL,
	agent_id     TEXT NOT NULL,
	name         TEXT NOT NULL DEFAULT '',
	hint         TEXT NOT NULL,
	hash         TEXT NOT NULL,
	created_at   TIMESTAMPTZ NOT NULL,
	created_by   TEXT NOT NULL DEFAULT '',
	expires_at   TIMESTAMPTZ,
	revoked_at   TIMESTAMPTZ,
	revoked_by   TEXT NOT NULL DEFAULT '',
	last_used_at TIMESTAMPTZ,
	CONSTRAINT agent_tokens_agent_fkey FOREIGN KEY (account_id, agent_id)
		REFERENCES agents (account_id, agent_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS agent_tokens_lookup_idx ON agent_tokens (agent_id, hint);

CREATE TABLE IF NOT EXISTS agent_bindings (
	binding_id  TEXT PRIMARY KEY,
	account_id  TEXT NOT NULL,
	agent_id    TEXT NOT NULL,
	issuer      TEXT NOT NULL,
	subject     TEXT NOT NULL,
	audience    TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	created_at  TIMESTAMPTZ NOT NULL,
	created_by  TEXT NOT NULL DEFAULT '',
	CONSTRAINT agent_bindings_agent_fkey FOREIGN KEY (account_id, agent_id)
		REFERENCES agents (account_id, agent_id) ON DELETE CASCADE,
	CONSTRAINT agent_bindings_unique UNIQUE (account_id, agent_id, issuer, subject, audience)
);
CREATE INDEX IF NOT EXISTS agent_bindings_lookup_idx ON agent_bindings (issuer, subject);

-- Usage profiles reference a secret by its backing name. There is no foreign
-- key to sm_secrets: a profile whose secret is gone is reported unavailable
-- rather than silently deleted.
CREATE TABLE IF NOT EXISTS agent_credentials (
	account_id            TEXT NOT NULL,
	name                  TEXT NOT NULL,
	secret_name           TEXT NOT NULL,
	kind                  TEXT NOT NULL,
	description           TEXT NOT NULL DEFAULT '',
	allowed_hosts         TEXT NOT NULL DEFAULT '[]',
	allowed_methods       TEXT NOT NULL DEFAULT '[]',
	allowed_path_prefixes TEXT NOT NULL DEFAULT '[]',
	header_name           TEXT NOT NULL DEFAULT '',
	header_prefix         TEXT NOT NULL DEFAULT '',
	query_param           TEXT NOT NULL DEFAULT '',
	allow_http            BOOLEAN NOT NULL DEFAULT FALSE,
	allowed_cidrs         TEXT NOT NULL DEFAULT '[]',
	created_at            TIMESTAMPTZ NOT NULL,
	created_by            TEXT NOT NULL DEFAULT '',
	updated_at            TIMESTAMPTZ NOT NULL,
	updated_by            TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (account_id, name)
);
CREATE INDEX IF NOT EXISTS agent_credentials_secret_idx ON agent_credentials (account_id, secret_name);

-- requires_approval and lease_ttl_seconds are reserved for 2.3 (NULL = not
-- set).
CREATE TABLE IF NOT EXISTS agent_grants (
	grant_id          TEXT PRIMARY KEY,
	account_id        TEXT NOT NULL,
	agent_id          TEXT NOT NULL,
	credential        TEXT NOT NULL,
	actions           TEXT NOT NULL DEFAULT '["use"]',
	not_before        TIMESTAMPTZ,
	not_after         TIMESTAMPTZ,
	window_start      TEXT NOT NULL DEFAULT '',
	window_end        TEXT NOT NULL DEFAULT '',
	window_days       TEXT NOT NULL DEFAULT '[]',
	timezone          TEXT NOT NULL DEFAULT '',
	max_uses_per_hour INTEGER NOT NULL DEFAULT 0,
	requires_approval BOOLEAN,
	lease_ttl_seconds INTEGER,
	created_at        TIMESTAMPTZ NOT NULL,
	created_by        TEXT NOT NULL DEFAULT '',
	updated_at        TIMESTAMPTZ NOT NULL,
	updated_by        TEXT NOT NULL DEFAULT '',
	CONSTRAINT agent_grants_agent_fkey FOREIGN KEY (account_id, agent_id)
		REFERENCES agents (account_id, agent_id) ON DELETE CASCADE,
	CONSTRAINT agent_grants_credential_fkey FOREIGN KEY (account_id, credential)
		REFERENCES agent_credentials (account_id, name),
	CONSTRAINT agent_grants_unique UNIQUE (account_id, agent_id, credential)
);
CREATE INDEX IF NOT EXISTS agent_grants_credential_idx ON agent_grants (account_id, credential);

CREATE TABLE IF NOT EXISTS agent_settings (
	account_id       TEXT PRIMARY KEY,
	agents_suspended BOOLEAN NOT NULL DEFAULT FALSE,
	suspended_at     TIMESTAMPTZ,
	suspended_by     TEXT NOT NULL DEFAULT '',
	reason           TEXT NOT NULL DEFAULT '',
	updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
