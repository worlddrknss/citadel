-- Console authentication: platform admins, persistent sessions, organization
-- settings and the console SSO provider table.

-- A platform admin (global role admin + this flag) manages every account;
-- other admins only the accounts where they hold the admin role.
ALTER TABLE ui_users ADD COLUMN IF NOT EXISTS platform_admin BOOLEAN NOT NULL DEFAULT FALSE;

-- Signed-in console sessions. token_hash is the hex SHA-256 of the cookie
-- value; the token itself is never stored. id is a separate public handle
-- used to list and revoke sessions.
CREATE TABLE IF NOT EXISTS console_sessions (
	id TEXT PRIMARY KEY,
	token_hash TEXT NOT NULL UNIQUE,
	username TEXT NOT NULL REFERENCES ui_users(username) ON DELETE CASCADE,
	account_id TEXT NOT NULL DEFAULT '',
	method TEXT NOT NULL DEFAULT 'password',
	ip TEXT NOT NULL DEFAULT '',
	user_agent TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL,
	last_seen_at TIMESTAMPTZ NOT NULL,
	expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS console_sessions_username_idx ON console_sessions (username);
CREATE INDEX IF NOT EXISTS console_sessions_expires_idx ON console_sessions (expires_at);
CREATE INDEX IF NOT EXISTS console_sessions_last_seen_idx ON console_sessions (last_seen_at);

-- Organization-wide settings: a single row (id = 1).
CREATE TABLE IF NOT EXISTS org_settings (
	id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
	organization_name TEXT NOT NULL DEFAULT '',
	approval_environments TEXT NOT NULL DEFAULT '[]',
	approval_min_approvers INTEGER NOT NULL DEFAULT 1,
	allow_self_approval BOOLEAN NOT NULL DEFAULT FALSE,
	session_idle_minutes INTEGER NOT NULL DEFAULT 0,
	session_max_hours INTEGER NOT NULL DEFAULT 0,
	updated_at TIMESTAMPTZ,
	updated_by TEXT NOT NULL DEFAULT ''
);

-- Console single sign-on (OIDC) providers. The client secret is stored
-- wrapped with the deployment wrapping key, never in plaintext.
CREATE TABLE IF NOT EXISTS console_sso_providers (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	issuer TEXT NOT NULL,
	client_id TEXT NOT NULL,
	client_secret_wrapped_b64 TEXT NOT NULL DEFAULT '',
	client_secret_nonce_b64 TEXT NOT NULL DEFAULT '',
	scopes_json TEXT NOT NULL DEFAULT '[]',
	group_claim TEXT NOT NULL DEFAULT '',
	role_mappings_json TEXT NOT NULL DEFAULT '[]',
	default_role TEXT NOT NULL DEFAULT 'none',
	enabled BOOLEAN NOT NULL DEFAULT TRUE,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
