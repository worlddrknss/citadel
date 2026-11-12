-- Identity: console SSO (owning account, email domain allowlist, linked
-- external identities, single-use sign-in states) and the workload identity
-- issuer (signing keys, settings, clients).

ALTER TABLE console_sso_providers ADD COLUMN IF NOT EXISTS account_id TEXT NOT NULL DEFAULT '';
ALTER TABLE console_sso_providers ADD COLUMN IF NOT EXISTS allowed_email_domains_json TEXT NOT NULL DEFAULT '[]';

-- An identity at a provider is keyed by (provider, subject), never by email,
-- so a provider cannot take over a user by asserting their address.
CREATE TABLE IF NOT EXISTS console_sso_identities (
	provider_id TEXT NOT NULL REFERENCES console_sso_providers(id) ON DELETE CASCADE,
	subject TEXT NOT NULL,
	username TEXT NOT NULL REFERENCES ui_users(username) ON DELETE CASCADE,
	email TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL,
	last_login_at TIMESTAMPTZ NOT NULL,
	PRIMARY KEY (provider_id, subject)
);
CREATE INDEX IF NOT EXISTS console_sso_identities_username_idx ON console_sso_identities (username);

-- Consumed single-use values (OIDC sign-in states), shared by replicas.
CREATE TABLE IF NOT EXISTS consumed_once (
	id TEXT PRIMARY KEY,
	expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS consumed_once_expires_idx ON consumed_once (expires_at);

-- Workload identity issuer signing keys (Citadel KMS keys). At most one row
-- has retired_at NULL: the current key.
CREATE TABLE IF NOT EXISTS workload_signing_keys (
	kid TEXT PRIMARY KEY,
	kms_key_id TEXT NOT NULL,
	algorithm TEXT NOT NULL,
	activated_at TIMESTAMPTZ NOT NULL,
	retired_at TIMESTAMPTZ,
	unpublish_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS workload_signing_keys_current_idx ON workload_signing_keys ((retired_at IS NULL)) WHERE retired_at IS NULL;

CREATE TABLE IF NOT EXISTS workload_issuer_settings (
	id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
	algorithm TEXT NOT NULL DEFAULT '',
	rotation_days INTEGER NOT NULL DEFAULT 0,
	updated_at TIMESTAMPTZ,
	updated_by TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS workload_clients (
	client_id TEXT PRIMARY KEY,
	account_id TEXT NOT NULL,
	name TEXT NOT NULL,
	audiences_json TEXT NOT NULL DEFAULT '[]',
	token_ttl_seconds INTEGER NOT NULL,
	subject_format TEXT NOT NULL,
	auth_method TEXT NOT NULL,
	allowed_users_json TEXT NOT NULL DEFAULT '[]',
	api_server TEXT NOT NULL DEFAULT '',
	ca_pem TEXT NOT NULL DEFAULT '',
	service_accounts_json TEXT NOT NULL DEFAULT '[]',
	review_audience TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL,
	last_issued_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS workload_clients_account_idx ON workload_clients (account_id);
