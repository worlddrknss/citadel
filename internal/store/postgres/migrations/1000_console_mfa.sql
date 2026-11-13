-- Console multi-factor authentication (TOTP).
--
-- Every statement here creates a new, empty table or adds a column with a
-- constant default (a catalog-only change since PostgreSQL 11), so the
-- migration is instant on databases of any size.

-- One TOTP enrolment per console user. secret_enc is the shared secret
-- sealed with AES-256-GCM under a key HKDF-derived from the deployment root
-- secret, with the username as additional data; it is never stored or
-- returned in the clear. enabled is false while the enrolment awaits its
-- confirming code. last_step is the last accepted RFC 6238 time step: a code
-- for that step or an earlier one is refused (replay protection).
CREATE TABLE IF NOT EXISTS console_mfa (
	username TEXT PRIMARY KEY REFERENCES ui_users(username) ON DELETE CASCADE,
	secret_enc BYTEA NOT NULL,
	enabled BOOLEAN NOT NULL DEFAULT FALSE,
	last_step BIGINT NOT NULL DEFAULT 0,
	created_at TIMESTAMPTZ NOT NULL,
	enabled_at TIMESTAMPTZ
);

-- Single-use recovery codes, stored as PBKDF2-HMAC-SHA256 hashes. A code is
-- spent by setting used_at in one conditional UPDATE, so exactly one
-- concurrent use succeeds.
CREATE TABLE IF NOT EXISTS console_mfa_recovery_codes (
	username TEXT NOT NULL REFERENCES console_mfa(username) ON DELETE CASCADE,
	code_hash TEXT NOT NULL,
	used_at TIMESTAMPTZ,
	PRIMARY KEY (username, code_hash)
);

-- Spent pending-login (second factor) token IDs, so a token completes at
-- most one sign-in across every replica. Rows are dropped once the token
-- has expired.
CREATE TABLE IF NOT EXISTS console_mfa_login_tokens (
	id TEXT PRIMARY KEY,
	expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS console_mfa_login_tokens_expires_idx ON console_mfa_login_tokens (expires_at);

-- Organization policy: require MFA for password sign-in.
ALTER TABLE org_settings ADD COLUMN IF NOT EXISTS require_mfa BOOLEAN NOT NULL DEFAULT FALSE;
