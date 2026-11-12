-- PKI: subordinate CA lineage, serial lookups, ACM-managed certificates, and
-- the state of Citadel's own RFC 8555 ACME server (per-account settings,
-- external account binding keys, and the ACME protocol objects).

ALTER TABLE pca_certificate_authorities ADD COLUMN IF NOT EXISTS parent_ca_id TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS pca_certificate_authorities_account_idx ON pca_certificate_authorities (account_id);
CREATE INDEX IF NOT EXISTS pca_certificates_serial_idx ON pca_certificates (serial);
CREATE INDEX IF NOT EXISTS pca_certificates_account_idx ON pca_certificates (account_id);
CREATE INDEX IF NOT EXISTS pca_certificates_status_not_after_idx ON pca_certificates (status, not_after);

-- Certificates managed through the ACM API. Private keys are wrapped with the
-- store wrapping key (AES-256-GCM, cert ARN as AAD).
CREATE TABLE IF NOT EXISTS acm_certificates (
	cert_arn TEXT PRIMARY KEY,
	account_id CHAR(12) NOT NULL,
	cert_type TEXT NOT NULL,
	ca_id TEXT NOT NULL DEFAULT '',
	pca_cert_id TEXT NOT NULL DEFAULT '',
	domain_name TEXT NOT NULL DEFAULT '',
	sans TEXT NOT NULL DEFAULT '[]',
	serial TEXT NOT NULL DEFAULT '',
	cert_b64 TEXT NOT NULL DEFAULT '',
	chain_pem TEXT NOT NULL DEFAULT '',
	key_wrapped_b64 TEXT NOT NULL DEFAULT '',
	key_nonce_b64 TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT 'ISSUED',
	not_before TIMESTAMPTZ NOT NULL,
	not_after TIMESTAMPTZ NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS acm_certificates_account_idx ON acm_certificates (account_id, created_at);

-- Per-account ACME server configuration.
CREATE TABLE IF NOT EXISTS pki_acme_settings (
	account_id CHAR(12) PRIMARY KEY,
	issuing_ca_id TEXT NOT NULL DEFAULT '',
	allowed_domains TEXT NOT NULL DEFAULT '[]',
	allowed_ip_ranges TEXT NOT NULL DEFAULT '[]',
	validation_allowed_cidrs TEXT NOT NULL DEFAULT '[]',
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_by TEXT NOT NULL DEFAULT ''
);

-- External account binding keys. The HMAC key is wrapped (AES-256-GCM, kid
-- as AAD); status moves unused -> bound exactly once, or to revoked.
CREATE TABLE IF NOT EXISTS pki_acme_eab_keys (
	kid TEXT PRIMARY KEY,
	account_id CHAR(12) NOT NULL,
	label TEXT NOT NULL DEFAULT '',
	hmac_wrapped_b64 TEXT NOT NULL,
	hmac_nonce_b64 TEXT NOT NULL,
	status TEXT NOT NULL DEFAULT 'unused',
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	created_by TEXT NOT NULL DEFAULT '',
	bound_at TIMESTAMPTZ,
	acme_account_id TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS pki_acme_eab_keys_account_idx ON pki_acme_eab_keys (account_id, created_at);

-- ACME protocol state (internal/acme.Store). Objects are stored as JSON with
-- the columns needed for lookups; version implements optimistic concurrency.
CREATE TABLE IF NOT EXISTS acme_srv_nonces (
	nonce TEXT PRIMARY KEY,
	expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS acme_srv_nonces_expires_idx ON acme_srv_nonces (expires_at);

CREATE TABLE IF NOT EXISTS acme_srv_accounts (
	id TEXT PRIMARY KEY,
	thumbprint TEXT NOT NULL UNIQUE,
	account_ref TEXT NOT NULL DEFAULT '',
	data JSONB NOT NULL,
	version BIGINT NOT NULL DEFAULT 1,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS acme_srv_orders (
	id TEXT PRIMARY KEY,
	seq BIGSERIAL,
	account_id TEXT NOT NULL,
	status TEXT NOT NULL,
	expires_at TIMESTAMPTZ NOT NULL,
	data JSONB NOT NULL,
	version BIGINT NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS acme_srv_orders_account_idx ON acme_srv_orders (account_id, seq);

CREATE TABLE IF NOT EXISTS acme_srv_authzs (
	id TEXT PRIMARY KEY,
	account_id TEXT NOT NULL,
	ident_type TEXT NOT NULL,
	ident_value TEXT NOT NULL,
	status TEXT NOT NULL,
	expires_at TIMESTAMPTZ NOT NULL,
	data JSONB NOT NULL,
	version BIGINT NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS acme_srv_authzs_lookup_idx ON acme_srv_authzs (account_id, ident_type, ident_value, status);

CREATE TABLE IF NOT EXISTS acme_srv_certs (
	id TEXT PRIMARY KEY,
	account_id TEXT NOT NULL,
	serial TEXT NOT NULL UNIQUE,
	data JSONB NOT NULL,
	version BIGINT NOT NULL DEFAULT 1
);
