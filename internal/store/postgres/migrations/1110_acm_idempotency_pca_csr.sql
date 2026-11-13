-- ACM IdempotencyToken claims and the CSRs of subordinate CAs created through
-- the ACM PCA API. Both are new, empty tables: no rewrite of existing data.
CREATE TABLE IF NOT EXISTS acm_idempotency_tokens (
	account_id TEXT NOT NULL,
	operation TEXT NOT NULL,
	token TEXT NOT NULL,
	params_hash TEXT NOT NULL,
	arn TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (account_id, operation, token)
);

CREATE INDEX IF NOT EXISTS acm_idempotency_tokens_created_at ON acm_idempotency_tokens (created_at);

CREATE TABLE IF NOT EXISTS pca_ca_csrs (
	ca_id TEXT PRIMARY KEY REFERENCES pca_certificate_authorities(ca_id) ON DELETE CASCADE,
	account_id TEXT NOT NULL DEFAULT '',
	csr_b64 TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
