-- The generated first-run bootstrap token (when KMS_BOOTSTRAP_TOKEN is not
-- set), shared by every replica. Only its SHA-256 is stored; the replica that
-- generated it logs the token once. A single row: one token at a time.
CREATE TABLE IF NOT EXISTS bootstrap_tokens (
	id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
	token_hash TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	consumed_at TIMESTAMPTZ
);
