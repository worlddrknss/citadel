-- Let's Encrypt issuance runs in the background: every order (HTTP-01 and
-- DNS-01) gets a row the console polls for progress. Existing rows are
-- DNS-01 orders waiting for their TXT records, which the defaults describe.
ALTER TABLE acme_le_orders
	ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'dns-01',
	ADD COLUMN IF NOT EXISTS progress TEXT NOT NULL DEFAULT '',
	ADD COLUMN IF NOT EXISTS error TEXT NOT NULL DEFAULT '',
	ADD COLUMN IF NOT EXISTS cert_id TEXT NOT NULL DEFAULT '',
	ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
