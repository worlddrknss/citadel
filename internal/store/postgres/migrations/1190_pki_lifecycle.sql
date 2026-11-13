-- CA deletion with a restore window (AWS ACM PCA semantics), removing
-- private CA certificates from the console inventory, and Let's Encrypt
-- automatic renewal state. Nullable columns and constant defaults are
-- metadata-only changes (no table rewrite); the backfill touches only the
-- small Let's Encrypt tables.
ALTER TABLE pca_certificate_authorities ADD COLUMN IF NOT EXISTS restorable_until TIMESTAMPTZ;
ALTER TABLE pca_certificates ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

ALTER TABLE acme_le_certificates
	ADD COLUMN IF NOT EXISTS challenge_kind TEXT NOT NULL DEFAULT '',
	ADD COLUMN IF NOT EXISTS auto_renew BOOLEAN NOT NULL DEFAULT FALSE,
	ADD COLUMN IF NOT EXISTS renew_attempts INTEGER NOT NULL DEFAULT 0,
	ADD COLUMN IF NOT EXISTS renew_next_attempt_at TIMESTAMPTZ,
	ADD COLUMN IF NOT EXISTS renew_last_attempt_at TIMESTAMPTZ,
	ADD COLUMN IF NOT EXISTS renew_last_error TEXT NOT NULL DEFAULT '',
	ADD COLUMN IF NOT EXISTS renewed_by TEXT NOT NULL DEFAULT '';

-- Certificates issued since 2.0.3 have an order row naming their challenge.
-- Earlier ones stay unknown ('') with auto-renew off until an operator turns
-- it on; wildcard names can only have been DNS-01.
UPDATE acme_le_certificates c
SET challenge_kind = o.kind, auto_renew = (o.kind = 'http-01')
FROM acme_le_orders o
WHERE o.cert_id = c.cert_id AND o.cert_id <> '' AND c.challenge_kind = '';

UPDATE acme_le_certificates SET challenge_kind = 'dns-01'
WHERE challenge_kind = '' AND domains LIKE '%*%';

CREATE INDEX IF NOT EXISTS acme_le_certificates_renewal_idx
	ON acme_le_certificates (not_after) WHERE auto_renew AND renewed_by = '';
