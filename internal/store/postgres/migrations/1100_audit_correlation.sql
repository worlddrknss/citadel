-- Write-ahead audit (2.1): a state-changing request first appends an
-- "attempt" event (result pending), then its outcome, both carrying the same
-- correlation ID. Adding a column with a constant default is a catalog-only
-- change (no table rewrite); existing rows read back as ''.
ALTER TABLE kms_audit_events
	ADD COLUMN IF NOT EXISTS correlation_id TEXT NOT NULL DEFAULT '';

-- Partial index for "show the attempt and its outcome". Every existing row
-- has '' and is left out, so the build only scans the table once and the
-- index stays small.
CREATE INDEX IF NOT EXISTS kms_audit_events_correlation_idx
	ON kms_audit_events (account_id, correlation_id) WHERE correlation_id <> '';
