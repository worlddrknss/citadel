-- Secret reads and rotation updates use sm_secrets.rotation_enabled, but no
-- earlier schema created it, so on a fresh database every secret read failed.
-- Backfill from the rotation settings that did exist.
ALTER TABLE sm_secrets ADD COLUMN IF NOT EXISTS rotation_enabled BOOLEAN NOT NULL DEFAULT FALSE;
UPDATE sm_secrets SET rotation_enabled = TRUE
WHERE rotation_enabled = FALSE AND rotation_lambda_arn <> '' AND rotation_days > 0;
