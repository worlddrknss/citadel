-- Versioned KMS key material and automatic rotation.
--
-- kms_keys.wrapped_key_b64 keeps holding a key's original material (the
-- version every pre-rotation ciphertext was sealed with). Each rotation adds a
-- row here, wrapped with the wrapping key under AAD "<key_id>#<material_id>",
-- and points kms_keys.current_material_id at it ('' = the original). The rows
-- double as the rotation history.
CREATE TABLE IF NOT EXISTS kms_key_materials (
	key_id TEXT NOT NULL REFERENCES kms_keys(id),
	material_id TEXT NOT NULL,
	account_id CHAR(12) NOT NULL,
	wrapped_b64 TEXT NOT NULL,
	nonce_b64 TEXT NOT NULL,
	kind TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (key_id, material_id)
);
CREATE INDEX IF NOT EXISTS kms_key_materials_account_idx ON kms_key_materials (account_id, key_id);

ALTER TABLE kms_keys ADD COLUMN IF NOT EXISTS current_material_id TEXT NOT NULL DEFAULT '';
ALTER TABLE kms_keys ADD COLUMN IF NOT EXISTS rotation_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE kms_keys ADD COLUMN IF NOT EXISTS rotation_period_days INTEGER NOT NULL DEFAULT 365;
ALTER TABLE kms_keys ADD COLUMN IF NOT EXISTS next_rotation_at TIMESTAMPTZ;
-- Set when scheduled deletion destroys the key: the row stays as a tombstone
-- (so the key ID is never reused and foreign keys stay valid) with its
-- material wiped.
ALTER TABLE kms_keys ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE kms_keys ADD COLUMN IF NOT EXISTS origin TEXT NOT NULL DEFAULT 'AWS_KMS';

CREATE INDEX IF NOT EXISTS kms_keys_next_rotation_idx ON kms_keys (next_rotation_at) WHERE rotation_enabled AND deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS kms_keys_deletion_date_idx ON kms_keys (deletion_date) WHERE deletion_date IS NOT NULL AND deleted_at IS NULL;
