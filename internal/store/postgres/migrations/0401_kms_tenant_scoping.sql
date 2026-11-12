-- Account scoping for KMS grants, key policies and tags. Grants and policies
-- predate per-account isolation; they inherit the owning key's account.
ALTER TABLE kms_grants ADD COLUMN IF NOT EXISTS account_id CHAR(12);
ALTER TABLE kms_key_policies ADD COLUMN IF NOT EXISTS account_id CHAR(12);

UPDATE kms_grants g SET account_id = k.account_id
FROM kms_keys k WHERE g.key_id = k.id AND g.account_id IS NULL;
UPDATE kms_key_policies p SET account_id = k.account_id
FROM kms_keys k WHERE p.key_id = k.id AND p.account_id IS NULL;

CREATE INDEX IF NOT EXISTS kms_grants_account_key_idx ON kms_grants (account_id, key_id);

CREATE TABLE IF NOT EXISTS kms_key_tags (
	key_id TEXT NOT NULL REFERENCES kms_keys(id),
	account_id CHAR(12) NOT NULL,
	tag_key TEXT NOT NULL,
	tag_value TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (key_id, tag_key)
);
CREATE INDEX IF NOT EXISTS kms_key_tags_account_idx ON kms_key_tags (account_id, key_id);
