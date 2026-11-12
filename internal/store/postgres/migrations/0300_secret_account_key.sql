-- Secrets are keyed per account.
--
-- sm_secrets used to have name as its primary key, so a secret name could
-- exist once per deployment: account B could not create "app/prod/DB" when
-- account A already had it, and the duplicate-key error told B that the name
-- was taken (leaking A's secret names). Promote the key to (account_id, name)
-- and carry account_id into every child table so their keys and foreign keys
-- are per account too.
--
-- Every catalog lookup here goes through regclass casts, which resolve against
-- the current search_path, so the migration only ever sees the tables of the
-- schema it runs in. It is guarded so re-running it is a no-op.
DO $$
DECLARE
	root_acct CHAR(12);
	r RECORD;
	pk TEXT;
	child TEXT;
BEGIN
	IF EXISTS (
		SELECT 1 FROM pg_index i
		JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey)
		WHERE i.indrelid = 'sm_secrets'::regclass AND i.indisprimary AND a.attname = 'account_id'
	) THEN
		RETURN;
	END IF;

	SELECT setting_value INTO root_acct FROM kms_settings WHERE setting_key = 'aws_account_id' LIMIT 1;
	IF root_acct IS NULL OR LENGTH(TRIM(root_acct)) <> 12 THEN
		root_acct := '000000000000';
	END IF;
	UPDATE sm_secrets SET account_id = root_acct WHERE account_id IS NULL;
	ALTER TABLE sm_secrets ALTER COLUMN account_id SET NOT NULL;

	-- Child foreign keys point at the old single-column key; drop them first.
	FOR r IN
		SELECT conrelid::regclass::text AS tbl, conname
		FROM pg_constraint
		WHERE contype = 'f' AND confrelid = 'sm_secrets'::regclass
	LOOP
		EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', r.tbl, r.conname);
	END LOOP;

	SELECT conname INTO pk FROM pg_constraint WHERE conrelid = 'sm_secrets'::regclass AND contype = 'p';
	IF pk IS NOT NULL THEN
		EXECUTE format('ALTER TABLE sm_secrets DROP CONSTRAINT %I', pk);
	END IF;
	ALTER TABLE sm_secrets ADD PRIMARY KEY (account_id, name);

	FOREACH child IN ARRAY ARRAY['sm_secret_versions', 'sm_secret_tags', 'sm_secret_policies', 'sm_secret_version_stages'] LOOP
		EXECUTE format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS account_id CHAR(12)', child);
		EXECUTE format('UPDATE %I c SET account_id = s.account_id FROM sm_secrets s WHERE s.name = c.secret_name AND c.account_id IS NULL', child);
		-- Rows whose parent is gone (impossible while the old FK held) would
		-- block NOT NULL; they are unreachable, so drop them.
		EXECUTE format('DELETE FROM %I WHERE account_id IS NULL', child);
		EXECUTE format('ALTER TABLE %I ALTER COLUMN account_id SET NOT NULL', child);
		pk := NULL;
		SELECT conname INTO pk FROM pg_constraint WHERE conrelid = child::regclass AND contype = 'p';
		IF pk IS NOT NULL THEN
			EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', child, pk);
		END IF;
	END LOOP;

	ALTER TABLE sm_secret_versions ADD PRIMARY KEY (account_id, secret_name, version_id);
	ALTER TABLE sm_secret_tags ADD PRIMARY KEY (account_id, secret_name, tag_key);
	ALTER TABLE sm_secret_policies ADD PRIMARY KEY (account_id, secret_name);
	ALTER TABLE sm_secret_version_stages ADD PRIMARY KEY (account_id, secret_name, stage_label);

	DROP INDEX IF EXISTS sm_secret_versions_secret_token_idx;
	CREATE UNIQUE INDEX sm_secret_versions_secret_token_idx
		ON sm_secret_versions (account_id, secret_name, client_request_token);

	ALTER TABLE sm_secret_versions ADD CONSTRAINT sm_secret_versions_secret_fkey
		FOREIGN KEY (account_id, secret_name) REFERENCES sm_secrets (account_id, name) ON DELETE CASCADE ON UPDATE CASCADE;
	ALTER TABLE sm_secret_tags ADD CONSTRAINT sm_secret_tags_secret_fkey
		FOREIGN KEY (account_id, secret_name) REFERENCES sm_secrets (account_id, name) ON DELETE CASCADE ON UPDATE CASCADE;
	ALTER TABLE sm_secret_policies ADD CONSTRAINT sm_secret_policies_secret_fkey
		FOREIGN KEY (account_id, secret_name) REFERENCES sm_secrets (account_id, name) ON DELETE CASCADE ON UPDATE CASCADE;
	ALTER TABLE sm_secret_version_stages ADD CONSTRAINT sm_secret_version_stages_secret_fkey
		FOREIGN KEY (account_id, secret_name) REFERENCES sm_secrets (account_id, name) ON DELETE CASCADE ON UPDATE CASCADE;
END $$;

-- Who wrote a secret's current version, and each version (console usernames or
-- access-key IDs; empty for rows written before this migration).
ALTER TABLE sm_secrets ADD COLUMN IF NOT EXISTS updated_by TEXT NOT NULL DEFAULT '';
ALTER TABLE sm_secret_versions ADD COLUMN IF NOT EXISTS created_by TEXT NOT NULL DEFAULT '';

-- The purge job looks for secrets whose deletion date has passed.
CREATE INDEX IF NOT EXISTS sm_secrets_deleted_date_idx ON sm_secrets (deleted_date) WHERE deleted_date IS NOT NULL;
