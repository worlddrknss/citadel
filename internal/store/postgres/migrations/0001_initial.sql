-- 0001_initial: the Citadel schema as it stood when versioned migrations were
-- introduced. It is the DDL that used to run on every startup, verbatim, and is
-- idempotent: on a database created before migrations existed it is re-run once
-- (bringing older layouts up to date exactly as the startup DDL did) and then
-- recorded in schema_migrations.

-- Migrate legacy tenant objects to the account naming (idempotent).
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'ui_tenants')
     AND NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'ui_accounts') THEN
    ALTER TABLE ui_tenants RENAME TO ui_accounts;
  END IF;
END $$;

DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'ui_accounts' AND column_name = 'tenant')
     AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'ui_accounts' AND column_name = 'account') THEN
    ALTER TABLE ui_accounts RENAME COLUMN tenant TO account;
  END IF;
END $$;

DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'ui_users' AND column_name = 'tenants_json')
     AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'ui_users' AND column_name = 'accounts_json') THEN
    ALTER TABLE ui_users RENAME COLUMN tenants_json TO accounts_json;
  END IF;
END $$;

DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'pca_certificate_authorities' AND column_name = 'tenant')
     AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'pca_certificate_authorities' AND column_name = 'account') THEN
    ALTER TABLE pca_certificate_authorities RENAME COLUMN tenant TO account;
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS kms_keys (
  id TEXT PRIMARY KEY,
  arn TEXT NOT NULL UNIQUE,
  master_key_b64 TEXT NOT NULL,
	wrapped_key_b64 TEXT NOT NULL DEFAULT '',
	key_nonce_b64 TEXT NOT NULL DEFAULT '',
	public_key_b64 TEXT NOT NULL DEFAULT '',
	key_usage TEXT NOT NULL DEFAULT 'ENCRYPT_DECRYPT',
	key_spec TEXT NOT NULL DEFAULT 'SYMMETRIC_DEFAULT',
  description TEXT NOT NULL DEFAULT '',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
	deletion_date TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS kms_aliases (
	alias_name TEXT PRIMARY KEY,
	target_key_id TEXT NOT NULL REFERENCES kms_keys(id),
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS kms_settings (
  setting_key TEXT PRIMARY KEY,
  setting_value TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS kms_key_policies (
	key_id TEXT NOT NULL REFERENCES kms_keys(id),
	policy_name TEXT NOT NULL,
	policy_document TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (key_id, policy_name)
);

CREATE TABLE IF NOT EXISTS kms_grants (
	grant_id TEXT PRIMARY KEY,
	grant_token TEXT NOT NULL UNIQUE,
	key_id TEXT NOT NULL REFERENCES kms_keys(id),
	grantee_principal TEXT NOT NULL,
	retiring_principal TEXT NOT NULL DEFAULT '',
	operations_json TEXT NOT NULL,
	grant_name TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS kms_audit_events (
	id BIGSERIAL PRIMARY KEY,
	action TEXT NOT NULL,
	key_id TEXT,
	result TEXT NOT NULL,
	error_type TEXT,
	actor TEXT,
	prev_hash TEXT,
	event_hash TEXT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sm_secrets (
	name TEXT PRIMARY KEY,
	arn TEXT NOT NULL UNIQUE,
	description TEXT NOT NULL DEFAULT '',
	kms_key_id TEXT NOT NULL REFERENCES kms_keys(id),
	current_version_id TEXT NOT NULL,
	previous_version_id TEXT NOT NULL DEFAULT '',
	deleted_date TIMESTAMPTZ,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sm_secret_versions (
	secret_name TEXT NOT NULL REFERENCES sm_secrets(name) ON DELETE CASCADE,
	version_id TEXT NOT NULL,
	client_request_token TEXT NOT NULL,
	encrypted_payload_b64 TEXT NOT NULL,
	is_binary BOOLEAN NOT NULL DEFAULT FALSE,
	version_created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (secret_name, version_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS sm_secret_versions_secret_token_idx
	ON sm_secret_versions (secret_name, client_request_token);

CREATE TABLE IF NOT EXISTS sm_secret_tags (
	secret_name TEXT NOT NULL REFERENCES sm_secrets(name) ON DELETE CASCADE,
	tag_key TEXT NOT NULL,
	tag_value TEXT NOT NULL,
	PRIMARY KEY (secret_name, tag_key)
);

CREATE TABLE IF NOT EXISTS sm_secret_policies (
	secret_name TEXT PRIMARY KEY REFERENCES sm_secrets(name) ON DELETE CASCADE,
	policy_document TEXT NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sm_secret_version_stages (
	secret_name TEXT NOT NULL REFERENCES sm_secrets(name) ON DELETE CASCADE,
	version_id TEXT NOT NULL,
	stage_label TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (secret_name, stage_label)
);

CREATE TABLE IF NOT EXISTS sm_projects (
	account_id CHAR(12) NOT NULL DEFAULT '000000000000',
	slug TEXT NOT NULL,
	name TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (account_id, slug)
);

CREATE TABLE IF NOT EXISTS sm_environments (
	account_id CHAR(12) NOT NULL DEFAULT '000000000000',
	project_slug TEXT NOT NULL,
	slug TEXT NOT NULL,
	name TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (account_id, project_slug, slug)
);

CREATE TABLE IF NOT EXISTS sm_folders (
	account_id CHAR(12) NOT NULL DEFAULT '000000000000',
	project_slug TEXT NOT NULL,
	env_slug TEXT NOT NULL,
	folder_path TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (account_id, project_slug, env_slug, folder_path)
);

CREATE TABLE IF NOT EXISTS ps_parameters (
	account_id CHAR(12) NOT NULL DEFAULT '000000000000',
	name TEXT NOT NULL,
	param_type TEXT NOT NULL DEFAULT 'String',
	param_value TEXT NOT NULL DEFAULT '',
	is_encrypted BOOLEAN NOT NULL DEFAULT FALSE,
	kms_key_id TEXT NOT NULL DEFAULT '',
	tier TEXT NOT NULL DEFAULT 'Standard',
	version BIGINT NOT NULL DEFAULT 1,
	description TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (account_id, name)
);

CREATE TABLE IF NOT EXISTS ps_parameter_history (
	account_id CHAR(12) NOT NULL DEFAULT '000000000000',
	name TEXT NOT NULL,
	version BIGINT NOT NULL,
	param_type TEXT NOT NULL DEFAULT 'String',
	param_value TEXT NOT NULL DEFAULT '',
	is_encrypted BOOLEAN NOT NULL DEFAULT FALSE,
	kms_key_id TEXT NOT NULL DEFAULT '',
	tier TEXT NOT NULL DEFAULT 'Standard',
	description TEXT NOT NULL DEFAULT '',
	labels_json TEXT NOT NULL DEFAULT '[]',
	modified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (account_id, name, version)
);

CREATE TABLE IF NOT EXISTS ps_parameter_tags (
	account_id CHAR(12) NOT NULL DEFAULT '000000000000',
	name TEXT NOT NULL,
	tag_key TEXT NOT NULL,
	tag_value TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (account_id, name, tag_key)
);

CREATE TABLE IF NOT EXISTS ui_users (
	username TEXT PRIMARY KEY,
	password_hash TEXT NOT NULL,
	role TEXT NOT NULL DEFAULT 'viewer',
	display_name TEXT NOT NULL DEFAULT '',
	accounts_json TEXT NOT NULL DEFAULT '[]',
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ui_accounts (
	account_id CHAR(12) PRIMARY KEY,
	account TEXT NOT NULL UNIQUE,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Migrate existing ui_accounts: rename old 'account' PK to a regular column and add account_id PK
DO $$
DECLARE
	pk_constraint TEXT;
BEGIN
	-- Ensure account_id column exists; if not, we're on old schema
	IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='ui_accounts' AND column_name='account_id')
	THEN
		-- Drop existing primary key constraint if present.
		BEGIN
			SELECT constraint_name INTO pk_constraint
			FROM information_schema.table_constraints
			WHERE table_name='ui_accounts' AND constraint_type='PRIMARY KEY'
			LIMIT 1;
			IF pk_constraint IS NOT NULL THEN
				EXECUTE 'ALTER TABLE ui_accounts DROP CONSTRAINT ' || quote_ident(pk_constraint);
			END IF;
		EXCEPTION WHEN UNDEFINED_OBJECT THEN
			NULL;
		END;
		-- Add new account_id column
		ALTER TABLE ui_accounts ADD COLUMN account_id CHAR(12);
		-- Backfill with deterministic numeric IDs based on account name
		UPDATE ui_accounts SET account_id = SUBSTR('1' || SUBSTR(TRANSLATE(MD5(account), 'abcdef', '012345'), 1, 11), 1, 12)
			WHERE account_id IS NULL;
		-- Add NOT NULL constraint
		ALTER TABLE ui_accounts ALTER COLUMN account_id SET NOT NULL;
		-- Set as new primary key
		ALTER TABLE ui_accounts ADD PRIMARY KEY (account_id);
		-- Ensure account column still has unique constraint
		ALTER TABLE ui_accounts ADD UNIQUE (account);
	END IF;
END $$;

-- Junction table: users can belong to multiple accounts
CREATE TABLE IF NOT EXISTS user_accounts (
	username TEXT NOT NULL,
	account_id CHAR(12) NOT NULL,
	role TEXT NOT NULL DEFAULT 'Viewer',
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (username, account_id),
	FOREIGN KEY (username) REFERENCES ui_users(username) ON DELETE CASCADE,
	FOREIGN KEY (account_id) REFERENCES ui_accounts(account_id) ON DELETE CASCADE
);

-- Migrate existing accounts_json from ui_users to user_accounts (one-time)
DO $$
DECLARE
	user_rec RECORD;
	account_name TEXT;
	account_id_val CHAR(12);
BEGIN
	-- Only run if user_accounts is empty
	IF NOT EXISTS (SELECT 1 FROM user_accounts LIMIT 1) THEN
		FOR user_rec IN SELECT username, accounts_json FROM ui_users LOOP
			-- Parse the JSON array and insert one row per account
			IF user_rec.accounts_json IS NOT NULL AND user_rec.accounts_json != '[]' THEN
				BEGIN
					-- This is a simple approach; won't handle complex JSON escaping
					-- but works for account names as stored by the app
					PERFORM COUNT(*) FROM (
						SELECT (json_array_elements(user_rec.accounts_json::json) ->> 0)::TEXT as acct
					) AS tmp;
				EXCEPTION WHEN OTHERS THEN
					-- If JSON parsing fails, skip this user
					RAISE NOTICE 'Failed to parse accounts_json for user %: %', user_rec.username, SQLERRM;
					CONTINUE;
				END;
			END IF;
		END LOOP;
		-- Simpler approach: for each ui_user with non-empty accounts_json, assign to first 
		-- account from the list that exists in ui_accounts, with 'Owner' role
		FOR user_rec IN 
			SELECT u.username, u.accounts_json 
			FROM ui_users u 
			WHERE u.accounts_json IS NOT NULL AND u.accounts_json != '[]'
		LOOP
			-- Find the first account in the JSON that exists in ui_accounts
			DECLARE
				acct_name TEXT;
				found_id CHAR(12);
			BEGIN
				-- Try to get first account (naive approach)
				acct_name := TRIM(BOTH '"' FROM SPLIT_PART(
					SUBSTR(user_rec.accounts_json, 2, LENGTH(user_rec.accounts_json)-2), ',', 1
				));
				
				-- Look up that account's ID
				SELECT account_id INTO found_id FROM ui_accounts 
				WHERE LOWER(account) = LOWER(acct_name) LIMIT 1;
				
				IF found_id IS NOT NULL THEN
					INSERT INTO user_accounts (username, account_id, role) 
					VALUES (user_rec.username, found_id, 'Owner')
					ON CONFLICT DO NOTHING;
				END IF;
			EXCEPTION WHEN OTHERS THEN
				RAISE NOTICE 'Failed to migrate user %: %', user_rec.username, SQLERRM;
			END;
		END LOOP;
	END IF;
END $$;

-- IAM access keys: programmatic credentials for users per account
CREATE TABLE IF NOT EXISTS iam_access_keys (
	access_key_id TEXT PRIMARY KEY,
	username TEXT NOT NULL,
	account_id CHAR(12) NOT NULL,
	secret_wrapped_b64 TEXT NOT NULL,
	secret_nonce_b64 TEXT NOT NULL,
	status TEXT NOT NULL DEFAULT 'Active',
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	last_used_at TIMESTAMPTZ,
	FOREIGN KEY (username, account_id) REFERENCES user_accounts(username, account_id) ON DELETE CASCADE,
	UNIQUE (access_key_id)
);

-- IAM OIDC identity providers: external token issuers whose JWTs may be
-- exchanged for temporary Citadel credentials via STS AssumeRoleWithWebIdentity.
CREATE TABLE IF NOT EXISTS iam_oidc_providers (
	provider_arn TEXT PRIMARY KEY,
	account_id CHAR(12) NOT NULL,
	url TEXT NOT NULL,
	client_ids_json TEXT NOT NULL DEFAULT '[]',
	thumbprints_json TEXT NOT NULL DEFAULT '[]',
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	UNIQUE (account_id, url)
);

-- IAM roles: named identities with a trust policy describing who may assume
-- them (an OIDC provider's subjects, or principal account IDs).
CREATE TABLE IF NOT EXISTS iam_roles (
	role_arn TEXT PRIMARY KEY,
	account_id CHAR(12) NOT NULL,
	role_name TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	trust_policy TEXT NOT NULL DEFAULT '{}',
	max_session_seconds INTEGER NOT NULL DEFAULT 3600,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	UNIQUE (account_id, role_name)
);

-- STS sessions: short-lived ASIA-prefixed temporary credentials minted by
-- AssumeRole / AssumeRoleWithWebIdentity. The secret is wrapped exactly like a
-- long-lived access key so the same SigV4 path verifies it.
CREATE TABLE IF NOT EXISTS sts_sessions (
	access_key_id TEXT PRIMARY KEY,
	account_id CHAR(12) NOT NULL,
	role_arn TEXT NOT NULL,
	role_session_name TEXT NOT NULL DEFAULT '',
	subject TEXT NOT NULL DEFAULT '',
	secret_wrapped_b64 TEXT NOT NULL,
	secret_nonce_b64 TEXT NOT NULL,
	session_token TEXT NOT NULL,
	expires_at TIMESTAMPTZ NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS sts_sessions_expires_idx ON sts_sessions (expires_at);


ALTER TABLE sm_secrets ADD COLUMN IF NOT EXISTS rotation_lambda_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE sm_secrets ADD COLUMN IF NOT EXISTS rotation_days INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sm_secrets ADD COLUMN IF NOT EXISTS next_rotation_date TIMESTAMPTZ;

ALTER TABLE kms_audit_events ADD COLUMN IF NOT EXISTS prev_hash TEXT;
ALTER TABLE kms_audit_events ADD COLUMN IF NOT EXISTS event_hash TEXT;
ALTER TABLE kms_keys ADD COLUMN IF NOT EXISTS deletion_date TIMESTAMPTZ;
ALTER TABLE kms_keys ADD COLUMN IF NOT EXISTS wrapped_key_b64 TEXT NOT NULL DEFAULT '';
ALTER TABLE kms_keys ADD COLUMN IF NOT EXISTS key_nonce_b64 TEXT NOT NULL DEFAULT '';
ALTER TABLE kms_keys ADD COLUMN IF NOT EXISTS public_key_b64 TEXT NOT NULL DEFAULT '';
ALTER TABLE kms_keys ADD COLUMN IF NOT EXISTS key_usage TEXT NOT NULL DEFAULT 'ENCRYPT_DECRYPT';
ALTER TABLE kms_keys ADD COLUMN IF NOT EXISTS key_spec TEXT NOT NULL DEFAULT 'SYMMETRIC_DEFAULT';
-- managed marks an immutable, system-provisioned default key (alias/default).
ALTER TABLE kms_keys ADD COLUMN IF NOT EXISTS managed BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS pca_certificate_authorities (
	ca_id TEXT PRIMARY KEY,
	urn TEXT NOT NULL UNIQUE,
	type TEXT NOT NULL DEFAULT 'ROOT',
	kms_key_id TEXT NOT NULL REFERENCES kms_keys(id),
	subject_dn TEXT NOT NULL,
	state TEXT NOT NULL DEFAULT 'CREATING',
	ca_cert_b64 TEXT NOT NULL DEFAULT '',
	path_length INTEGER,
	not_before TIMESTAMPTZ NOT NULL,
	not_after TIMESTAMPTZ NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	account TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS pca_certificates (
	cert_id TEXT PRIMARY KEY,
	ca_id TEXT NOT NULL REFERENCES pca_certificate_authorities(ca_id) ON DELETE CASCADE,
	serial TEXT NOT NULL,
	csr_b64 TEXT NOT NULL DEFAULT '',
	cert_b64 TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT 'ISSUED',
	not_before TIMESTAMPTZ NOT NULL,
	not_after TIMESTAMPTZ NOT NULL,
	revoked_at TIMESTAMPTZ,
	revocation_reason TEXT,
	template TEXT NOT NULL DEFAULT 'EndEntityCertificate',
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS pca_certificates_ca_serial_idx
	ON pca_certificates (ca_id, serial);

CREATE TABLE IF NOT EXISTS pca_ca_policies (
	ca_id TEXT NOT NULL REFERENCES pca_certificate_authorities(ca_id) ON DELETE CASCADE,
	policy_name TEXT NOT NULL,
	policy_document TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (ca_id, policy_name)
);

CREATE TABLE IF NOT EXISTS pca_crl_state (
	ca_id TEXT PRIMARY KEY REFERENCES pca_certificate_authorities(ca_id) ON DELETE CASCADE,
	crl_number BIGINT NOT NULL DEFAULT 1,
	last_generated TIMESTAMPTZ,
	next_update TIMESTAMPTZ,
	crl_b64 TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS acme_le_accounts (
	id TEXT PRIMARY KEY,
	directory_url TEXT NOT NULL UNIQUE,
	account_uri TEXT NOT NULL DEFAULT '',
	contact_email TEXT NOT NULL DEFAULT '',
	account_key_wrapped_b64 TEXT NOT NULL DEFAULT '',
	account_key_nonce_b64 TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS acme_le_certificates (
	cert_id TEXT PRIMARY KEY,
	directory_url TEXT NOT NULL DEFAULT '',
	domains TEXT NOT NULL DEFAULT '',
	serial TEXT NOT NULL DEFAULT '',
	cert_b64 TEXT NOT NULL DEFAULT '',
	chain_b64 TEXT NOT NULL DEFAULT '',
	key_wrapped_b64 TEXT NOT NULL DEFAULT '',
	key_nonce_b64 TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT 'ISSUED',
	not_before TIMESTAMPTZ NOT NULL,
	not_after TIMESTAMPTZ NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Pending manual DNS-01 orders. Persists the in-flight ACME order URL between
-- the "begin" call (which returns the TXT records to publish) and the
-- "complete" call (which validates and finalizes once the operator has added
-- them). Scoped per account; rows are short-lived and removed on completion.
CREATE TABLE IF NOT EXISTS acme_le_orders (
	order_id TEXT PRIMARY KEY,
	order_url TEXT NOT NULL,
	directory_url TEXT NOT NULL DEFAULT '',
	domains TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT 'pending',
	account_id CHAR(12),
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '7 days'
);

-- Per-account isolation: tag every resource with the owning account's 12-digit
-- ID. Columns are added nullable (no FK) so existing inserts keep working; the
-- backfill assigns legacy rows to the deployment's global/root account. Query
-- scoping is applied at the store layer only when an authenticated caller
-- account is present (DB-backed strict SigV4), so behavior is unchanged until
-- that path is enabled.
ALTER TABLE kms_keys ADD COLUMN IF NOT EXISTS account_id CHAR(12);
ALTER TABLE kms_aliases ADD COLUMN IF NOT EXISTS account_id CHAR(12);
ALTER TABLE sm_secrets ADD COLUMN IF NOT EXISTS account_id CHAR(12);
ALTER TABLE pca_certificate_authorities ADD COLUMN IF NOT EXISTS account_id CHAR(12);
ALTER TABLE pca_certificates ADD COLUMN IF NOT EXISTS account_id CHAR(12);
ALTER TABLE acme_le_certificates ADD COLUMN IF NOT EXISTS account_id CHAR(12);

DO $$
DECLARE
	root_acct CHAR(12);
BEGIN
	SELECT setting_value INTO root_acct FROM kms_settings WHERE setting_key = 'aws_account_id' LIMIT 1;
	IF root_acct IS NULL OR LENGTH(TRIM(root_acct)) <> 12 THEN
		root_acct := '000000000000';
	END IF;
	UPDATE kms_keys SET account_id = root_acct WHERE account_id IS NULL;
	UPDATE kms_aliases SET account_id = root_acct WHERE account_id IS NULL;
	UPDATE sm_secrets SET account_id = root_acct WHERE account_id IS NULL;
	UPDATE pca_certificate_authorities SET account_id = root_acct WHERE account_id IS NULL;
	UPDATE pca_certificates SET account_id = root_acct WHERE account_id IS NULL;
	UPDATE acme_le_certificates SET account_id = root_acct WHERE account_id IS NULL;
END $$;

-- Aliases are scoped per account: the same alias name (e.g. alias/default) may
-- exist once per account. Promote the kms_aliases primary key from a global
-- alias_name to the composite (account_id, alias_name). Runs after the backfill
-- above so account_id is fully populated and can be made NOT NULL.
DO $$
BEGIN
	IF EXISTS (
		SELECT 1 FROM information_schema.table_constraints
		WHERE table_name = 'kms_aliases' AND constraint_type = 'PRIMARY KEY' AND constraint_name = 'kms_aliases_pkey'
	) AND NOT EXISTS (
		SELECT 1 FROM information_schema.key_column_usage
		WHERE table_name = 'kms_aliases' AND constraint_name = 'kms_aliases_pkey' AND column_name = 'account_id'
	) THEN
		ALTER TABLE kms_aliases DROP CONSTRAINT kms_aliases_pkey;
		ALTER TABLE kms_aliases ALTER COLUMN account_id SET NOT NULL;
		ALTER TABLE kms_aliases ADD PRIMARY KEY (account_id, alias_name);
	END IF;
END $$;
