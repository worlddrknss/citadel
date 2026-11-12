-- Approval policies, change requests and per-account secrets settings.
--
-- Change requests used to live only in process memory: lost on restart and
-- invisible to other replicas. Proposed values are stored here only as
-- ciphertext sealed under the account's default KMS key (proposed_ciphertext,
-- proposed_kms_key_id), the same envelope secret versions use.

CREATE TABLE IF NOT EXISTS sm_approval_policies (
	account_id CHAR(12) NOT NULL,
	project TEXT NOT NULL,
	env TEXT NOT NULL,
	approvals_required INTEGER NOT NULL CHECK (approvals_required > 0),
	approver_roles_json TEXT NOT NULL DEFAULT '["admin"]',
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_by TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (account_id, project, env)
);

CREATE TABLE IF NOT EXISTS sm_change_requests (
	account_id CHAR(12) NOT NULL,
	id TEXT NOT NULL,
	project TEXT NOT NULL,
	env TEXT NOT NULL,
	folder_path TEXT NOT NULL DEFAULT '/',
	item_key TEXT NOT NULL,
	requester TEXT NOT NULL,
	requester_role TEXT NOT NULL DEFAULT '',
	title TEXT NOT NULL DEFAULT '',
	comment TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT 'pending',
	proposed_ciphertext TEXT NOT NULL,
	proposed_kms_key_id TEXT NOT NULL,
	proposed_length INTEGER NOT NULL DEFAULT 0,
	target_kms_key_id TEXT NOT NULL DEFAULT '',
	base_version_id TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	decided_by TEXT NOT NULL DEFAULT '',
	decided_at TIMESTAMPTZ,
	decision_comment TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (account_id, id)
);

CREATE INDEX IF NOT EXISTS sm_change_requests_created_idx ON sm_change_requests (account_id, created_at DESC);

CREATE TABLE IF NOT EXISTS sm_change_request_approvals (
	account_id CHAR(12) NOT NULL,
	request_id TEXT NOT NULL,
	username TEXT NOT NULL,
	comment TEXT NOT NULL DEFAULT '',
	decided_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (account_id, request_id, username),
	FOREIGN KEY (account_id, request_id) REFERENCES sm_change_requests (account_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sm_account_settings (
	account_id CHAR(12) PRIMARY KEY,
	viewers_can_reveal BOOLEAN NOT NULL DEFAULT FALSE,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_by TEXT NOT NULL DEFAULT ''
);
