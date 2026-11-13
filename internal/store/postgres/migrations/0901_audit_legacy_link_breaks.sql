-- Chain verification tolerates broken prev_hash links between pre-2.0
-- (hash_version 1) events, which Citadel 1.x wrote without locking the chain
-- head, and reports them instead of stopping. Incremental runs carry these
-- counts forward, so they are stored with the rest of the result.
ALTER TABLE audit_chain_verifications
	ADD COLUMN IF NOT EXISTS legacy_events BIGINT NOT NULL DEFAULT 0,
	ADD COLUMN IF NOT EXISTS legacy_link_breaks BIGINT NOT NULL DEFAULT 0,
	ADD COLUMN IF NOT EXISTS first_legacy_break_seq BIGINT NOT NULL DEFAULT 0,
	ADD COLUMN IF NOT EXISTS first_legacy_break_event_id BIGINT NOT NULL DEFAULT 0;

-- Results stored before this change don't have the legacy counts, so the
-- next verification starts from the beginning instead of the old checkpoint.
-- (Broken results already re-walk the whole chain.)
UPDATE audit_chain_verifications SET verified_seq = 0, verified_event_id = 0, verified_hash = '';
