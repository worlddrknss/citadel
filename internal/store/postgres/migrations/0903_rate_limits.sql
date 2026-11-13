-- Shared rate-limit counters (fixed windows), so limits on login, bootstrap,
-- SSO and the workload token endpoint hold across replicas. One row per
-- limiter, key (a SHA-256 prefix of the IP, username or client ID) and
-- window. UNLOGGED: counters are short-lived and not worth WAL; after a crash
-- or failover they start from zero, which only relaxes limits briefly. Old
-- windows are deleted by a background job.
CREATE UNLOGGED TABLE IF NOT EXISTS rate_limit_counters (
	limiter TEXT NOT NULL,
	key_hash TEXT NOT NULL,
	window_start TIMESTAMPTZ NOT NULL,
	hits INTEGER NOT NULL,
	PRIMARY KEY (limiter, key_hash, window_start)
);
CREATE INDEX IF NOT EXISTS rate_limit_counters_window_idx ON rate_limit_counters (window_start);
