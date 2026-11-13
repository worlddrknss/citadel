-- Workload identity client names are unique per account, ignoring case, so a
-- name identifies one client in the console and the audit log.
--
-- Existing duplicates (possible before 2.0.3) keep the oldest client's name;
-- the others get "-" and the last 8 characters of their client ID appended
-- (the name is cut to 55 characters first so it stays within the 64-character
-- limit). Client IDs, which workloads use, don't change.
WITH ranked AS (
	SELECT client_id,
		ROW_NUMBER() OVER (PARTITION BY account_id, lower(name) ORDER BY created_at, client_id) AS n
	FROM workload_clients
)
UPDATE workload_clients w
SET name = left(w.name, 55) || '-' || right(w.client_id, 8)
FROM ranked r
WHERE w.client_id = r.client_id AND r.n > 1;

CREATE UNIQUE INDEX IF NOT EXISTS workload_clients_account_name_uniq
	ON workload_clients (account_id, lower(name));
