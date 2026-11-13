# Audit log and retention

Every action in Citadel is recorded in the account's audit log: who acted
(and how they authenticated), on what, from where, and the result. This page
covers how long events are kept, how pruning works without weakening the
hash chain, and what to expect from the database's disk usage. The audit
model itself (what is recorded, write-ahead attempts, fail-closed reads) is
described in [security-model.md](security-model.md#audit).

## Hash chain and verification

Each account's events form one HMAC-SHA256 chain: every event carries its
position (`chainSeq`), the MAC of the event before it and its own MAC over
every field, keyed with `KMS_AUDIT_HMAC_KEY_B64` (see
[configuration](configuration.md#storage-and-keys)). **Audit → Verify now**
(`POST /v1/audit/verify`) walks the chain from the last verified event; a
platform admin can re-walk it from the start (**Full re-check**,
`?full=true`). Editing, re-ordering or deleting an event shows up as a break.

Events written by Citadel 1.x were appended without locking the chain, so
concurrent requests could link to the same predecessor. Verification reports
those links as a warning ("N links in pre-2.0 history don't connect"), not a
break.

## Retention

By default Citadel keeps audit events **forever**: nothing is ever deleted
unless someone sets a retention. A retention is a number of days; events
older than that are pruned.

| Where | Setting | Values |
|---|---|---|
| Deployment default | `KMS_AUDIT_RETENTION_DAYS` | `0` (keep forever, the default) or 7 to 3650 |
| Per account | **Administration → Audit** in the console, or `POST /v1/audit/retention` | the deployment default, keep forever (`0`), or 7 to 3650 days |

The per-account setting wins over the deployment default. Account admins set
it for their account and platform admins for any account they switch to.
Seven days is the floor, so a mistake can never wipe the log. Every change
is itself audited (`citadel.PutAuditRetention`, with the old and new value,
for example `audit-retention: default(forever) -> 90d`).

Before you save, the console shows the account's event count, its oldest
event, and how many events the new retention would prune right now
(`GET /v1/audit/retention/preview?days=N`). Platform admins also see the audit
table's size on disk and its estimated row count (deployment-wide).

Upgrading to 2.5 changes nothing until you set a retention.

### How pruning works

The `audit-retention` job runs at startup and then hourly.

- **One replica at a time.** A run starts by taking a deployment-wide lease
  (a row in `audit_retention_runs`); replicas that find it held skip that run.
  Each prune transaction also takes a per-account advisory lock, so even two
  overlapping runs can't prune the same account at once.
- **Oldest first, in small batches.** Each transaction deletes at most 5,000
  events, the oldest of the account's chain, and the job pauses 200 ms between
  batches. Batches find and delete their rows through the existing
  `(account_id, chain_seq)` index, run with a 5 s lock timeout and a 60 s
  statement timeout, and never touch the newest events, so appends carry on
  while pruning runs.
- **Audited.** For each account with events older than its cut-off, the job
  writes a write-ahead `citadel.PruneAuditEvents` attempt (actor
  `system:audit-retention`) before deleting anything, and an outcome with the
  number of events pruned and the new anchor. Accounts with nothing to prune
  get no events.

Pruning only ever removes a contiguous run of the oldest events, and it stops
early, keeping the rest for a later run, at the first event that:

| Held back | Why |
|---|---|
| is newer than the cut-off | the retention window is never cut into |
| is the newest event in the account | the chain head always has its event |
| doesn't verify (a gap, a broken link or a bad MAC) | pruning never destroys evidence of tampering; the outcome is an error (`AuditChainBroken`) and the server logs it. Run a full verification. |
| is a write-ahead attempt whose outcome is newer than the cut-off | an attempt and its outcome go together. Attempts with no outcome (unknown outcome) are pruned like any other event once they're old. |
| is still waiting to be delivered to the account's SIEM stream | see [Archiving before pruning](#archiving-before-pruning) |

Results of a 300,000-event log (one account, 120 days of events, pruned to
30 days on PostgreSQL 17; `TestAuditPrunePerformance`):

| | |
|---|---|
| Preview count (`created_at` index) | ~80 ms |
| Prune 225,000 events | 45 batches, 26 ms median per transaction (60 ms max), 10 s wall time with the pauses |
| Appends during the prune | 1,100, slowest 67 ms |
| Full verification before / after | 1.1 s (300,000 events) / 0.34 s (76,000 events) |

### Chain anchors

Deleting the oldest events would normally look exactly like tampering: the
first remaining event links to a MAC that no longer exists. So before a batch
is deleted, in the same transaction, Citadel records the account's **anchor**:
the position, ID and MAC of the last pruned event, its timestamp (everything
older is gone), and the running count of pruned events. The anchor carries
its own HMAC under the audit key.

Verification then starts at the anchor: it checks the anchor's MAC, then
requires the first remaining event to be at the next position and to link to
the anchor's MAC. Consequences:

- Pruned history reads as "History before *time* was pruned by the
  retention policy (*N* events)" on the Audit page, and as the `anchor` object
  in `GET`/`POST /v1/audit/verify` and `GET /v1/audit/retention`.
- Deleting events any other way still breaks the chain: there is no anchor
  for them, or the anchor doesn't match.
- An edited or forged anchor (moved forward to hide deleted rows, say) fails
  its MAC, and verification reports the chain as broken.
- A verification that runs while another replica prunes follows the anchor
  forward instead of reporting the rows it lost.

The anchor proves that the pruned events existed and ended with a given MAC;
it can't bring their contents back. Keep a copy elsewhere if you need them.

## Archiving before pruning

Citadel doesn't write archive files itself; it keeps your copy flowing
somewhere durable and makes sure pruning can't get ahead of it:

- **SIEM streaming** (**Audit → Stream to SIEM**). While streaming is on,
  pruning never deletes an event that is still queued for delivery, so every
  event reaches your SIEM before it can leave Citadel. Events whose delivery
  gave up after 15 attempts no longer hold pruning back (fix the endpoint and
  look at the server log for `audit stream: delivery failed`). The retention
  settings show "Pruning waits for SIEM delivery" while streaming is on.
- **Scheduled export.** For a file-based archive, export each period before
  it ages out, for example nightly with a time range:

  ```sh
  curl -fsS -H "Authorization: Bearer $CITADEL_KEY_ID:$CITADEL_SECRET" \
    "https://citadel.example.com/v1/audit/export?format=json&from=2026-11-01T00:00:00Z&to=2026-11-02T00:00:00Z" \
    | gzip > citadel-audit-2026-11-01.json.gz
  ```

  Exports are limited to 100,000 events and 5 per minute per user; narrow the
  time range if a day has more. Run the export well inside the retention
  window (a retention of 90 days and a nightly export leave 89 days of slack).

Every exported or streamed event carries its `chainSeq`, `prevHash` and
`hash`, so an archive can still be checked against the chain.

## Disk space

PostgreSQL doesn't return space to the operating system when rows are
deleted. After a prune, autovacuum marks the space free and new audit events
reuse it, so the table stops growing, but the files on disk stay the same size.
In the test above the table was 224 MB before the prune, 225 MB after it and
after a plain `VACUUM`, and 49 MB after `VACUUM FULL`.

To shrink the table once, after the first prune of a large backlog:

- `VACUUM FULL kms_audit_events;` rewrites the table and its indexes. It takes
  an **ACCESS EXCLUSIVE** lock for the whole rewrite, which blocks every
  audited request (and so most of Citadel). Run it in a maintenance window.
- [`pg_repack`](https://reorg.github.io/pg_repack/) rebuilds the table online,
  with only brief locks at the start and end. Prefer it on a live system.

No routine maintenance is needed afterwards: with a steady retention the
table stays roughly the size of one window.

## Metrics

On the metrics listener (`KMS_METRICS_ADDR`), per replica:

| Metric | Meaning |
|---|---|
| `citadel_audit_pruned_events_total` | events this replica's retention runs deleted |
| `citadel_audit_retention_runs_total{result}` | runs by result: `ok`, `error`, or `skipped` (another replica held the lease) |
| `citadel_audit_retention_last_run_timestamp_seconds` | when this replica last finished a run |
| `citadel_audit_retention_last_run_pruned_events` | events the last run on this replica deleted |

Only the replica that holds the lease runs, so look at the maximum across
replicas. Platform admins see the deployment-wide last run (time, events
pruned, error) under **Administration → Audit**.

## API

| Call | Role | |
|---|---|---|
| `GET /v1/audit/retention` | viewer | The retention in force and its source, the account's event count and oldest event, the anchor; for platform admins also the table size and last run |
| `POST /v1/audit/retention` | admin | `{"retentionDays": 90}`, `{"retentionDays": 0}` (keep forever) or `{"retentionDays": null}` (deployment default) |
| `GET /v1/audit/retention/preview?days=N` | admin | How many events a retention of N days would prune now |

The Go SDK has `GetAuditRetention`, `SetAuditRetention`,
`PreviewAuditRetention` and `VerifyAuditChain`. The full schema is in
[openapi.yaml](openapi.yaml).
