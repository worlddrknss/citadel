# Configuration reference

Citadel is configured with environment variables. Values marked **secret**
should come from a secret store (a Kubernetes Secret, External Secrets,
SOPS), never from plain manifests or shell history.

Durations use Go syntax (`30m`, `12h`, `5s`). Booleans are `true` or `false`.

## Storage and keys

| Variable | Default | Description |
|---|---|---|
| `KMS_DB_URL` **secret** | — | PostgreSQL connection URL. Required for anything beyond local development: without it Citadel keeps everything in memory, in one process. Use a password of at least 14 characters (FIPS mode rejects shorter HMAC keys, and the PostgreSQL driver uses the password as one). |
| `KMS_WRAPPING_KEY_B64` **secret** | — | Base64 of 32 random bytes. Encrypts all key material, access-key secrets and other sealed values at rest. Required with PostgreSQL unless `KMS_MASTER_KEY_B64` is set. **Back it up separately from the database: a backup is useless without it.** |
| `KMS_PREVIOUS_WRAPPING_KEYS_B64` **secret** | — | Comma-separated retired wrapping keys, used only to unwrap values wrapped before a rotation. See [Rotating the wrapping key](#rotating-the-wrapping-key). |
| `KMS_MASTER_KEY_B64` **secret** | — | Legacy (pre-1.0) single master key, base64 of 32 bytes. With PostgreSQL, the wrapping key is derived from it when `KMS_WRAPPING_KEY_B64` is unset. Without PostgreSQL it is the in-memory store's bootstrap key. |
| `KMS_KEY_ID`, `KMS_KEY_ARN` | derived | ID and ARN of the legacy bootstrap key. |
| `KMS_AUDIT_HMAC_KEY_B64` **secret** | derived | Key for the audit log's HMAC chain (at least 16 bytes). When unset it is derived from the deployment root secret, which stays stable across wrapping-key rotations. |
| `KMS_AUDIT_RETENTION_DAYS` | `0` | Default audit retention in days: `0` keeps events forever (so an upgrade never deletes anything), otherwise 7 to 3650. Older events are pruned hourly, in small batches, with a chain anchor that keeps verification intact. Account admins can override it per account under **Administration → Audit**. See [audit.md](audit.md#retention), including how to reclaim disk space after the first prune. |
| `KMS_JOB_INTERVAL` | `1h` | How often background KMS jobs run (automatic rotation, destroying keys past their deletion date, re-wrapping). Minimum `1m`. |

## Network and URLs

| Variable | Default | Description |
|---|---|---|
| `KMS_LISTEN_ADDR` | `:8080` | Address the API and console listen on. |
| `KMS_PUBLIC_URL` | — | External base URL, e.g. `https://citadel.example.com`, without a trailing slash. Required for the ACME server, console SSO and workload identity, which all hand out URLs to other systems. Those features stay off while it is unset. |
| `KMS_TRUSTED_PROXIES` | — | Comma-separated CIDRs or IPs of reverse proxies whose `X-Forwarded-For` / `X-Real-IP` headers are believed for audit source IPs and rate limits. Never `0.0.0.0/0`. |
| `KMS_TLS_CERT_FILE`, `KMS_TLS_KEY_FILE` | — | Serve TLS directly. The certificate reloads when the files change. Leave unset when TLS terminates at a load balancer or ingress. |
| `KMS_METRICS_ADDR` | — | Address of a separate Prometheus listener, e.g. `:9090`. Metrics are never served on the public port. |
| `KMS_PPROF_ADDR` | — | Go profiler listener. Bind to loopback only (`127.0.0.1:6060`) and reach it with port-forwarding. |
| `KMS_SHUTDOWN_DELAY` | `0` | After SIGTERM, keep serving this long while `/readyz` reports not ready, so load balancers stop sending traffic first. |

## AWS API authentication

Every AWS-protocol request must carry a valid SigV4 signature made with one
of: an access key created in the console, STS temporary credentials (with
their session token), or the static pair below.

| Variable | Default | Description |
|---|---|---|
| `KMS_ACCESS_KEY_ID` | — | Static deployment access key ID. Set together with the secret. |
| `KMS_SECRET_ACCESS_KEY` **secret** | — | Static secret, at least 20 characters. Required for the in-memory store (which has no console-managed keys). |
| `KMS_AWS_REGION` | `us-west-2` | Region used in the ARNs Citadel creates. Clients may sign requests for any region; the signature is checked against the region in its credential scope. |
| `KMS_AWS_ACCOUNT_ID` | generated | The deployment account ID used in ARNs. Stored in the database on first start; later values are ignored. |
| `KMS_POLICY_DEFAULT_DENY` | `false` | When `true`, key policies deny any action no statement allows (AWS behaviour). When `false`, an action no statement mentions is allowed. |

## Console

| Variable | Default | Description |
|---|---|---|
| `KMS_UI_USERS_JSON` **secret** | — | Console users defined by configuration: a JSON array of `{"username","passwordHash" or "password","role","displayName","accounts"}`. Prefer creating users in the console. |
| `KMS_UI_USERNAME`, `KMS_UI_PASSWORD` **secret**, `KMS_UI_ROLE`, `KMS_UI_DISPLAY_NAME`, `KMS_UI_ACCOUNTS` | `admin`, —, `admin`, `Admin`, — | A single configured user (used when `KMS_UI_USERS_JSON` is unset). |
| `KMS_BOOTSTRAP_TOKEN` **secret** | generated | One-time token for first-run setup (at least 16 characters). With PostgreSQL and no console users, Citadel starts in bootstrap mode and asks for this token to create the first organization and admin. When unset, the first replica to start generates one and logs it; only its SHA-256 is stored in the database, so every replica accepts it and setup consumes it once. The other replicas log that a token was already issued (look in the first replica's log, or set this variable). An unused generated token expires after 24 hours and the next replica to start issues a new one. |
| `KMS_UI_SECURE_COOKIES` | `true` | Mark the session cookie `Secure`. Only set `false` if browsers reach the console over plain HTTP outside development. |
| `KMS_UI_SESSION_IDLE_TTL` | `30m` | Sign out after this much inactivity. Organization settings can override it. |
| `KMS_UI_SESSION_MAX_TTL` | `12h` | Maximum session length. Organization settings can override it. |

## Workload identity

| Variable | Default | Description |
|---|---|---|
| `KMS_WORKLOAD_K8S_REVIEWER_TOKEN_FILE` | in-cluster token | File with the bearer token Citadel uses for the Kubernetes TokenReview API, re-read on every use. Defaults to the pod's service-account token when running in Kubernetes. The service account needs the `system:auth-delegator` ClusterRole. |
| `KMS_WORKLOAD_K8S_REVIEWER_TOKEN` **secret** | — | Static alternative to the token file. Don't set both. |

## Email notifications (SMTP)

Email [notification channels](notifications.md) send through one outgoing
mail server for the whole deployment. Leave `KMS_SMTP_HOST` unset to turn
email channels off (webhook and Slack channels still work). There is no
plaintext mode: the connection is always TLS, and credentials are only sent
after it is encrypted.

| Variable | Default | Description |
|---|---|---|
| `KMS_SMTP_HOST` | — | Mail server host name or address, without a port. |
| `KMS_SMTP_PORT` | `587` (`465` with `tls`) | Mail server port. |
| `KMS_SMTP_TLS` | `starttls` (`tls` on port 465) | `starttls`: connect, then upgrade with STARTTLS (a server that doesn't offer it is refused); `tls`: implicit TLS (SMTPS). The server's certificate is verified against the system roots. |
| `KMS_SMTP_USERNAME` | — | User for AUTH PLAIN. Leave unset for a relay that needs no authentication. |
| `KMS_SMTP_PASSWORD` **secret** | — | Password for `KMS_SMTP_USERNAME`. |
| `KMS_SMTP_PASSWORD_FILE` | — | File holding the password, re-read on every send (for a mounted secret). Don't set both. |
| `KMS_SMTP_FROM` | — | Required with `KMS_SMTP_HOST`. Sender address, optionally with a display name: `Citadel <citadel@example.com>`. |

## Rate limits

Rate limits have no settings. Each replica keeps token buckets in memory
(per client IP for sign-in, first-run setup, SSO and the workload token
endpoint; also per username for sign-in and per client ID for workload
tokens; per client IP and per user for MFA codes), with a lockout after
repeated failed sign-ins and after repeated wrong MFA codes.

With PostgreSQL the same endpoints are also limited **deployment-wide**, so
adding replicas doesn't multiply the limits:

| Limiter | Key | Limit per window |
|---|---|---|
| Sign-in | client IP | 40 per minute |
| Sign-in | username (any case) | 20 per minute |
| MFA code (sign-in, enrolment, re-authentication) | client IP | 40 per minute |
| MFA code | username (any case) | 15 per 5 minutes |
| First-run setup | client IP | 10 per 5 minutes |
| SSO sign-in start | client IP | 90 per minute |
| Workload token | client IP | 90 per minute |
| Workload token | client ID | 360 per minute |

Each limit is at least what one replica's bucket allows over the same window,
so a single replica behaves as it did before. Design:

- **Fixed windows in one UPSERT.** Each counted request increments a row
  keyed by limiter, key and window (`rate_limit_counters`) with
  `INSERT … ON CONFLICT DO UPDATE … RETURNING`; every counter a request needs
  (for example IP and username) goes in the same statement, so a request
  costs one round trip. Windows are aligned to the database clock, so
  replicas with skewed clocks share them.
- **Local first.** The in-memory bucket runs first and refuses floods without
  touching the database; only requests it lets through are counted.
- **No hot row.** Rows are per key and window: requests contend only with
  requests for the same IP, username or client in the same window, never on a
  global counter. Rows are locked in a fixed order, so concurrent requests
  can't deadlock.
- **Bounded cost.** The table is `UNLOGGED` (no WAL; counters reset after a
  crash or failover, which only relaxes limits briefly), keys are stored as a
  SHA-256 prefix (no IPs or usernames in clear), and a job deletes windows
  older than an hour every 5 minutes.
- **Fail open.** The counter query has a 250 ms timeout. If the database is
  slow or failing the request is allowed (and a warning logged at most once a
  minute); the local buckets still apply.
- Fixed windows can let up to twice a limit through around a window
  boundary. The sign-in lockout after repeated failures stays per replica;
  the shared per-username limit bounds guesses across replicas.

The memory store (a single process) uses the in-memory buckets only.

## Logging

| Variable | Default | Description |
|---|---|---|
| `KMS_LOG_FORMAT` | `json` | `json` or `text`. |
| `KMS_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. |

## Development only

| Variable | Default | Description |
|---|---|---|
| `KMS_INSECURE_DEV` | `false` | Turns off **all** authentication: unsigned AWS requests are accepted and every console visitor is an administrator. For local development only. Citadel logs a warning at startup when it is on. |

## Removed

| Variable | Notes |
|---|---|
| `KMS_SIGV4_STRICT` | Ignored since 2.0: signatures are always verified. A warning is logged if it is set. |

## Rotating the wrapping key

1. Generate a new key: `openssl rand -base64 32`.
2. Deploy with `KMS_WRAPPING_KEY_B64` set to the new key and
   `KMS_PREVIOUS_WRAPPING_KEYS_B64` set to the old one. New values are wrapped
   with the new key; old ones still unwrap.
3. Re-wrap everything: `POST /v1/kms/admin/rewrap` as a platform admin (or
   wait for the background job, which runs while previous keys are
   configured). The response counts what was re-wrapped and what failed.
   Repeat until `failed` is 0.
4. Remove the old key from `KMS_PREVIOUS_WRAPPING_KEYS_B64` and redeploy.

Derived keys (the audit chain key, fingerprints, sealed SSO and stream
secrets) come from a deployment root secret that is itself wrapped, so they
don't change during a rotation. The first start of 2.0 creates that root
secret from the wrapping key in use at that moment, so upgrade to 2.0 before
you rotate for the first time; Citadel refuses to create it while previous
keys are configured.
