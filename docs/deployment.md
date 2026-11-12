# Deploying Citadel

This guide is for operators running Citadel in production. It covers the
architecture, sizing, TLS, secrets and key rotation, backups, upgrades, FIPS
mode, image verification, and quick starts for the Helm chart
(`deploy/helm/citadel`) and the Compose stack (`deploy/compose`).

## Architecture

```
clients ──HTTPS──▶ ingress / gateway / load balancer
                         │  X-Forwarded-For
                         ▼
               ┌──────────────────────┐
               │ citadel replicas (N) │  stateless, :8080
               └──────────┬───────────┘
                          ▼
                      PostgreSQL         all state, encrypted with
                                          the wrapping key
```

- **Replicas are stateless.** Keys, secrets, parameters, certificates, console
  users and sessions, approvals and the audit chain all live in PostgreSQL.
  Any replica can serve any request, so you can run several behind one Service.
- **PostgreSQL is required for production** (`KMS_DB_URL`). Without it Citadel
  keeps everything in process memory: data is lost on restart and cannot be
  shared, so in-memory mode is for single-replica development only. The chart
  refuses to render it with more than one replica.
- **The wrapping key** (`KMS_WRAPPING_KEY_B64`, 32 bytes) encrypts all key
  material and secret values before they reach the database. The database on
  its own is useless without it, and so is a backup.
- **Startup is safe to run concurrently.** Schema migrations are versioned and
  serialized with a PostgreSQL advisory lock: one replica applies pending
  migrations, the others wait and then find them applied. Background jobs
  (session purges, certificate expiry, secret purges) are safe to run on every
  replica.
- **One origin serves everything:** the console (`/app/`), the AWS-protocol
  APIs (`/` and `/api`), the native API (`/v1/`), the ACME server (`/acme/`),
  CRLs (`/crl/`), Let's Encrypt HTTP-01 challenges
  (`/.well-known/acme-challenge/`) and workload identity discovery (`/oidc`).
  Route the whole hostname to Citadel; do not split paths across services.
- **Shutdown drains for up to 15 seconds** after SIGTERM. Give pods a
  termination grace period of at least 20 seconds (the chart defaults to 30,
  with a 5 second preStop sleep so load balancers stop sending traffic first).

## Sizing

Citadel is light on CPU and memory; PostgreSQL usually decides capacity.

| | Small (team) | Medium (org) | Notes |
|---|---|---|---|
| Replicas | 2 | 3–6 (HPA on CPU) | Two minimum for availability. |
| CPU request / replica | 100m | 250m–500m | RSA key generation and signing are the CPU-heavy operations. |
| Memory limit / replica | 512Mi | 512Mi–1Gi | |
| PostgreSQL | 2 vCPU, 4 GiB | 4 vCPU, 8–16 GiB, HA | Managed (RDS, Cloud SQL, Azure) or an operator such as CloudNativePG. |

Each replica opens up to **20 database connections** (5 kept idle). Set
PostgreSQL `max_connections` to at least `20 × maximum replicas` plus headroom
for maintenance and backups, or put PgBouncer (session mode) in front.

The audit log grows with every request. Watch database size and plan
retention and export accordingly.

## TLS

Choose one:

1. **Terminate at the ingress or gateway (recommended).** Use cert-manager or
   your cloud's certificate service for the public hostname, and let the
   ingress talk plain HTTP to the pods inside the cluster. Combine with a
   NetworkPolicy so only the ingress controller can reach the pods.
2. **TLS in the pod.** Set `KMS_TLS_CERT_FILE` and `KMS_TLS_KEY_FILE` (chart:
   `tls.enabled=true` and `tls.existingSecret=<kubernetes.io/tls Secret>`).
   Use this for end-to-end encryption behind the ingress (configure the
   ingress for an HTTPS backend, e.g.
   `nginx.ingress.kubernetes.io/backend-protocol: HTTPS`) or when exposing a
   LoadBalancer Service directly. Certificates are read at startup; restart
   the pods after renewal.

Either way:

- Set `KMS_PUBLIC_URL` to the external `https://` URL. The ACME server is
  disabled without it (JWS URLs must match exactly), and console SSO
  redirects, workload identity issuer URLs and CRL distribution points are
  built from it.
- Keep `KMS_UI_SECURE_COOKIES=true` (the default). Only turn it off for local
  evaluation over plain `http://localhost`.
- If you use Citadel's Let's Encrypt client with HTTP-01, exempt
  `/.well-known/acme-challenge/` from any HTTP-to-HTTPS redirect at the
  ingress, or make sure the redirect keeps the path (Let's Encrypt follows
  redirects to HTTPS).

## Trusted proxies and client addresses

Citadel records the client address in the audit log and uses it for rate
limits. Behind a proxy, every connection comes from the proxy, so Citadel
only believes `X-Forwarded-For` / `X-Real-IP` from addresses listed in
`KMS_TRUSTED_PROXIES` (comma-separated CIDRs or IPs).

- Set it to the **pod CIDR of the ingress controller** (or the node CIDR when
  the controller uses host networking), or the address range of your cloud
  load balancer if it adds `X-Forwarded-For`.
- Make sure the proxy sends the header. ingress-nginx does by default; for
  a cloud L4 load balancer in front of ingress-nginx, enable the PROXY
  protocol or `use-forwarded-headers` as appropriate so the original client
  address reaches the controller.
- Never list `0.0.0.0/0` or `::/0`: any client could then forge its address.
  The chart refuses to render it.
- With no proxy (clients connect straight to a LoadBalancer Service with
  `externalTrafficPolicy: Local`), leave it empty.

## Configuration reference

| Variable | Required | Sensitive | Purpose |
|---|---|---|---|
| `KMS_DB_URL` | yes (production) | yes | PostgreSQL URL. Use `sslmode=verify-full` for a remote database. The password must be at least 14 characters (FIPS 140-3). |
| `KMS_WRAPPING_KEY_B64` | with `KMS_DB_URL` | yes | 32 random bytes, base64. Encrypts all stored material. |
| `KMS_PREVIOUS_WRAPPING_KEYS_B64` | no | yes | Comma-separated retired wrapping keys, accepted for unwrapping during a rotation. |
| `KMS_AUDIT_HMAC_KEY_B64` | recommended | yes | At least 16 bytes, base64. Keys the audit hash chain. Derived from the wrapping key when unset. |
| `KMS_PUBLIC_URL` | for ACME, SSO, workload identity | no | External base URL. |
| `KMS_TRUSTED_PROXIES` | behind a proxy | no | See above. |
| `KMS_LISTEN_ADDR` | no | no | Default `:8080`. |
| `KMS_TLS_CERT_FILE`, `KMS_TLS_KEY_FILE` | no | key file | TLS in the pod. |
| `KMS_UI_USERS_JSON` | no | yes | Console users defined by configuration. Otherwise create them in the console after bootstrap. |
| `KMS_BOOTSTRAP_TOKEN` | no | yes | One-time first-run setup token (at least 16 characters). Generated and logged when unset. |
| `KMS_ACCESS_KEY_ID`, `KMS_SECRET_ACCESS_KEY` | no | secret key | Static AWS-style credentials (secret at least 20 characters). Prefer per-user access keys from the console. |
| `KMS_AWS_REGION`, `KMS_AWS_ACCOUNT_ID` | no | no | Identity used in ARNs. |
| `KMS_POLICY_DEFAULT_DENY` | no | no | Deny requests no policy allows. |
| `KMS_UI_SECURE_COOKIES` | no | no | Default `true`. |
| `KMS_UI_SESSION_IDLE_TTL`, `KMS_UI_SESSION_MAX_TTL` | no | no | Console session lifetimes (default 30m / 12h). |
| `KMS_PPROF_ADDR` | no | no | Loopback profiling listener; reach it with `kubectl port-forward`. |
| `KMS_INSECURE_DEV` | never in production | no | Turns off all authentication. |

## First run

With PostgreSQL and no console users, Citadel starts in **bootstrap mode**:
its API is closed except for first-run setup, server info and login. Open
`<KMS_PUBLIC_URL>/app/`, enter the bootstrap token, and create the
organization, first account and platform admin. The token is the value of
`KMS_BOOTSTRAP_TOKEN` if you set one; otherwise the server generates one and
prints it in its log. A generated token is valid only on the replica that
printed it, so for a multi-replica first run set `KMS_BOOTSTRAP_TOKEN` (or run
setup with one replica):

```bash
kubectl -n citadel logs -l app.kubernetes.io/name=citadel --tail=-1 | grep -i bootstrap
```

Setup can succeed only once; concurrent attempts are serialized in the
database. Do this immediately after the first deployment, before exposing
the hostname widely.

## Secrets management

The chart takes every sensitive value from Kubernetes Secrets and will not
put secrets in plain values unless you set `secrets.create=true`. Inline
values end up in values files, in Git, and in Helm's release history.

Recommended: keep the values in a secret store and sync them into one
Secret with the [External Secrets Operator](https://external-secrets.io):

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: citadel-secrets
  namespace: citadel
spec:
  refreshInterval: 1h
  secretStoreRef:
    kind: ClusterSecretStore
    name: vault            # or aws-secrets-manager, gcp-sm, azure-kv, ...
  target:
    name: citadel-secrets
    creationPolicy: Owner
    deletionPolicy: Retain # never delete the wrapping key with the CR
  data:
    - secretKey: KMS_DB_URL
      remoteRef: {key: citadel/prod, property: db_url}
    - secretKey: KMS_WRAPPING_KEY_B64
      remoteRef: {key: citadel/prod, property: wrapping_key}
    - secretKey: KMS_AUDIT_HMAC_KEY_B64
      remoteRef: {key: citadel/prod, property: audit_hmac_key}
```

Then install with `secrets.existingSecret=citadel-secrets`. Sealed Secrets
or SOPS work the same way: produce a Secret with keys named after the
environment variables. Individual values can also come from different
Secrets (`secrets.<name>.existingSecret` and `.existingSecretKey`), for
example a database Secret created by your PostgreSQL operator.

Generate keys with:

```bash
openssl rand -base64 32   # KMS_WRAPPING_KEY_B64
openssl rand -base64 32   # KMS_AUDIT_HMAC_KEY_B64
```

Set `KMS_AUDIT_HMAC_KEY_B64` explicitly at installation. When it is unset the
audit key is derived from the wrapping key, so rotating the wrapping key would
also change the key the audit chain is verified with.

Environment variables are read at startup. After changing a Secret, restart
the pods (`kubectl rollout restart deploy/citadel`). The chart rolls the pods
automatically only for the Secret it manages itself.

### Rotating the wrapping key

Rotation replaces the key that wraps stored material without downtime:

1. **Back up** the database and confirm you hold the current wrapping key.
2. **Generate** a new key: `openssl rand -base64 32`.
3. **Update the Secret:** set `KMS_WRAPPING_KEY_B64` to the new key and put
   the old key in `KMS_PREVIOUS_WRAPPING_KEYS_B64`. If the list already has
   entries, keep them, comma-separated.
4. **Restart** the replicas (`kubectl rollout restart deploy/citadel`). From
   now on new material is wrapped with the new key; material wrapped with a
   previous key is still readable.
5. **Re-wrap.** While previous keys are configured, each replica runs a
   re-wrap job at startup and daily that rewrites stored material under the
   current key. Updates are conditional, so several replicas running it is
   safe. To run it immediately, an admin can call
   `POST /v1/kms/admin/rewrap`, which returns
   `{"scanned": n, "rewrapped": n, "failed": n}`. The job logs
   `kms rewrap: scanned=… rewrapped=… failed=…` and records an audit event.
6. **Verify** that a run reports `failed=0`, then take a **new backup**.
7. **Retire** the old key: remove it from `KMS_PREVIOUS_WRAPPING_KEYS_B64`
   and restart. Keep the old key archived, offline, for as long as you keep
   backups taken before the rotation: those backups need it to restore.

If any material fails to re-wrap, do not remove the previous key; check the
server log for the affected records.

## Backups and restore

A complete backup is **two things, stored separately**:

1. The PostgreSQL database, e.g.
   `pg_dump --format=custom --file=citadel-$(date +%F).dump "$KMS_DB_URL"`,
   or your platform's snapshots / point-in-time recovery.
2. The **wrapping key** (and the audit HMAC key and any previous wrapping
   keys), kept in a different system from the database backups: a secret
   manager, an HSM-backed vault, or sealed offline copies under dual control.

Without the wrapping key a database backup cannot be decrypted. **If you lose
the wrapping key, all keys, secrets and certificates in Citadel are lost.**
There is no recovery path. Conversely, anyone holding both a backup and the
key has everything, which is why they must not sit together.

Restore:

1. Restore the dump into an empty database
   (`pg_restore --no-owner --dbname "$KMS_DB_URL" citadel.dump`).
2. Deploy Citadel with the same `KMS_WRAPPING_KEY_B64` (and
   `KMS_PREVIOUS_WRAPPING_KEYS_B64` if the backup predates a rotation that
   had not finished re-wrapping) and the same `KMS_AUDIT_HMAC_KEY_B64`.
3. Use the same Citadel version as the backup or newer; migrations bring an
   older schema forward.
4. Verify the audit chain and read a known secret.

Test restores regularly in a separate namespace.

## Upgrades

- **Read the changelog** for breaking changes and new required settings.
- **Back up first.** Migrations run automatically at startup and are not
  reversible.
- **Rolling upgrade:** `helm upgrade` replaces pods one at a time
  (`maxUnavailable: 0`). The first new pod takes the advisory lock and
  applies pending migrations; the others wait for it. Old pods keep serving
  while this happens, so they run briefly against the new schema; releases
  keep migrations compatible with the previous version unless the changelog
  says otherwise. In that case scale to one replica, or schedule downtime.
- The startup probe allows 5 minutes (60 × 5s) for the first start, which
  includes waiting for migrations. Raise `probes.startup.failureThreshold`
  for very large databases.
- **Rollback:** there are no down migrations. Rolling back the image
  (`helm rollback`) works when the newer release's migrations were additive;
  an older binary ignores schema versions it does not know. If the changelog
  marks a migration as incompatible, roll back by restoring the pre-upgrade
  backup together with the old image.
- Pin images by digest (`image.digest`) for reproducible deployments, after
  verifying the signature.

## FIPS 140-3

The image is built with the Go Cryptographic Module (`GOFIPS140=certified`)
and runs with `GODEBUG=fips140=only`, set by the base image: non-approved
algorithms fail at runtime rather than being used silently. Consequences for
operators:

- PostgreSQL passwords must be **at least 14 characters**; SCRAM-SHA-256 with
  a shorter password is rejected in FIPS mode. Use `scram-sha-256`
  authentication (the default on PostgreSQL 14 and later).
- HMAC keys must be at least 112 bits: `KMS_AUDIT_HMAC_KEY_B64` at least 16
  bytes, static secret access keys at least 20 characters.
- Keep TLS endpoints (ingress, database, OIDC providers) on TLS 1.2+ with
  approved cipher suites; legacy suites fail the handshake.
- Do not override `GODEBUG` in the pod: removing `fips140=only` takes the
  process out of its validated configuration.
- The image is published for `linux/amd64`.

## Verifying the image

Release images are signed keylessly with Sigstore from the release workflow
and carry an SBOM and build provenance. Verify before deploying:

```bash
cosign verify ghcr.io/worlddrknss/citadel:<tag> \
  --certificate-identity-regexp 'https://github.com/worlddrknss/citadel/.github/workflows/release-image.yaml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Use the digest from the output for `image.digest` so the cluster runs exactly
the image you verified. To enforce this in the cluster, use an admission
policy (Sigstore policy-controller, Kyverno `verifyImages`) with the same
identity and issuer.

## Quick start: Helm

Prerequisites: Kubernetes 1.27+ (1.30+ for the preStop sleep), Helm 3,
PostgreSQL reachable from the cluster, an ingress controller or Gateway.

```bash
kubectl create namespace citadel

# 1. Secrets (use External Secrets / Sealed Secrets in production).
kubectl -n citadel create secret generic citadel-secrets \
  --from-literal=KMS_DB_URL='postgres://citadel:<password>@db.example.internal:5432/citadel?sslmode=verify-full' \
  --from-literal=KMS_WRAPPING_KEY_B64="$(openssl rand -base64 32)" \
  --from-literal=KMS_AUDIT_HMAC_KEY_B64="$(openssl rand -base64 32)"

# Back up the wrapping key now, somewhere other than the database backups:
kubectl -n citadel get secret citadel-secrets -o jsonpath='{.data.KMS_WRAPPING_KEY_B64}' | base64 -d | base64

# 2. Values.
cat > citadel-values.yaml <<'EOF'
secrets:
  existingSecret: citadel-secrets
config:
  publicUrl: https://citadel.example.com
  trustedProxies: ["10.244.0.0/16"]   # ingress controller pod CIDR
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt
  hosts:
    - host: citadel.example.com
      paths: [{path: /, pathType: Prefix}]
  tls:
    - secretName: citadel-tls
      hosts: [citadel.example.com]
networkPolicy:
  enabled: true
  egress:
    database:
      cidrs: ["10.0.20.0/24"]          # PostgreSQL address range
EOF

# 3. Install.
helm install citadel deploy/helm/citadel -n citadel -f citadel-values.yaml
kubectl -n citadel rollout status deploy/citadel
```

Then follow the printed notes: read the bootstrap token from the log and
open `https://citadel.example.com/app/`.

Optional features, all in `values.yaml` with comments:

- `httpRoute.enabled` — Gateway API instead of Ingress.
- `autoscaling.enabled` — HorizontalPodAutoscaler (CPU, optionally memory).
- `workloadIdentity.kubernetes.tokenReview` — mounts Citadel's service
  account token and binds it to `system:auth-delegator` so Citadel can verify
  Kubernetes service account tokens. Off by default; no API token is mounted
  otherwise. With a NetworkPolicy, also set
  `networkPolicy.egress.kubeApiServer.cidrs`.
- `metrics.enabled` and `metrics.serviceMonitor.enabled` — scrape a metrics
  endpoint (`metrics.path`) on releases that serve one.
- `probes.readinessPath` — point readiness at `/readyz` on releases that
  provide it.
- `tls.enabled` — HTTPS in the pod.

The NetworkPolicy allows ingress from the controller's namespace
(`networkPolicy.ingress.namespaceSelector`) and egress to DNS, PostgreSQL,
HTTPS (OIDC providers, Let's Encrypt, ACME `tls-alpn-01` validation) and
HTTP on port 80 (ACME `http-01` validation), excluding the cloud metadata
address. Narrow the HTTPS and HTTP ranges if you do not use those features.

The chart validates its values (`values.schema.json`) and refuses unsafe
combinations at render time. `deploy/helm/validate.sh` runs the same checks
as CI.

## Quick start: Docker Compose

For local evaluation with PostgreSQL 17:

```bash
cd deploy/compose
./generate-env.sh            # writes .env with random secrets, mode 0600
docker compose up -d
docker compose logs citadel | grep -i bootstrap
open http://localhost:8080/app/
```

`generate-env.sh` never overwrites an existing `.env`, because replacing the
wrapping key makes the existing database unreadable. `.env` is ignored by
Git; never commit it. To start over, `docker compose down -v` removes the
database volume.

The Compose stack serves plain HTTP on `127.0.0.1` with Secure cookies off.
It is not a production deployment: put TLS in front, back up the volume and
the `.env` keys, and prefer the Helm chart or an equivalent orchestrated
setup for anything you depend on.
