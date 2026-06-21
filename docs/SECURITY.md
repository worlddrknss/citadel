# Citadel Security Model

Citadel (module `github.com/worlddrknss/go-kms`) is an AWS KMS + Secrets Manager
JSON API-compatible service used for Vault auto-unseal and secret storage. This
document describes its trust model, what the request signing actually verifies,
and the controls available for production hardening.

> Naming: the product is **Citadel**. The Go module path, container image,
> Kubernetes manifests, and `KMS_*` environment variables retain the historical
> `go-kms` / `KMS_` identifiers for backward compatibility with existing
> deployments.

## Trust model

Citadel holds the master key material used to wrap data keys and to encrypt
secret values. Anyone with network access to the service and valid credentials
can request decryption. Treat the service host, its database, and its
environment variables as highly sensitive.

Primary threats considered:

- Unauthorized API access (mitigated by access-key + SigV4 verification).
- Credential stuffing / weak admin passwords (mitigated by Argon2id hashing and
  DB-backed RBAC).
- Ciphertext tampering (mitigated by AES-256-GCM with key-ID bound as AAD).
- Audit-log tampering (mitigated by an HMAC-SHA256 hash chain).
- Session theft / fixation (mitigated by HttpOnly + optional Secure cookies and
  idle/absolute session TTLs).
- Denial of service via slow/large requests (mitigated by HTTP timeouts and a
  bounded request-body reader).

Out of scope: hardware key isolation (no HSM), side-channel resistance beyond
constant-time comparisons, and protection against an attacker with read access
to the master key or database.

## Request authentication (SigV4)

Two independent controls gate the KMS endpoint:

1. `KMS_ACCESS_KEY_ID` — when set, requests must present this access key ID in
   the `Authorization` header (presence check).
2. `KMS_SECRET_ACCESS_KEY` — when set together with `KMS_SIGV4_STRICT=true`,
   Citadel performs a full AWS Signature V4 recomputation:
   - parses the `Authorization` header (credential scope, signed headers,
     provided signature),
   - reads and SHA-256 hashes the request body (bounded reader),
   - rebuilds the canonical request and string-to-sign,
   - derives the signing key (`AWS4` → date → region → service → `aws4_request`),
   - constant-time compares the recomputed signature with the provided one.

   On any mismatch the response is a generic `request signature is invalid`
   to avoid leaking which step failed.

If `KMS_SECRET_ACCESS_KEY` is empty, only the presence check (control 1) runs.
For production, set both and enable strict mode.

## Admin console authentication (RBAC)

- Passwords are verified with **Argon2id** (`$argon2id$v=19$m=65536,t=3,p=2$…`).
  Plaintext verification remains only as a fallback for legacy env users; supply
  `passwordHash` in `KMS_UI_USERS_JSON` to avoid plaintext entirely.
- Users may be **stored in the database** (`ui_users` table). DB users take
  precedence over env users, and env users are seeded into the DB (hashed) on
  first run, so accounts can be managed centrally without redeploys.
- Roles are ranked `admin > editor > viewer`; handlers enforce a minimum role.
- Unknown usernames still run a dummy Argon2 verification to keep login timing
  roughly constant (mitigates user enumeration).
- Sessions enforce both an **idle TTL** and an **absolute TTL**; cookies are
  `HttpOnly`, `SameSite=Lax`, and `Secure` when `KMS_UI_SECURE_COOKIES=true`.

## Cryptography

- **Key wrapping:** AES-256-GCM. The wrapping key is derived from the master key
  with HKDF-SHA256. The key ID is bound as additional authenticated data (AAD)
  so a wrapped blob cannot be replayed under a different key ID. Legacy blobs
  (single SHA-256 derivation, no AAD) remain decryptable via a fallback
  candidate list.
- **Secret values:** AES-256-GCM under the resolved data key.
- **Audit chain:** each record's hash is `HMAC-SHA256(auditHMACKey, prevHash ||
  event || ts)` when `KMS_AUDIT_HMAC_KEY_B64` is set, otherwise SHA-256. The
  HMAC variant detects tampering by anyone lacking the key.

## Security-relevant environment variables

| Variable | Purpose | Production recommendation |
| --- | --- | --- |
| `KMS_ACCESS_KEY_ID` | Required access key ID in Authorization header | Set |
| `KMS_SECRET_ACCESS_KEY` | Secret for full SigV4 verification | Set |
| `KMS_SIGV4_STRICT` | Enable full SigV4 signature recomputation | `true` |
| `KMS_POLICY_DEFAULT_DENY` | Deny when no matching policy statement | `true` |
| `KMS_AUDIT_HMAC_KEY_B64` | Base64 key for HMAC audit chain | Set (32 bytes) |
| `KMS_UI_SECURE_COOKIES` | Mark admin session cookie `Secure` | `true` (behind TLS) |
| `KMS_UI_SESSION_IDLE_TTL` | Idle session timeout (e.g. `30m`) | `15m`–`30m` |
| `KMS_UI_SESSION_MAX_TTL` | Absolute session lifetime (e.g. `12h`) | `8h`–`12h` |
| `KMS_UI_USERS_JSON` | Admin users; supports `passwordHash` (Argon2id) | Use `passwordHash` |
| `KMS_TLS_CERT_FILE` / `KMS_TLS_KEY_FILE` | Enable in-process TLS | Set or terminate TLS at proxy |
| `KMS_MASTER_KEY_B64` | Master key material | Inject via secret manager |
| `KMS_DB_URL` | PostgreSQL connection string | Required for RBAC + Secrets Manager |

## Production checklist

- [ ] `KMS_DB_URL` configured (enables RBAC and Secrets Manager).
- [ ] `KMS_ACCESS_KEY_ID` + `KMS_SECRET_ACCESS_KEY` set, `KMS_SIGV4_STRICT=true`.
- [ ] `KMS_POLICY_DEFAULT_DENY=true`.
- [ ] `KMS_AUDIT_HMAC_KEY_B64` set to a unique 32-byte key.
- [ ] TLS enabled (in-process or via a terminating proxy) and
      `KMS_UI_SECURE_COOKIES=true`.
- [ ] Admin users defined with Argon2id `passwordHash` (no plaintext); rotate
      regularly.
- [ ] Session TTLs tuned (`KMS_UI_SESSION_IDLE_TTL`, `KMS_UI_SESSION_MAX_TTL`).
- [ ] Master key and DB credentials injected from a secret manager, never baked
      into images.
- [ ] Network policy restricts access to trusted clients (e.g. Vault) only.

## Reporting

For suspected vulnerabilities, contact the repository maintainers privately
before public disclosure.
