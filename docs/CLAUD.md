# go-kms — Codebase Review & Recommendations

> Reviewer: Claude (GitHub Copilot)
> Date: 2026-06-21
> Scope: Full read-only review of `cmd/server/*.go` and templates. Findings below were
> verified against the actual source (line references are approximate and may shift).

> **Implementation status (follow-up):** All High, Medium, and Low findings below have
> since been implemented. Highlights:
> - **H1** Full AWS SigV4 signature recomputation + constant-time compare (`security.go`,
>   wired into `handleKMS` under `KMS_SIGV4_STRICT` + `KMS_SECRET_ACCESS_KEY`).
> - **H2** Argon2id password hashing (`hashPassword`/`verifyPassword`) and a **DB-backed
>   RBAC** user store (`ui_users` table, `admin_users.go`) merged with env users.
> - **H3/M1/M2** HTTP timeouts, graceful shutdown via signals, and panic-recovery middleware.
> - **H4** `inMemoryStore` mutex covering all mutable methods (verified with `go test -race`).
> - **M3** `KMS_POLICY_DEFAULT_DENY`; **M4/L1** HKDF wrapping key + key-ID AAD (backward
>   compatible); **L4** HMAC-SHA256 audit chain; **M5** security headers + secure cookies;
>   **L2** idle/absolute session TTLs.
> - Trust model and a production checklist are documented in `docs/SECURITY.md`.
> - Branding: the product is now **Citadel**; the Go module path and `KMS_*` env vars are
>   retained for deployment backward compatibility.

## 1. Executive Summary

`go-kms` is a focused, well-tested AWS KMS + Secrets Manager JSON-API-compatible service
intended for Vault auto-unseal and lab/internal environments. The protocol surface is broad,
the admin console is genuinely useful, and there is a solid audit-chain foundation. The code
is clean and idiomatic Go with a healthy test suite (`main_test.go` ~900 lines).

The main risks are concentrated in three areas:

1. **Authentication strength** — SigV4 is presence-checked but never cryptographically
   verified; UI passwords are stored and compared in plaintext.
2. **Operational hardening** — missing HTTP timeouts, a dead graceful-shutdown path, no
   panic recovery, and no `inMemoryStore` locking.
3. **Maintainability** — `main.go` is ~2,576 lines mixing routing, crypto, policy, schema,
   and storage.

None of these are blockers for the stated lab/Vault-unseal use case, but they should be
addressed before any exposure beyond a trusted network. The README already acknowledges this
("not a full AWS KMS implementation"), which is the right posture.

### Severity snapshot

| Severity | Count | Themes |
|----------|-------|--------|
| High     | 4     | SigV4 not verified, plaintext UI passwords, no HTTP timeouts, `inMemoryStore` data races |
| Medium   | 7     | Dead shutdown path, no panic recovery, default-allow policy, deterministic wrapping-key KDF, no TLS/security headers, error leakage, monolithic `main.go` |
| Low      | 5     | No AAD on wrap, session TTL, length-leak in compare, audit authenticity, feature-gap UX |

---

## 2. What's Working Well

- **Test coverage** is strong: auth flows, policy-deny paths, grants lifecycle, audit
  rendering, and ciphertext compatibility are all exercised.
- **Audit hash chain** (`hashAuditRecord`, `RecordAudit`) gives tamper-evidence with
  `PrevHash`/`EventHash` linkage — a good foundation.
- **Key-material migration** (`migrateLegacyKeyMaterial`) safely upgrades plaintext
  `master_key_b64` rows to wrapped storage, and legacy ciphertexts remain decryptable.
- **Config validation** is careful: 32-byte key enforcement, clear required-env errors, and
  a derived-wrapping-key fallback so DB mode can't start without a wrapping key.
- **`html/template`** is used for the admin UI, which auto-escapes and neutralizes most XSS.
- **Role model** (`viewer`/`editor`/`admin`) and tenant scoping are cleanly factored into
  `admin_auth.go` / `admin_scope.go`.

---

## 3. High-Priority Findings

### H1 — SigV4 is validated by presence, not by signature
`validateSigV4Request` (main.go ~L1412) only checks that the `Authorization` header starts
with `AWS4-HMAC-SHA256 ` and contains the substrings `Credential=`, `SignedHeaders=`,
`Signature=`, plus `X-Amz-Date`/`X-Amz-Target`. The signature itself is never recomputed or
compared. Combined with `hasAccessKey` (a substring check on `Credential=<key>/`), any client
that knows the access key ID can forge a request.

**Recommendation:** Implement real SigV4 verification behind `KMS_SIGV4_STRICT=true` (derive
the signing key from a configured secret, recompute the canonical request + string-to-sign,
and `subtle.ConstantTimeCompare` the signature). Document clearly that without it, the service
trusts the network perimeter and `mTLS`/`KMS_ACCESS_KEY_ID` only.

### H2 — UI passwords are stored and compared in plaintext
`uiUserConfig.Password` comes straight from `KMS_UI_PASSWORD` / `KMS_UI_USERS_JSON` and is
compared via `compareSecret` (main.go ~L2390), which is constant-time but operates on raw
plaintext. Passwords therefore live in environment variables and process memory.

**Recommendation:** Store and compare a hash (bcrypt or argon2id). Accept pre-hashed values in
`KMS_UI_USERS_JSON` (e.g. `passwordHash`) so secrets never appear in plaintext env. Keep the
constant-time comparison on the hash.

**Comments:** We should be using `ARGON2` and we should add a use RBAC system that tied into the DB.

### H3 — HTTP server has no request/idle timeouts (Slowloris exposure)
`httpServer` (main.go ~L358) sets only `ReadHeaderTimeout: 10s`. There is no `ReadTimeout`,
`WriteTimeout`, or `IdleTimeout`, so a slow client can hold connections open and exhaust
resources.

**Recommendation:**
```go
httpServer := &http.Server{
    Addr:              cfg.addr,
    Handler:           h,
    ReadHeaderTimeout: 10 * time.Second,
    ReadTimeout:       30 * time.Second,
    WriteTimeout:      30 * time.Second,
    IdleTimeout:       120 * time.Second,
}
```

### H4 — `inMemoryStore` mutates shared state without locking
`inMemoryStore` (main.go ~L103) holds `keys`, `aliases`, `grants`, `policies`, `secrets`,
and `audit` with no mutex. `RecordAudit` (~L2011) does `s.auditSeq++` and `append`, and the
secret/grant methods write shared maps/slices. Under concurrent requests this is a data race
(`go test -race` would likely flag it). This store backs the legacy single-key/no-DB mode.

**Recommendation:** Add a `sync.RWMutex` to `inMemoryStore` and guard every method, or document
that in-memory mode is single-threaded only. The DB store is fine (Postgres handles
concurrency), so this is contained to the fallback path.

---

## 4. Medium-Priority Findings

### M1 — Graceful shutdown is dead code
After `httpServer.ListenAndServe()` (main.go ~L365), the code builds a 5s context and calls
`httpServer.Shutdown(ctx)`. But `ListenAndServe` blocks until the server errors, and there is
**no `signal.Notify`** for SIGINT/SIGTERM. On a normal Ctrl-C / pod termination the process is
killed before the shutdown path runs, so in-flight requests are not drained.

**Recommendation:** Run `ListenAndServe` in a goroutine and block on a signal channel, then call
`Shutdown`:
```go
idle := make(chan struct{})
go func() {
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
    <-sig
    ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
    defer cancel()
    _ = httpServer.Shutdown(ctx)
    close(idle)
}()
if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
    log.Fatalf("server exited: %v", err)
}
<-idle
```

### M2 — No panic-recovery middleware
`withRequestLogging` (main.go ~L2150) wraps the mux but does not `recover()`. A nil-pointer or
malformed-policy panic in any handler crashes the whole server.

**Recommendation:** Add a recovery wrapper that logs the panic + stack and returns a generic
500, composed alongside `withRequestLogging`.

### M3 — Policy evaluation is allow-by-default
`policyAllows` (main.go ~L2426) returns `true` when no statement matches the action/resource
(`if hasRelevantStatement { return allowed } return true`). Explicit `Deny` is honored and an
explicit `Allow` works, but an empty/absent policy grants access. This is an intentional
backward-compat choice, but it is the opposite of AWS's deny-by-default.

**Recommendation:** Keep the compat behavior behind a flag, and add a
`KMS_POLICY_DEFAULT_DENY=true` mode that returns `false` when no matching `Allow` is found.
Document the default explicitly so operators aren't surprised.

### M4 — Wrapping key derivation is an unsalted single SHA-256
`deriveWrappingKey` (main.go ~L2382) computes `SHA256("go-kms-wrap-v1|" + masterKey)`. It's
deterministic with no salt and no KDF iteration/expansion. If the master key leaks, the
wrapping key is trivially reproduced.

**Recommendation:** Prefer an explicit `KMS_WRAPPING_KEY_B64` (already supported). When deriving,
use HKDF-SHA256 (`golang.org/x/crypto/hkdf`) with a fixed info label and, ideally, a configured
salt. This is defense-in-depth; the explicit-key path is already the recommended one.

### M5 — No TLS and no security headers on the admin UI
The server listens on plaintext `:8080` and sets no `X-Frame-Options`, `Content-Security-Policy`,
`X-Content-Type-Options`, or HSTS. The session cookie is set with `Secure: false`
(admin_auth.go ~L105), so it can ride over plaintext HTTP.

**Recommendation:** Terminate TLS (ingress or in-process), gate `Secure: true` on a
`KMS_UI_SECURE_COOKIES`/TLS flag, and add a small security-headers middleware for `/admin*`.

### M6 — Error responses disclose internal detail
SigV4 validation returns specific reasons ("missing X-Amz-Date header", etc.) and crypto paths
surface "encrypt failed"/"decrypt failed". This aids an attacker probing the boundary.

**Recommendation:** Return a single generic auth error (e.g. `InvalidSignatureException`) for all
SigV4 failures; log the specific reason server-side only.

### M7 — `main.go` is a 2,576-line monolith
Routing, AES-GCM crypto, policy evaluation, DB schema/DDL, both store implementations, and
helpers all live in one file.

**Recommendation:** Split into cohesive files in the same package (no API change needed):
`crypto.go`, `policy.go`, `store_db.go`, `store_memory.go`, `schema.go`, `sigv4.go`,
`handlers_kms.go`. This dramatically improves auditability of the security-sensitive parts.

---

## 5. Low-Priority / Polish

- **L1 — No AAD on key wrapping.** `wrapKeyMaterial` calls `gcm.Seal(nil, nonce, raw, nil)`.
  Binding the key ID as AAD would prevent wrapped blobs from being swapped between rows.
- **L2 — Sessions never expire.** `uiSession` records `LastSeenAt` but nothing enforces an idle
  or absolute TTL; sessions live until restart. Add a max-age + idle-timeout check in
  `requireUISession`.
- **L3 — `compareSecret` length check leaks length.** The early `len(a) != len(b)` return is a
  (minor) timing side channel. Hash both inputs first (which also fixes H2) to make comparisons
  fixed-width.
- **L4 — Audit chain proves integrity, not authenticity.** Anyone with DB write access can
  recompute the chain. Consider HMAC-ing each record with a server-held key, or periodically
  anchoring the head hash externally.
- **L5 — `inMemoryStore` returns `errUnsupported` for several Secrets ops.** Clients get a
  generic unsupported error in no-DB mode; a clearer message ("Secrets Manager requires
  KMS_DB_URL") would help.

> Note: `randomHex(24)` produces 24 random bytes (192 bits) of session entropy — this is
> adequate; it is **not** a finding. CSRF risk on admin POSTs is partially mitigated by the
> `SameSite=Lax` cookie (cross-site POSTs don't send the cookie), but adding per-form CSRF
> tokens would close the same-site gap.

---

## 6. Prioritized Action Plan

**Before any non-trusted-network exposure**
1. Implement real SigV4 verification under `KMS_SIGV4_STRICT` (H1).
2. Hash UI passwords; accept pre-hashed config values (H2).
3. Add full HTTP timeouts (H3) and fix graceful shutdown signal handling (M1).
4. Add `sync.RWMutex` to `inMemoryStore` or document single-threaded mode (H4).

**Hardening pass**
5. Panic-recovery middleware (M2).
6. `KMS_POLICY_DEFAULT_DENY` option + documented default (M3).
7. TLS guidance, `Secure` cookies, security headers (M5).
8. Generic auth/crypto error responses (M6).

**Maintainability**
9. Split `main.go` into focused files (M7).
10. HKDF for derived wrapping key (M4), AAD on wraps (L1), session TTL (L2).

**Validation**
- Run `go test -race ./...` in CI to catch H4 and any future concurrency regressions.
- Add `golangci-lint` (gosec, govet, errcheck) to the GitHub Actions workflow.

---

## 7. Suggested Doc/Process Additions

- A `SECURITY.md` stating the trust model (trusted network + Vault unseal), what is and isn't
  verified (SigV4), and supported reporting channels.
- A "Production checklist" section in `README.md` linking the items in §6.
- Keep `docs/PHASES.md` / `docs/SECRETS_MANAGER_PHASES.md` as the roadmap; reference this
  review from the AuthZ/Hardening phases so findings map to planned work.
