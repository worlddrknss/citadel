# AWS Private CA + Certificate Manager Compatibility Supplement

This document extends the Citadel (go-kms) roadmap with an AWS Private CA
(`acm-pca`) and Certificate Manager (`acm`) compatible service plan. It records
the key architectural decision that **the CA signs through Citadel's own KMS
engine**, and the phased plan that follows from it.

> Naming: the product is **Citadel**. The Go module path
> (`github.com/worlddrknss/go-kms`) and `KMS_*` environment variables are
> retained for deployment backward compatibility.

## Goal

Deliver AWS `acm-pca` and `acm` compatible APIs and a control plane that stays
self-hostable, reuses Citadel's existing security primitives (key wrapping,
policy engine, audit chain, RBAC, admin UI), and lets internal systems obtain
certificates the same way they already speak to KMS and Secrets Manager.

## Core Architectural Decision — sign through the KMS engine

AWS Private CA stores each CA's private key inside KMS and performs issuance by
calling KMS to sign. Citadel mirrors this exactly: a CA's signing key is a
Citadel KMS **asymmetric key**, and certificate/CRL signing is an internal
`Sign` operation. The CA layer never sees raw private key bytes.

Consequences and benefits:

1. **Prerequisite:** the KMS engine is symmetric-only today
   (`kmsKey.MasterKeyRaw` is a 32-byte AES key; only Encrypt/Decrypt exist).
   Signing through KMS therefore requires adding **asymmetric key support**
   first (Phase 0). This is a legitimate standalone KMS feature, not just CA
   plumbing.
2. **Unified custody:** CA private keys are wrapped with the existing
   HKDF-SHA256 + AES-256-GCM + key-ID-AAD scheme — no second cryptographic root.
3. **HSM story for free:** the `Sign` operation is an interface seam. A software
   signer ships first; a PKCS#11 / cloud-KMS / HSM-backed signer can replace it
   later behind the same call with no CA-layer changes.
4. **Dogfooding + auditability:** every signature flows through KMS authZ and
   the existing HMAC audit chain.

## Design Principles

1. Reuse shared platform pieces: SigV4 handling, tenant identity, `policyAllows`
   authorization, the HMAC audit chain, the admin UI shell, and DB migrations.
2. Keep KMS, Secrets Manager, and CA protocol surfaces distinct even when they
   share internals; all dispatch through the existing `X-Amz-Target` switch in
   `handleKMS`.
3. Preserve AWS behavioral compatibility first: ARN shapes, field names, state
   machines (`acm-pca` CA states, certificate statuses).
4. Private keys never leave the KMS boundary; the CA holds only a key reference.
5. Treat revocation (CRL/OCSP) as a first-class correctness requirement, not an
   optional extra.

## Recommended Execution Order

The dependency chain is explicit:

1. **Phase 0 (Asymmetric KMS)** must land before any CA work — it provides the
   signing primitive.
2. **Phase A (CA core)** depends on Phase 0 and on the existing wrapping/policy/
   audit code.
3. **Phase B (ACM façade)** is a thin layer over Phase A.
4. **Phase C (Revocation)** can begin once Phase A issues certificates; CRLs are
   themselves signed via KMS `Sign`.
5. **Phase D (ACME)** layers on top of the Phase A CA and is the highest
   day-to-day payoff for the `infrastructure` repo (cert-manager/Caddy/Traefik).

## Phase 0 — Asymmetric KMS (prerequisite)

Add AWS KMS asymmetric-key compatibility to the engine.

New protocol surface (`TrentService.*`):

- `CreateKey` extended with `KeyUsage` (`ENCRYPT_DECRYPT` | `SIGN_VERIFY`) and
  `KeySpec` (`RSA_2048`, `RSA_3072`, `RSA_4096`, `ECC_NIST_P256`,
  `ECC_NIST_P384`).
- `Sign` — `(KeyId, Message | MessageType=DIGEST, SigningAlgorithm)` →
  `Signature`.
- `Verify` — `(KeyId, Message, Signature, SigningAlgorithm)` → `SignatureValid`.
- `GetPublicKey` — returns DER `SubjectPublicKeyInfo` + supported algorithms.

Storage / model changes:

- Extend `kmsKey` with `KeyUsage`, `KeySpec`, and wrapped asymmetric material.
  Asymmetric private keys are PKCS#8 DER, wrapped with the existing
  `wrapKeyMaterial` (key ID as AAD) — reuse the same column/representation as
  symmetric material where practical, or add `kms_keys.key_spec` /
  `kms_keys.key_usage` columns plus a wrapped-private-key column.
- Public key is stored alongside (unwrapped) for `GetPublicKey`/`Verify`.

Signer seam:

- Define an internal `signer` abstraction (`Sign(digest, alg) ([]byte, error)`,
  `Public() crypto.PublicKey`). The default implementation loads + unwraps the
  KMS private key and uses `crypto/rsa` / `crypto/ecdsa`. Future HSM/PKCS#11
  signers implement the same interface.

## Phase A — Private CA core (`acm-pca`)

Priority operations:

- `acm-pca.CreateCertificateAuthority` — generates (or references) a Phase-0
  `SIGN_VERIFY` key as the CA key; builds the CA certificate (self-signed for a
  ROOT, or a CSR for a SUBORDINATE) via internal `Sign`.
- `acm-pca.GetCertificateAuthorityCertificate`
- `acm-pca.GetCertificateAuthorityCsr` (subordinate enrollment)
- `acm-pca.ImportCertificateAuthorityCertificate` (install signed subordinate)
- `acm-pca.IssueCertificate` — validate CSR, apply issuance template/constraints,
  sign leaf via KMS `Sign`, persist.
- `acm-pca.GetCertificate`
- `acm-pca.RevokeCertificate`
- `acm-pca.DescribeCertificateAuthority`, `acm-pca.ListCertificateAuthorities`,
  `acm-pca.UpdateCertificateAuthority`, `acm-pca.DeleteCertificateAuthority`

CA types and lifecycle:

- ROOT and SUBORDINATE CAs; states mirroring AWS
  (`CREATING`, `PENDING_CERTIFICATE`, `ACTIVE`, `DISABLED`, `DELETED`).
- Validity handling: `NotBefore`/`NotAfter`, path-length constraints,
  basic constraints, key usage / extended key usage, name constraints.

Authorization & audit (reuse):

- `authorizeCertificateAction(ctx, r, ca, "acm-pca:IssueCertificate")` following
  the `authorizeKeyAction` / `authorizeSecretAction` pattern, evaluating the CA
  resource policy with `policyAllows` and the CA ARN as the resource.
- Record `auditEvent{Action: "acm-pca.IssueCertificate", KeyID: caID, ...}` on
  the existing HMAC audit chain for every issuance and revocation.

## Phase B — Certificate Manager façade (`acm`)

A thin inventory/lifecycle layer over Phase A:

- `acm.RequestCertificate`, `acm.DescribeCertificate`, `acm.ListCertificates`,
  `acm.GetCertificate`, `acm.ExportCertificate`, `acm.DeleteCertificate`,
  `acm.RenewCertificate`, `acm.AddTagsToCertificate`,
  `acm.RemoveTagsFromCertificate`.
- Maps AWS ACM semantics (statuses, renewal eligibility) onto Phase-A records.

## Phase C — Revocation

- **CRL first:** periodically (and on revoke) generate a CRL, **sign it via KMS
  `Sign`**, publish at a stable endpoint (e.g. `GET /crl/<ca-id>.crl`), and
  reference it via CRL Distribution Points in issued certs.
- **OCSP later:** signed OCSP responder if pull-based, low-latency revocation is
  needed.
- Revocation reasons and `RevokeCertificate` semantics follow AWS.

## Phase D — ACME server (RFC 8555)

- Implement the `/acme/*` directory: new-nonce, new-account, new-order,
  authorization, challenge (`http-01` and/or `dns-01`), finalize, certificate.
- Back issuance with the Phase-A CA so cert-manager, Caddy, and Traefik can
  auto-enroll against Citadel with no AWS SDK calls.
- This is the primary integration payoff for the `infrastructure` repo.

## Proposed Storage Model

New tables alongside `kms_*` / `sm_*`:

- `pca_certificate_authorities`: `ca_id`, `arn`, `type` (ROOT|SUBORDINATE),
  `kms_key_id` (Phase-0 signing key), `subject`, `state`, `ca_cert_blob`,
  `path_length`, `not_before`, `not_after`, `tenant`, timestamps.
- `pca_certificates`: `cert_id`, `ca_id`, `serial`, `csr_blob`, `cert_blob`,
  `status` (ISSUED|REVOKED|EXPIRED), `not_before`, `not_after`,
  `revoked_at`, `revocation_reason`, `template`, timestamps.
- `pca_ca_policies`: resource policies per CA (mirrors `kms_key_policies` /
  `sm_secret_policies`), evaluated by `policyAllows`.
- `pca_crl_state`: per-CA CRL number, last-generated time, next-update, signed
  CRL blob (or pointer).
- (Phase D) `acme_accounts`, `acme_orders`, `acme_authorizations`,
  `acme_challenges`.

Certificate/CA audit reuses the existing `kms_audit_events` chain (shared
actor/result/hash columns) rather than a separate table, keeping one
tamper-evident log across KMS, Secrets, and CA.

## Compatibility Guardrails

1. Preserve AWS naming, ARN shape, field names, CA states, and certificate
   statuses for the supported API set.
2. Serial numbers are unique, non-sequential positive integers per CA.
3. Honor and validate basic constraints, key usage / EKU, path length, and name
   constraints on issuance.
4. CRLs and OCSP responses are signed by the CA key via KMS `Sign`.
5. Private keys never appear in any API response (only certs, CSRs, public keys).

## Admin Console

- New `handleCertificatesAdmin` in `admin_certificates.go`, registered at
  `mux.HandleFunc("/admin/certificates", s.handleCertificatesAdmin)`, mirroring
  `handleSecretsAdmin`.
- Embedded template `templates/admin_certificates.html` with the existing
  sidebar shell and a Certificates tab next to KMS / Secrets / Audit.
- Role-gated via `requireUISession` (viewer/editor/admin) with tenant scoping.
- Operator workflows: create CA, view CA chain, issue from CSR, revoke, view CRL
  status, browse issued certs.

## Security Notes

- CA signing keys inherit Citadel's wrapping (HKDF + AES-GCM + AAD); set
  `KMS_POLICY_DEFAULT_DENY=true` so issuance requires an explicit allow.
- All issuance/revocation events land on the HMAC audit chain
  (`KMS_AUDIT_HMAC_KEY_B64`).
- The signer seam is the planned integration point for HSM-backed CA roots.
- See `docs/SECURITY.md` for the overall trust model and production checklist.

## Open Items / Future Decisions

- Issuance templates: fixed set (AWS-style `EndEntityCertificate/V1`, etc.) vs.
  policy-driven custom templates.
- ACME challenge types to support first (`http-01` vs `dns-01`) given the
  cluster ingress/DNS setup in the `infrastructure` repo.
- Whether `acm` and `acm-pca` share one tenant/ARN namespace with KMS or get
  distinct ARN services.
