# AWS API compatibility

Citadel serves AWS-compatible KMS, Secrets Manager, SSM Parameter Store and STS
APIs. The KMS, Secrets Manager and SSM APIs use the AWS JSON 1.1 protocol
(`POST /`, `X-Amz-Target`). STS uses the Query protocol (`POST /`, form body).
Point an SDK at Citadel with a custom endpoint (`BaseEndpoint`,
`EndpointResolverV2`, `--endpoint-url`, `AWS_ENDPOINT_URL`).

This matrix is checked by `internal/server/awscompat_sdk*_test.go`, which drive
Citadel with the real `aws-sdk-go-v2` clients. A second test replays the
requests that Vault's `awskms` seal and External Secrets Operator send.

**Legend:** ✅ supported · 🟡 partial (see the notes) · ❌ not supported (the API
returns `InvalidAction`)

## Behaviour common to all services

- **Authentication:** SigV4 only. Requests can be signed with three kinds of
  credentials: the static deployment key, an IAM-style access key, or STS
  temporary credentials (which need their session token). The canonical query
  and headers follow the AWS rules: RFC 3986 encoding, sorted, and a signed
  `Content-Length`. SigV4A and presigned query-string auth are not supported.
- **Request decoding:** members Citadel does not model are ignored, as in AWS,
  so newer SDK and Terraform versions keep working. The native `/v1` API keeps
  strict decoding.
- **Responses:** every response has an `x-amzn-RequestId` header. JSON error
  bodies include `__type`, `message` and `RequestId`, and set
  `X-Amzn-ErrorType`. Timestamps are epoch seconds.
- **Internal errors:** 5xx responses use the service's own code:
  `KMSInternalException` (KMS), `InternalServiceError` (Secrets Manager),
  `InternalServerError` (SSM) and `InternalFailure` (STS). They carry a fixed
  message. The underlying error is logged with the request ID and never
  returned to the client.
- **Pagination:** markers and tokens are opaque. A forged or stale marker is
  rejected: `ValidationException` (KMS), `InvalidNextTokenException` (Secrets
  Manager) or `InvalidNextToken` (SSM). Listings page in the store and do not
  load every row.
- **Tenancy:** every resource is scoped to the caller's account.

## KMS (`TrentService`)

| Action | Status | Notes |
|---|---|---|
| CreateKey | 🟡 | Supported: `SYMMETRIC_DEFAULT` with `ENCRYPT_DECRYPT`; RSA_2048/3072/4096 and ECC_NIST_P256/P384 with `SIGN_VERIFY`; `Policy`. Returns `UnsupportedOperationException` for: other origins, multi-Region keys, custom key stores, HMAC, ML-DSA, SM2, secp256k1 and P-521. RSA encryption keys and `Tags` belong to the KMS work stream. |
| DescribeKey | ✅ | Accepts a key ID, key ARN, alias name or alias ARN (the same applies to every `KeyId`). Without a `KeyId` it describes the account's default key (a Citadel extension). |
| ListKeys | ✅ | `Limit` from 1 to 1000. Paged in the store. |
| Encrypt | 🟡 | `SYMMETRIC_DEFAULT` only. Supports `EncryptionContext`, `GrantTokens` (accepted, not evaluated) and `DryRun`. Plaintext limit is 4 KiB. Returns `KeyId` as an ARN. |
| Decrypt | 🟡 | `SYMMETRIC_DEFAULT` only. A `KeyId` that doesn't match the ciphertext's key returns `IncorrectKeyException`. `Recipient` (Nitro attestation) is rejected. |
| ReEncrypt | ✅ | Symmetric keys. Checks `kms:ReEncryptFrom` on the source key and `kms:ReEncryptTo` on the destination key. |
| GenerateDataKey | ✅ | `KeySpec` AES_256 or AES_128, or `NumberOfBytes` from 1 to 1024. Supports `DryRun`. `Recipient` is rejected. |
| GenerateDataKeyWithoutPlaintext | ✅ | |
| GenerateDataKeyPair | 🟡 | FIPS 140-3 approved specs only: RSA_2048/3072/4096 and ECC_NIST_P256/P384. Other specs return `ValidationException`. |
| GenerateDataKeyPairWithoutPlaintext | 🟡 | Same specs as GenerateDataKeyPair. |
| Sign / Verify | ✅ | RSASSA_PKCS1_V1_5 and RSASSA_PSS with SHA-256/384/512, ECDSA_SHA_256 and ECDSA_SHA_384. `MessageType` RAW or DIGEST. An invalid signature returns `KMSInvalidSignatureException`, as in AWS. |
| GetPublicKey | ✅ | DER `SubjectPublicKeyInfo`. |
| CreateAlias / UpdateAlias / DeleteAlias | ✅ | `alias/aws/*` returns `NotAuthorizedException`. `alias/default` is Citadel's immutable per-account alias. A duplicate alias returns `AlreadyExistsException`. |
| ListAliases | ✅ | Supports the `KeyId` filter and pagination. Returns `AliasArn`. |
| EnableKey / DisableKey | ✅ | Pending-deletion keys return `KMSInvalidStateException`. |
| ScheduleKeyDeletion / CancelKeyDeletion | ✅ | Window of 7 to 30 days. Cancelling leaves the key `Disabled`, as in AWS. |
| GetKeyPolicy / PutKeyPolicy | ✅ | Policy name `default`. |
| CreateGrant / ListGrants / RevokeGrant / RetireGrant | 🟡 | Owned by the KMS work stream. `ListGrants` timestamps aren't epoch seconds yet. |
| Key rotation, TagResource, UntagResource, ListResourceTags | ❌ | Owned by the KMS work stream. |
| GenerateMac, VerifyMac, DeriveSharedSecret, GenerateRandom, ImportKeyMaterial, custom key stores, multi-Region | ❌ | |

**Error codes:**

| Error | When it's returned |
|---|---|
| `NotFoundException` | The key or alias is missing. |
| `DisabledException` | The key is disabled. |
| `KMSInvalidStateException` | The key is pending deletion, or the operation conflicts with the key's state. |
| `InvalidKeyUsageException` | The key usage or algorithm doesn't match the operation. |
| `InvalidCiphertextException` | The ciphertext can't be decrypted. |
| `IncorrectKeyException` | The `KeyId` doesn't match the ciphertext's key. |
| `AccessDeniedException` | The key policy denies the action. |
| `MalformedPolicyDocumentException` | The policy document isn't valid. |
| `ValidationException` | A request member is invalid. |
| `DryRunOperationException` | The request would succeed, but `DryRun` is set. |

## Secrets Manager (`secretsmanager`)

| Action | Status | Notes |
|---|---|---|
| CreateSecret | 🟡 | Supports `SecretString`/`SecretBinary`, `KmsKeyId`, `Description`, `ClientRequestToken` and `Tags` (up to 50). `AddReplicaRegions` is rejected. A name that shadows a folder projection is rejected. |
| DescribeSecret | ✅ | Includes `Tags`, `VersionIdsToStages` and rotation fields (`RotationRules`, `NextRotationDate`, `LastRotatedDate`). |
| GetSecretValue | ✅ | By name or ARN, with `VersionId` or `VersionStage`. Folder JSON projection is a Citadel extension. |
| BatchGetSecretValue | ✅ | `SecretIdList` (up to 20) or `Filters` with `MaxResults`/`NextToken`. Errors for individual secrets go in `Errors`. |
| PutSecretValue / UpdateSecret | ✅ | `VersionStages` on PutSecretValue isn't honoured: new versions become `AWSCURRENT`. |
| ListSecretVersionIds | ✅ | |
| UpdateSecretVersionStage | ✅ | |
| ListSecrets | 🟡 | Filters: `name`, `description`, `tag-key`, `tag-value`, `all`, and `!` negation (prefix match, case-insensitive). Supports `IncludePlannedDeletion` and store-level pagination. Results are ordered by name: `SortOrder` `asc` (default) or `desc` reverses it, `SortBy` may only be `name` (other values are rejected with `InvalidParameterException`, as Citadel does not order by date). A `NextToken` is only valid with the `SortOrder` that produced it. `primary-region` and `owning-service` are rejected. |
| DeleteSecret / RestoreSecret | ✅ | Recovery window of 7 to 30 days, or `ForceDeleteWithoutRecovery`. |
| TagResource / UntagResource | ✅ | |
| GetResourcePolicy / PutResourcePolicy / ValidateResourcePolicy | 🟡 | Policies are evaluated by Citadel's IAM subset. `BlockPublicPolicy` is ignored. |
| DeleteResourcePolicy | ✅ | Removes the secret's policy; it falls back to the default account policy. Returns `ARN` and `Name`. |
| RotateSecret / CancelRotateSecret | 🟡 | `RotationRules` `AutomaticallyAfterDays`, `ScheduleExpression` (`rate()` and `cron()`) and `Duration`, with AWS's window semantics. Lambda functions can't run: a `RotationLambdaARN` of the form `arn:citadel:rotator:<region>:<account>:<type>[/<config-id>]` selects a built-in rotator (`random`, `postgresql`, `webhook`) that runs the four rotation steps with `AWSPENDING`/`AWSCURRENT`/`AWSPREVIOUS`, in the background, with `VersionId` as its token; a real Lambda ARN is recorded but nothing runs (schedule only). An unfinished rotation returns `InvalidRequestException` and is reattempted. Built-in rotators are refused (`AccessDeniedException`) in environments that require approval. `CancelRotateSecret` keeps an unfinished `AWSPENDING` version, as AWS does. See [rotation.md](rotation.md). |
| GetRandomPassword | ✅ | Uses `crypto/rand` with AWS character classes and defaults (32 characters, `RequireEachIncludedType`). |
| Replication (ReplicateSecretToRegions etc.), StopReplicationToReplica | ❌ | |

**Error codes:**

| Error | When it's returned |
|---|---|
| `ResourceNotFoundException` | The secret or the requested version is missing. |
| `ResourceExistsException` | A secret with that name already exists. |
| `InvalidRequestException` | The secret is marked for deletion, or the request conflicts with its state. |
| `InvalidParameterException` | A request member is invalid. |
| `InvalidNextTokenException` | The `NextToken` isn't valid. |
| `AccessDeniedException` | The resource policy denies the action. |

## SSM Parameter Store (`AmazonSSM`)

| Action | Status | Notes |
|---|---|---|
| PutParameter | 🟡 | Types `String`, `StringList` and `SecureString`. Supports `KeyId`, `Overwrite`, `Tags` (rejected together with `Overwrite`, as in AWS), `AllowedPattern` (Go RE2 syntax), `Description` and `Tier` (`Intelligent-Tiering` is treated as Standard). `DataType` is `text` only. `Policies` is rejected. Values are limited to 8 KiB. |
| GetParameter | ✅ | Supports `WithDecryption`, `name:version` and `name:label` selectors, and ARNs as names. |
| GetParameters | ✅ | Up to 10 names. Missing names go in `InvalidParameters`. |
| GetParametersByPath | ✅ | Supports `Recursive`, `Path` `"/"`, and `MaxResults` up to 10 with `NextToken`, paged in the store. `ParameterFilters` supports `Type`, `KeyId` and `Label`. |
| DescribeParameters | ✅ | `ParameterFilters` supports `Name` (Equals, BeginsWith or Contains), `Type`, `KeyId`, `Path` (Recursive or OneLevel, pushed down to the store), `Tier`, `DataType` and `tag:<key>`. Legacy `Filters` also work. `MaxResults` up to 50. `Shared` returns nothing. |
| DeleteParameter / DeleteParameters | ✅ | Up to 10 names. |
| GetParameterHistory | ✅ | `MaxResults`/`NextToken`. |
| LabelParameterVersion | ✅ | Labels that break AWS's naming rules go in `InvalidLabels`. |
| UnlabelParameterVersion | ✅ | `ParameterVersion` is required. Labels the version doesn't carry go in `InvalidLabels`; detached ones in `RemovedLabels`. |
| AddTagsToResource / RemoveTagsFromResource / ListTagsForResource | 🟡 | Only `ResourceType` `Parameter` is supported. |
| Parameter policies, advanced-tier sharing | ❌ | |

**Error codes:** `ParameterNotFound`, `ParameterAlreadyExists`,
`ParameterVersionNotFound`, `ParameterPatternMismatchException`,
`InvalidKeyId`, `InvalidResourceId`, `InvalidResourceType`, `InvalidNextToken`,
`HierarchyLevelLimitExceededException` and `ValidationException`.

**Parameter names** follow AWS's documented rules. Every operation refuses a
`Name` longer than 2048 characters or deeper than 15 levels. `PutParameter`
also refuses names beginning with `aws` or `ssm` in any case (for a
hierarchy, its first level: `/aws/x` and `SSM-config` are refused,
`/app/aws` is not), and names whose full ARN
(`arn:aws:ssm:<region>:<account>:parameter/<name>`) is longer than 1011
characters. Parameters created before 2.0.3 with such names can still be read,
overwritten through the console's edit, and deleted.

## STS (Query protocol)

| Action | Status | Notes |
|---|---|---|
| GetCallerIdentity | ✅ | |
| AssumeRole | 🟡 | Uses Citadel trust policies of type `account`. `DurationSeconds` is clamped to 900 seconds up to the role's maximum. Session policies, tags, `ExternalId` and MFA are ignored. |
| AssumeRoleWithWebIdentity | 🟡 | Uses trust policies of type `oidc`. The issuer must be registered, and the audience and subject must match. Tokens are verified against the issuer's JWKS (RS256/384/512, ES256/384/512). Works with `stscreds.WebIdentityRoleProvider` (IRSA-style). |
| AssumeRoleWithSAML, GetSessionToken, GetFederationToken, DecodeAuthorizationMessage, GetAccessKeyInfo | ❌ | |

## ACM and ACM PCA

These are served on the same endpoint (AWS JSON 1.1, `X-Amz-Target`
`CertificateManager.*` and `ACMPrivateCA.*`). This section lists the
behaviours the aws-sdk-go-v2 harness covers; it is not a full matrix.

| Action | Status | Notes |
|---|---|---|
| ACM RequestCertificate `IdempotencyToken` | ✅ | 1 to 32 word characters. The same token with the same `DomainName`, `SubjectAlternativeNames`, `CertificateAuthorityArn` and `KeyAlgorithm` within one hour returns the first request's ARN without issuing again. Reusing a token with different parameters returns `InvalidParameterException` (ACM documents no dedicated error for this). Tokens are per account and kept in the store, so they hold across replicas. A failed request frees its token. |
| ACM ImportCertificate `IdempotencyToken` | 🟡 | Citadel extension: AWS's ImportCertificate has no token, so SDKs can't send it. Same rules as RequestCertificate; the parameters compared are the certificate, its chain and `CertificateArn`. |
| ACM PCA CreateCertificateAuthority (`SUBORDINATE`) | ✅ | As in AWS, the CA is created in `PENDING_CERTIFICATE` with a new key. `GetCertificateAuthorityCertificate` returns `InvalidStateException` until a certificate is imported. |
| ACM PCA GetCertificateAuthorityCsr | ✅ | Returns the PEM CSR of a CA created as `SUBORDINATE` through this API (`InvalidStateException` for other CAs). |
| ACM PCA IssueCertificate with `SubordinateCACertificate_PathLen{0,1,2,3}/V1` | ✅ | Signs a CA certificate with that path length. The path length must fit below the issuing CA's constraint. These certificates can't be renewed through the console's leaf renewal. |
| ACM PCA ImportCertificateAuthorityCertificate | 🟡 | Activates a `PENDING_CERTIFICATE` CA. The certificate must be a CA certificate for the CA's key and must chain through `CertificateChain` to a self-signed root. When a Citadel CA in the same account signed it, that CA becomes the parent, and chains returned later run up to the root. An externally signed CA is linked to no parent, so later chains stop at the subordinate CA. Re-importing on an `ACTIVE` CA (renewing a CA certificate) isn't supported. |
| ACM PCA UpdateCertificateAuthority | 🟡 | `Status` `ACTIVE` or `DISABLED`. `RevocationConfiguration` is accepted and ignored. An expired CA can't be enabled. |
| ACM PCA DeleteCertificateAuthority | 🟡 | As AWS: the CA must be `DISABLED` (or expired, or never activated); it becomes `DELETED` with `RestorableUntil` after `PermanentDeletionTimeInDays` (7–30, default 30), then is purged with its certificates. Citadel also refuses (`InvalidStateException`) while the CA has issued certificates or subordinate CAs that are still valid: revoke them first. |
| ACM PCA RestoreCertificateAuthority | 🟡 | Within the window. The CA returns to `DISABLED` (AWS restores a CA deleted while `PENDING_CERTIFICATE` to that state). |

aws-sdk-go-v2 `service/acmpca` v1.57 and later uses the Smithy RPCv2 CBOR
protocol by default, which Citadel doesn't serve. Select AWS JSON 1.1 on the
client:

```go
acmpca.NewFromConfig(cfg, func(o *acmpca.Options) {
	o.Protocol = awsjson.New11(schemas.ACMPrivateCA) // smithy-go transport/http/protocol/awsjson, acmpca/schemas
})
```

## Known gaps and follow-ups

- The memory store doesn't scope SSM parameters by account; the Postgres store
  does.
- Grant timestamps and grant tokens aren't evaluated yet (KMS work stream).
- ACM PCA over Smithy RPCv2 CBOR (the default of recent aws-sdk-go-v2
  `acmpca` releases) isn't served; clients must select AWS JSON 1.1.
