# Phase A Compatibility Matrix

This tracks the current Phase A AWS KMS compatibility surface for the highest-frequency go-kms operations.

## Core Operations

| Operation | Status | Notes | Validation |
| --- | --- | --- | --- |
| `TrentService.Encrypt` | Pass | AWS-style JSON envelope, key lookup, disabled-key handling, base64 validation | `TestEncryptDecryptRoundTrip`, `TestEncryptRejectsUnknownKeyID` |
| `TrentService.Decrypt` | Pass | Supports key-ID header blobs plus legacy blob fallback for Vault continuity | `TestEncryptDecryptRoundTrip`, `TestDecryptLegacyBlobCompatibility`, `TestDecodeCipherBlobLegacyFallbackOnMalformedHeader` |
| `TrentService.DescribeKey` | Pass | Returns AWS-like `KeyMetadata` payload | Covered by handler behavior and shared metadata path |
| `TrentService.ListKeys` | Pass | Stable ordering, `Limit`, `Marker`, `NextMarker`, `Truncated`, validation for invalid markers | `TestListKeysPagination`, `TestListKeysRejectsInvalidMarker`, `TestListKeysAllowsEmptyBody` |
| `TrentService.ListAliases` | Pass | Stable ordering, `Limit`, `Marker`, `NextMarker`, `Truncated` | `TestListAliasesPagination` |
| `TrentService.GetKeyPolicy` | Pass | Defaults missing `PolicyName` to `default` and returns persisted policy JSON | `TestGetKeyPolicyReturnsDefaultPolicy`, `TestPutAndGetKeyPolicy` |

## Compatibility Suite Result

- Defined Phase A suite: 9 core compatibility checks.
- Current pass count: 9/9.
- Current pass rate: 100 percent.
- Vault continuity coverage remains in decrypt round-trip and legacy blob compatibility tests.

## Remaining Gaps Beyond Phase A

| Area | Status | Gap |
| --- | --- | --- |
| AWS response fixture parity | Partial | Core semantics are locked down by handler-level compatibility tests, but there is no recorded AWS fixture corpus yet |
| Compatibility suite breadth | Partial | Phase A covers the high-frequency core paths only; future list and grant APIs need their own suites |
| Paging coverage | Complete for current list APIs | `ListKeys` and `ListAliases` are paginated; future list APIs will need the same semantics when added |
| SigV4 verification | Not started | Strict header presence exists, but cryptographic signature verification is still out of scope for Phase A |

## Exit Criteria Tracking

- Core handler tests pass for encrypt/decrypt/list/policy flows.
- List operations expose deterministic paging semantics.
- Vault legacy decrypt compatibility remains covered.
- The defined Phase A compatibility suite passes above the `>=95%` threshold.
- Fixture-based response comparison remains useful follow-up work, but is no longer a blocker for Phase A completion.