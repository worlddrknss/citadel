// Public request and response types. Wire shapes come straight from the
// types generated from docs/openapi.yaml (src/generated/openapi.ts), so a
// spec change that breaks a shape breaks the build.
import type { components } from './generated/openapi.js';

type Schemas = components['schemas'];

/** Generated OpenAPI component schemas, for operations the client doesn't wrap. */
export type { components, operations, paths } from './generated/openapi.js';

export type ApiError = Schemas['Error'];
export type Tag = Schemas['Tag'];
export type Me = Schemas['Me'];
export type CreatedAccessKey = Schemas['CreatedAccessKey'];

export type Project = Schemas['Project'];
export type SecretItem = Schemas['SecretItem'];
export type SecretListing = Schemas['SecretListing'];
export type PutSecretResult = Schemas['PutSecretResult'];
export type SecretValue = Schemas['SecretValue'];
export type DeleteSecretResult = Schemas['DeleteSecretResult'];
export type SecretVersion = Schemas['SecretVersion'];
export type SecretVersionList = Schemas['SecretVersionList'];

export type Parameter = Schemas['Parameter'];
export type ParameterList = Schemas['ParameterList'];
export type ParameterValue = Schemas['ParameterValue'];
export type ParameterVersion = Schemas['ParameterVersion'];
export type ParameterHistory = Schemas['ParameterHistory'];
export type PutParameterInput = Schemas['ParameterPutRequest'];

export type KmsKey = Schemas['KmsKey'];
export type KmsEncryptResponse = Schemas['KmsEncryptResponse'];
export type KmsDecryptResponse = Schemas['KmsDecryptResponse'];
export type EncryptionAlgorithm = NonNullable<Schemas['KmsEncryptRequest']['encryptionAlgorithm']>;

export type CertificateSummary = Schemas['CertificateSummary'];
export type IssueCertificateInput = Schemas['CertificateIssueRequest'];
export type IssueCertificateResult = Schemas['CertificateIssueResponse'];
export type IssueGeneratedCertificateInput = Schemas['CertificateGenerateRequest'];
export type GeneratedCertificate = Schemas['CertificateGenerateResponse'];

export type WorkloadTokenInput = Schemas['WorkloadTokenRequest'];
export type WorkloadToken = Schemas['WorkloadToken'];

/** Addresses a folder: project, environment and an optional folder path. */
export interface FolderRef {
  project: string;
  env: string;
  /** Folder path such as `api/db`; omit (or `/`) for the environment root. */
  path?: string;
}

/** Addresses one secret. */
export interface SecretRef extends FolderRef {
  key: string;
}

export interface GetSecretInput extends SecretRef {
  /** A specific version ID instead of the current one. */
  versionId?: string;
  /** A version stage such as `AWSPREVIOUS`. */
  versionStage?: string;
  /** Resolve `${...}` references to other secrets. */
  resolve?: boolean;
}

export interface PutSecretInput extends SecretRef {
  value: string;
  /** KMS key to encrypt with; defaults to the account's default key. */
  kmsKeyId?: string;
}

export interface DeleteSecretInput extends SecretRef {
  /** Delete now instead of after the recovery window. */
  force?: boolean;
  /** Recovery window in days (default: the server's). */
  recoveryWindowDays?: number;
}

/** Plaintext accepted by encrypt: a UTF-8 string or raw bytes. */
export type Plaintext = string | Uint8Array;

export interface EncryptInput {
  /** Key ID, key ARN, alias name (`alias/...`) or alias ARN. */
  keyId: string;
  plaintext: Plaintext;
  encryptionContext?: Record<string, string>;
  encryptionAlgorithm?: EncryptionAlgorithm;
}

export interface EncryptResult {
  keyId: string;
  /** Base64 ciphertext, as stored or sent to decrypt. */
  ciphertextBlob: string;
  encryptionAlgorithm: string;
}

export interface DecryptInput {
  keyId: string;
  /** Base64 ciphertext returned by encrypt. */
  ciphertextBlob: string;
  encryptionContext?: Record<string, string>;
  encryptionAlgorithm?: EncryptionAlgorithm;
}

export interface DecryptResult {
  keyId: string;
  plaintext: Uint8Array;
  encryptionAlgorithm: string;
}
