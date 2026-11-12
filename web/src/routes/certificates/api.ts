// Page-local client for certificate features the shared $lib/api client does
// not cover yet. Every call here targets a contract documented in the console
// redesign report; the server rejects unknown JSON fields, so optional new
// fields are only sent when they carry a value.

import { req, api, type Certificate, type CertificateDetail } from '$lib/api';

/**
 * A row of GET /v1/certificates. The extra fields are part of the extended
 * list contract; until the server sends them the page fills commonName,
 * serial and revokedAt from the detail endpoint.
 */
export interface CertRow extends Certificate {
  commonName?: string;
  serial?: string;
  keyAlgorithm?: string;
  parentCaId?: string;
  revokedAt?: string;
}

export type KeyAlgorithm = 'EC_prime256v1' | 'EC_secp384r1' | 'RSA_2048' | 'RSA_3072' | 'RSA_4096';
export type Template = 'server' | 'client';

export const certApi = {
  list: () => api.certificates() as Promise<{ certificates: CertRow[] }>,
  detail: (source: string, id: string) => api.certificateDetail(source, id),

  createCA: (body: {
    caType: 'ROOT' | 'SUBORDINATE';
    keyAlgorithm: KeyAlgorithm;
    commonName: string;
    organization?: string;
    country?: string;
    parentCaId?: string;
  }) => {
    const payload: Record<string, string> = {
      caType: body.caType,
      keyAlgorithm: body.keyAlgorithm,
      commonName: body.commonName
    };
    if (body.organization) payload.organization = body.organization;
    if (body.country) payload.country = body.country;
    if (body.caType === 'SUBORDINATE' && body.parentCaId) payload.parentCaId = body.parentCaId;
    return req<{ caId: string; created: boolean }>('/v1/certificates/authorities', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  },

  /** Signs a pasted CSR. `template` is sent only when it isn't the default. */
  issueFromCsr: (body: {
    caId: string;
    csrPem: string;
    validityDays: number;
    commonName: string;
    sans: string[];
    template: Template;
  }) => {
    const payload: Record<string, string> = {
      caArn: body.caId,
      csrPem: body.csrPem,
      validityDays: String(body.validityDays)
    };
    if (body.commonName) payload.overrideCommonName = body.commonName;
    if (body.sans.length) payload.sanNames = body.sans.join(',');
    if (body.template !== 'server') payload.template = body.template;
    return req<{ issued: boolean; certId?: string }>('/v1/certificates/issue', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  },

  /** Generates the key pair and CSR inside Citadel; the private key is returned once. */
  issueWithGeneratedKey: (body: {
    caId: string;
    commonName: string;
    sans: string[];
    template: Template;
    keyAlgorithm: KeyAlgorithm;
    validityDays: number;
  }) =>
    req<{ certId: string; certificatePem: string; chainPem: string; privateKeyPem: string }>(
      '/v1/certificates/issue/generate',
      { method: 'POST', body: JSON.stringify(body) }
    ),

  // ACME server: External Account Binding keys for the current account.
  eabKeys: () => req<{ keys: EabKey[] }>('/v1/certificates/acme/eab'),
  createEabKey: (label: string) =>
    req<{ kid: string; hmacKey: string; label: string; createdAt: string }>('/v1/certificates/acme/eab', {
      method: 'POST',
      body: JSON.stringify({ label })
    }),
  revokeEabKey: (kid: string) =>
    req<{ kid: string; revoked: boolean }>(`/v1/certificates/acme/eab?${new URLSearchParams({ kid })}`, {
      method: 'DELETE'
    })
};

export interface EabKey {
  kid: string;
  label: string;
  status: 'unused' | 'bound' | 'revoked';
  createdAt: string;
  createdBy: string;
  boundAt?: string;
  acmeAccountId?: string;
}

export type { Certificate, CertificateDetail };
