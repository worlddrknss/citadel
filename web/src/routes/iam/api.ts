// Page-local client for IAM edits the shared #lib/api client lacks. Targets
// the contracts documented in the console redesign report.

import { req, type TrustPolicy } from '#lib/api.ts';

export const iamApi = {
  updateRole: (body: { roleName: string; description: string; trust: TrustPolicy; maxSessionSeconds: number }) =>
    req<{ roleArn: string; updated: boolean }>('/v1/iam/roles/update', { method: 'POST', body: JSON.stringify(body) }),
  updateOIDCProvider: (providerArn: string, clientIds: string[]) =>
    req<{ providerArn: string; updated: boolean }>('/v1/iam/oidc-providers/update', {
      method: 'POST',
      body: JSON.stringify({ providerArn, clientIds })
    })
};
