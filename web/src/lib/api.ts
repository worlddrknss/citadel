// Typed client for the native Citadel /v1 API. All calls are same-origin and
// rely on the existing UI session cookie for authentication.

export class ApiError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
    credentials: 'same-origin'
  });
  if (!res.ok) {
    let code = 'error';
    let message = res.statusText;
    try {
      const body = await res.json();
      code = body.error ?? code;
      message = body.message ?? message;
    } catch {
      /* non-JSON error */
    }
    throw new ApiError(res.status, code, message);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export interface Me {
  username: string;
  displayName: string;
  role: string;
  accountId: string;
  accounts: string[];
}

export interface Project {
  slug: string;
  environments: string[];
}

export interface Item {
  project: string;
  env: string;
  path: string;
  key: string;
  arn: string;
  updatedAt: string;
}

export interface ListResult {
  project: string;
  env: string;
  path: string;
  folders: string[];
  items: Item[];
}

export interface KMSKey {
  keyId: string;
  arn: string;
  description: string;
  enabled: boolean;
  keyUsage: string;
  keySpec: string;
  createdAt: string;
  deletionDate?: string;
}

export interface Certificate {
  source: string;
  id: string;
  subject: string;
  status: string;
  notBefore?: string;
  notAfter?: string;
}

export interface AuditEvent {
  id: number;
  action: string;
  keyId?: string;
  result: string;
  errorType?: string;
  actor: string;
  createdAt: string;
}

export interface ItemVersion {
  versionId: string;
  stages: string[];
  createdAt: string;
}

export interface AccessKey {
  accessKeyId: string;
  status: string;
  createdAt: string;
  lastUsedAt?: string;
}

export interface AdminUser {
  username: string;
  displayName: string;
  role: string;
  accounts: string[];
}

export interface Account {
  accountId: string;
  name: string;
  createdAt: string;
}

const qs = (params: Record<string, string>) =>
  new URLSearchParams(params).toString();

export const api = {
  me: () => req<Me>('/v1/me'),
  login: (accountId: string, username: string, password: string) =>
    req<Me & { authOff?: boolean }>('/v1/login', {
      method: 'POST',
      body: JSON.stringify({ accountId, username, password })
    }),
  logout: () => req<{ loggedOut: boolean }>('/v1/logout', { method: 'POST' }),
  projects: () => req<{ projects: Project[] }>('/v1/projects'),
  list: (project: string, env: string, path: string) =>
    req<ListResult>(`/v1/secrets?${qs({ project, env, path })}`),
  reveal: (project: string, env: string, path: string, key: string) =>
    req<{ key: string; value?: string; binaryValue?: string; versionId: string }>(
      `/v1/secrets/value?${qs({ project, env, path, key })}`
    ),
  put: (body: {
    project: string;
    env: string;
    path: string;
    key: string;
    value: string;
    kmsKeyId?: string;
  }) => req<{ created: boolean }>('/v1/secrets', { method: 'POST', body: JSON.stringify(body) }),
  remove: (project: string, env: string, path: string, key: string) =>
    req<{ deleted: boolean }>(`/v1/secrets?${qs({ project, env, path, key })}`, {
      method: 'DELETE'
    }),
  versions: (project: string, env: string, path: string, key: string) =>
    req<{ key: string; versions: ItemVersion[] }>(
      `/v1/secrets/versions?${qs({ project, env, path, key })}`
    ),
  createProject: (slug: string, name: string) =>
    req<{ created: boolean }>('/v1/projects', {
      method: 'POST',
      body: JSON.stringify({ slug, name })
    }),
  createEnvironment: (project: string, slug: string, name: string) =>
    req<{ created: boolean }>('/v1/environments', {
      method: 'POST',
      body: JSON.stringify({ project, slug, name })
    }),
  createFolder: (project: string, env: string, path: string) =>
    req<{ created: boolean }>('/v1/folders', {
      method: 'POST',
      body: JSON.stringify({ project, env, path })
    }),

  // KMS
  kmsKeys: () => req<{ keys: KMSKey[] }>('/v1/kms/keys'),
  createKmsKey: (body: { description: string; keyUsage: string; keySpec: string }) =>
    req<{ keyId: string; arn: string; created: boolean }>('/v1/kms/keys', {
      method: 'POST',
      body: JSON.stringify(body)
    }),
  setKmsKeyEnabled: (keyId: string, enabled: boolean) =>
    req<{ keyId: string; enabled: boolean }>('/v1/kms/keys/enabled', {
      method: 'POST',
      body: JSON.stringify({ keyId, enabled })
    }),
  scheduleKmsKeyDeletion: (keyId: string, windowDays: number) =>
    req<{ keyId: string; deletionDate: string }>('/v1/kms/keys/schedule-deletion', {
      method: 'POST',
      body: JSON.stringify({ keyId, windowDays })
    }),
  cancelKmsKeyDeletion: (keyId: string) =>
    req<{ keyId: string; restored: boolean }>('/v1/kms/keys/cancel-deletion', {
      method: 'POST',
      body: JSON.stringify({ keyId })
    }),

  // Certificates
  certificates: () => req<{ certificates: Certificate[] }>('/v1/certificates'),
  createCA: (body: {
    caType: string;
    keyAlgorithm: string;
    signingAlgorithm?: string;
    commonName: string;
    organization?: string;
    country?: string;
  }) =>
    req<{ caId: string; created: boolean }>('/v1/certificates/authorities', {
      method: 'POST',
      body: JSON.stringify(body)
    }),
  issueCert: (body: {
    caArn: string;
    csrPem: string;
    validityDays?: string;
    signingAlgorithm?: string;
    overrideCommonName?: string;
    sanNames?: string;
  }) =>
    req<{ issued: boolean }>('/v1/certificates/issue', {
      method: 'POST',
      body: JSON.stringify(body)
    }),
  revokeCert: (certId: string, reason: string) =>
    req<{ revoked: boolean }>('/v1/certificates/revoke', {
      method: 'POST',
      body: JSON.stringify({ certId, reason })
    }),

  audit: () => req<{ events: AuditEvent[] }>('/v1/audit'),

  // Account self-service
  accessKeys: () => req<{ accessKeys: AccessKey[] }>('/v1/account/keys'),
  createAccessKey: () =>
    req<{ accessKeyId: string; secretKey: string }>('/v1/account/keys', { method: 'POST' }),
  deleteAccessKey: (accessKeyId: string) =>
    req<{ deleted: boolean }>(`/v1/account/keys?${qs({ accessKeyId })}`, { method: 'DELETE' }),
  setAccessKeyStatus: (accessKeyId: string, status: string) =>
    req<{ accessKeyId: string; status: string }>('/v1/account/keys/status', {
      method: 'POST',
      body: JSON.stringify({ accessKeyId, status })
    }),
  changePassword: (currentPassword: string, newPassword: string) =>
    req<{ updated: boolean }>('/v1/account/password', {
      method: 'POST',
      body: JSON.stringify({ currentPassword, newPassword })
    }),

  // Master admin
  users: () => req<{ users: AdminUser[] }>('/v1/admin/users'),
  upsertUser: (body: {
    username: string;
    displayName?: string;
    role: string;
    password?: string;
    accounts?: string[];
  }) =>
    req<{ username: string; created: boolean }>('/v1/admin/users', {
      method: 'POST',
      body: JSON.stringify(body)
    }),
  deleteUser: (username: string) =>
    req<{ deleted: boolean }>(`/v1/admin/users?${qs({ username })}`, { method: 'DELETE' }),
  accounts: () => req<{ accounts: Account[] }>('/v1/admin/accounts'),
  createAccount: (name: string) =>
    req<{ accountId: string; created: boolean }>('/v1/admin/accounts', {
      method: 'POST',
      body: JSON.stringify({ name })
    }),
  deleteAccount: (accountId: string) =>
    req<{ deleted: boolean }>(`/v1/admin/accounts?${qs({ accountId })}`, { method: 'DELETE' }),
  assignUserAccount: (username: string, accountId: string, role: string) =>
    req<{ assigned: boolean }>('/v1/admin/accounts/assign', {
      method: 'POST',
      body: JSON.stringify({ username, accountId, role })
    }),
  removeUserAccount: (username: string, accountId: string) =>
    req<{ removed: boolean }>(`/v1/admin/accounts/assign?${qs({ username, accountId })}`, {
      method: 'DELETE'
    })
};

