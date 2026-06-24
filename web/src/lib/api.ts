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

const qs = (params: Record<string, string>) =>
  new URLSearchParams(params).toString();

export const api = {
  me: () => req<Me>('/v1/me'),
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
  kmsKeys: () => req<{ keys: KMSKey[] }>('/v1/kms/keys'),
  certificates: () => req<{ certificates: Certificate[] }>('/v1/certificates'),
  audit: () => req<{ events: AuditEvent[] }>('/v1/audit')
};

