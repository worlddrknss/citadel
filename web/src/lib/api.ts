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
    })
};
