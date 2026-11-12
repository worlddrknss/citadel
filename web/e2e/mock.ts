// A fake Citadel /v1 API for the e2e smoke tests, served through Playwright
// route interception so the Go server isn't needed. Responses follow the
// shapes in src/lib/api.ts and the page-local api.ts modules.

import type { Page, Route } from '@playwright/test';

const DAY = 86_400_000;
const ago = (ms: number) => new Date(Date.now() - ms).toISOString();
const ahead = (ms: number) => new Date(Date.now() + ms).toISOString();

export const ACCOUNT = '123456789012';

export const me = {
  username: 'alice',
  displayName: 'Alice Admin',
  role: 'admin',
  accountId: ACCOUNT,
  accounts: [ACCOUNT, '210987654321'],
  platformAdmin: true
};

const projects = [
  {
    slug: 'payments',
    name: 'Payments',
    environments: ['dev', 'staging', 'prod'],
    environmentCounts: { dev: 4, staging: 4, prod: 4 }
  },
  { slug: 'web', name: 'Web', environments: ['dev', 'prod'], environmentCounts: { dev: 1, prod: 1 } }
];

function secretItem(project: string, env: string, path: string, key: string, i: number) {
  return {
    project,
    env,
    path,
    key,
    arn: `arn:aws:secretsmanager:us-east-1:${ACCOUNT}:secret:${project}/${env}${path === '/' ? '' : path}/${key}`,
    updatedAt: ago((i + 1) * 3_600_000),
    version: i + 2,
    updatedBy: i % 2 ? 'svc/rotation' : 'alice',
    tags: i === 0 ? [{ key: 'team', value: 'payments' }] : []
  };
}

function secretList(project: string, env: string, path: string) {
  if (path === '/db') {
    return {
      project,
      env,
      path,
      folders: [],
      folderCounts: {},
      items: ['DB_PASSWORD', 'DB_USER'].map((k, i) => secretItem(project, env, path, k, i)),
      shadowed: []
    };
  }
  return {
    project,
    env,
    path: '/',
    folders: ['db'],
    folderCounts: { db: 2 },
    items: ['API_KEY', 'STRIPE_KEY'].map((k, i) => secretItem(project, env, '/', k, i)),
    shadowed: []
  };
}

const keys = [
  {
    keyId: '1111aaaa-0000-4000-8000-000000000001',
    description: 'Account default key',
    enabled: true,
    keyUsage: 'ENCRYPT_DECRYPT',
    keySpec: 'SYMMETRIC_DEFAULT',
    createdAt: ago(200 * DAY),
    aliases: ['alias/default'],
    managed: true,
    rotation: { enabled: true, rotationPeriodDays: 365 },
    usedBy: { secrets: 10, parameters: 2 }
  },
  {
    keyId: '2222bbbb-0000-4000-8000-000000000002',
    description: 'Payments data key',
    enabled: true,
    keyUsage: 'ENCRYPT_DECRYPT',
    keySpec: 'SYMMETRIC_DEFAULT',
    createdAt: ago(90 * DAY),
    aliases: ['alias/payments'],
    rotation: { enabled: false },
    usedBy: { secrets: 3, parameters: 0 }
  },
  {
    keyId: '3333cccc-0000-4000-8000-000000000003',
    description: 'Release signing',
    enabled: false,
    keyUsage: 'SIGN_VERIFY',
    keySpec: 'ECC_NIST_P256',
    createdAt: ago(30 * DAY),
    aliases: ['alias/release-signing']
  },
  {
    keyId: '4444dddd-0000-4000-8000-000000000004',
    description: 'Old key',
    enabled: false,
    keyUsage: 'ENCRYPT_DECRYPT',
    keySpec: 'SYMMETRIC_DEFAULT',
    createdAt: ago(400 * DAY),
    deletionDate: ahead(5 * DAY),
    aliases: ['alias/legacy']
  }
].map((k) => ({ ...k, arn: `arn:aws:kms:us-east-1:${ACCOUNT}:key/${k.keyId}` }));

function keyDetail(keyId: string) {
  const k = keys.find((x) => x.keyId === keyId || x.aliases.includes(keyId)) ?? keys[1];
  return {
    ...k,
    keyState: k.deletionDate ? 'PendingDeletion' : k.enabled ? 'Enabled' : 'Disabled',
    encryptionAlgorithms: k.keyUsage === 'ENCRYPT_DECRYPT' ? ['SYMMETRIC_DEFAULT'] : undefined,
    signingAlgorithms: k.keyUsage === 'SIGN_VERIFY' ? ['ECDSA_SHA_256'] : undefined,
    policyDocument: JSON.stringify(
      {
        Version: '2012-10-17',
        Statement: [{ Sid: 'Root', Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${ACCOUNT}:root` }, Action: 'kms:*', Resource: '*' }]
      },
      null,
      2
    ),
    grants: []
  };
}

const parameters = [
  { name: '/payments/prod/db/url', type: 'String', tier: 'Standard', version: 3, description: 'DB URL', lastModified: ago(2 * DAY), value: 'postgres://db' },
  { name: '/payments/prod/db/password', type: 'SecureString', tier: 'Standard', version: 7, description: '', kmsKeyId: 'alias/default', lastModified: ago(DAY) },
  { name: '/payments/prod/hosts', type: 'StringList', tier: 'Advanced', version: 1, description: 'Hosts', lastModified: ago(10 * DAY), value: 'a,b,c' },
  { name: 'feature-flag', type: 'String', tier: 'Standard', version: 1, description: '', lastModified: ago(3_600_000), value: 'on' }
];

const certificates = [
  { source: 'pca', id: 'ca-root-1', subject: 'CN=Acme Root CA', commonName: 'Acme Root CA', status: 'ACTIVE', notBefore: ago(100 * DAY), notAfter: ahead(3000 * DAY), caType: 'ROOT', serial: '01' },
  { source: 'pca', id: 'cert-api-1', subject: 'CN=api.acme.test', commonName: 'api.acme.test', status: 'ISSUED', notBefore: ago(80 * DAY), notAfter: ahead(10 * DAY), issuerCaId: 'ca-root-1', serial: '02' },
  { source: 'acm', id: 'cert-www-1', subject: 'CN=www.acme.test', commonName: 'www.acme.test', status: 'ISSUED', notBefore: ago(20 * DAY), notAfter: ahead(70 * DAY), serial: '03' }
];

function certDetail(id: string) {
  const c = certificates.find((x) => x.id === id) ?? certificates[1];
  return {
    ...c,
    issuer: 'CN=Acme Root CA',
    keyAlgorithm: 'EC_prime256v1',
    signatureAlgorithm: 'SHA256WITHECDSA',
    sans: [c.commonName],
    isCA: !!c.caType,
    pem: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----'
  };
}

const auditRows = Array.from({ length: 12 }, (_, i) => ({
  id: 100 - i,
  createdAt: ago(i * 3_600_000 + 60_000),
  actor: i % 3 ? 'alice' : 'AKIACITADELTEST0001',
  actorType: i % 3 ? 'console' : 'access-key',
  actorDisplayName: i % 3 ? 'Alice Admin' : undefined,
  accessKeyId: i % 3 ? undefined : 'AKIACITADELTEST0001',
  action: ['secretsmanager.GetSecretValue', 'kms.Encrypt', 'citadel.Login', 'citadel.IssueWorkloadToken'][i % 4],
  resource: i % 2 ? 'payments/prod/API_KEY' : 'alias/default',
  keyId: i % 2 ? undefined : 'alias/default',
  // The server normalizes results to success | denied | error.
  result: i === 4 ? 'denied' : 'success',
  errorType: i === 4 ? 'AccessDeniedException' : undefined,
  sourceIp: '10.0.0.5',
  userAgent: i % 3 ? 'Mozilla/5.0 (Macintosh) Chrome/130' : 'aws-cli/2.17',
  chainSeq: 100 - i,
  prevHash: `h${101 - i}`,
  hash: `h${100 - i}`,
  hashValid: true
}));

const changeRequests = [
  { id: '1042', project: 'payments', env: 'prod', path: '/', key: 'STRIPE_KEY', requester: 'bob', status: 'pending', createdAt: ago(2 * 3_600_000) },
  { id: '1041', project: 'payments', env: 'prod', path: '/db', key: 'DB_PASSWORD', requester: 'alice', status: 'approved', createdAt: ago(3 * DAY), decidedBy: 'carol', decidedAt: ago(2 * DAY) }
];

const roles = [
  {
    roleArn: `arn:aws:iam::${ACCOUNT}:role/deploy`,
    roleName: 'deploy',
    description: 'CI deploys',
    trust: { type: 'oidc', providerUrl: 'https://token.actions.githubusercontent.com', audiences: ['sts.amazonaws.com'], subjects: ['repo:acme/app:*'] },
    maxSessionSeconds: 3600,
    createdAt: ago(40 * DAY),
    updatedAt: ago(4 * DAY)
  },
  {
    roleArn: `arn:aws:iam::${ACCOUNT}:role/audit-reader`,
    roleName: 'audit-reader',
    description: '',
    trust: { type: 'account', principals: ['210987654321'] },
    maxSessionSeconds: 7200,
    createdAt: ago(10 * DAY),
    updatedAt: ago(10 * DAY)
  }
];

const wiClients = [
  {
    clientId: 'wic-1',
    name: 'billing-worker',
    audiences: ['sts.amazonaws.com'],
    tokenTtlSeconds: 3600,
    subjectFormat: 'system:serviceaccount:{namespace}:{serviceAccount}',
    auth: { method: 'k8s-token-review', apiServer: 'https://k8s.acme.test', serviceAccounts: ['billing:worker'] },
    createdAt: ago(20 * DAY),
    updatedAt: ago(2 * DAY),
    lastIssuedAt: ago(3_600_000)
  }
];

const ssoProviders = [
  {
    id: 'sso-9f8e7d6c5b4a',
    name: 'Okta',
    issuer: 'https://acme.okta.com',
    clientId: '0oa1citadel',
    clientSecretSet: true,
    scopes: ['openid', 'email', 'profile', 'groups'],
    groupClaim: 'groups',
    roleMappings: [{ group: 'platform-admins', accountId: ACCOUNT, role: 'admin' }],
    defaultRole: 'viewer',
    enabled: true,
    redirectUri: 'http://localhost:4173/v1/auth/oidc/sso-9f8e7d6c5b4a/callback',
    accountId: ACCOUNT,
    allowedEmailDomains: ['acme.test'],
    createdAt: ago(40 * DAY),
    updatedAt: ago(10 * DAY)
  }
];

type Json = Record<string, unknown> | unknown[];
type Handler = (q: URLSearchParams, body: Record<string, unknown>) => Json | undefined;

const ok = { ok: true };

/** GET handlers by path. */
const GET: Record<string, Handler> = {
  // The server deliberately leaves out its version.
  '/v1/server/info': () => ({ fips: true, sessionIdleMinutes: 30, sessionMaxHours: 12 }),
  '/v1/auth/providers': () => ({ providers: [] }),
  '/v1/bootstrap': () => ({ required: false }),
  '/v1/me': () => me,
  '/v1/me/organization': () => ({
    organization: { name: 'Acme Corp' },
    accounts: [
      { accountId: ACCOUNT, name: 'production', role: 'admin' },
      { accountId: '210987654321', name: 'staging', role: 'editor' }
    ]
  }),
  '/v1/projects': () => ({ projects }),
  '/v1/secrets': (q) => secretList(q.get('project') ?? '', q.get('env') ?? '', q.get('path') || '/'),
  '/v1/secrets/summary': () => ({ total: 13, projects: 2, environments: 5 }),
  '/v1/secrets/value': (q) => ({ key: q.get('key'), value: `value-of-${q.get('key')}`, versionId: 'v-current' }),
  '/v1/secrets/detail': (q) => {
    const path = q.get('path') || '/';
    const key = q.get('key') ?? '';
    const item = secretItem(q.get('project') ?? '', q.get('env') ?? '', path, key, 0);
    return {
      ...item,
      description: 'Used by the API',
      kmsKeyId: 'alias/default',
      currentVersionId: 'v-current',
      previousVersionId: 'v-prev',
      status: 'active',
      createdAt: ago(30 * DAY),
      policyDocument: '',
      rotation: { enabled: false },
      valueLength: 24,
      fingerprint: 'sha256:3f9a…c41e'
    };
  },
  '/v1/secrets/versions': (q) => ({
    key: q.get('key'),
    versions: [
      { versionId: 'v-current', stages: ['AWSCURRENT'], createdAt: ago(3_600_000), createdBy: 'alice' },
      { versionId: 'v-prev', stages: ['AWSPREVIOUS'], createdAt: ago(5 * DAY), createdBy: 'svc/rotation' }
    ]
  }),
  '/v1/secrets/policy': (q) => ({ key: q.get('key'), policyDocument: '' }),
  '/v1/change-requests': () => ({ changeRequests }),
  '/v1/change-requests/policies': () => ({
    policies: [{ project: 'payments', env: 'prod', approvalsRequired: 1, approverRoles: ['admin'] }]
  }),
  '/v1/change-requests/detail': (q) => {
    const cr = changeRequests.find((c) => c.id === q.get('id')) ?? changeRequests[0];
    return {
      ...cr,
      title: `Update ${cr.key}`,
      changes: [
        {
          key: cr.key,
          path: cr.path,
          change: 'modified',
          previous: { sha256: 'a'.repeat(64), length: 20, version: 'v7' },
          proposed: { sha256: 'b'.repeat(64), length: 24, version: 'v8' }
        }
      ],
      policy: { name: 'payments/prod', approvalsRequired: 1, approverRoles: ['admin'] },
      approvals: [],
      canApprove: cr.requester !== me.username && cr.status === 'pending'
    };
  },
  '/v1/kms/keys': () => ({ keys }),
  '/v1/kms/keys/detail': (q) => keyDetail(q.get('keyId') ?? ''),
  '/v1/kms/keys/rotation': (q) => ({
    keyId: q.get('keyId'),
    supported: true,
    enabled: false,
    rotationPeriodDays: 365,
    history: []
  }),
  '/v1/kms/keys/tags': (q) => ({ keyId: q.get('keyId'), tags: [{ key: 'team', value: 'payments' }] }),
  '/v1/kms/grants': () => ({ grants: [] }),
  '/v1/parameters': () => ({ parameters }),
  '/v1/parameters/value': (q) => ({ parameter: parameters.find((p) => p.name === q.get('name')) ?? parameters[0], value: 'decrypted' }),
  '/v1/parameters/history': (q) => ({
    name: q.get('name'),
    history: [{ name: q.get('name'), version: 1, type: 'String', tier: 'Standard', description: '', labels: ['stable'], modifiedAt: ago(DAY) }]
  }),
  '/v1/parameters/tags': (q) => ({ name: q.get('name'), tags: [] }),
  '/v1/certificates': () => ({ certificates }),
  '/v1/certificates/detail': (q) => certDetail(q.get('id') ?? ''),
  '/v1/certificates/letsencrypt/settings': () => ({ environment: 'staging', directoryUrl: '', contactEmail: 'ops@acme.test' }),
  '/v1/certificates/acme/eab': () => ({ keys: [] }),
  '/v1/audit': () => ({ events: auditRows.map(({ id, action, keyId, result, errorType, actor, createdAt }) => ({ id, action, keyId, result, errorType, actor, createdAt })) }),
  '/v1/audit/events': (q) => {
    const limit = Number(q.get('limit') ?? 50);
    const offset = Number(q.get('offset') ?? 0);
    return { events: auditRows.slice(offset, offset + limit), total: auditRows.length, limit, offset };
  },
  '/v1/audit/verify': () => ({ status: 'verified', verifiedThrough: 100, headHash: 'h100', checkedAt: ago(600_000), totalEvents: 100 }),
  '/v1/audit/stream': () => ({ enabled: false, url: '', format: 'json', hasToken: false }),
  '/v1/account/keys': () => ({
    accessKeys: [{ accessKeyId: 'AKIACITADELTEST0001', status: 'Active', createdAt: ago(60 * DAY), lastUsedAt: ago(DAY) }]
  }),
  '/v1/account/sessions': () => ({
    sessions: [
      { id: 's1', current: true, createdAt: ago(3_600_000), lastSeenAt: ago(60_000), expiresAt: ahead(11 * 3_600_000), ip: '10.0.0.5', userAgent: 'Mozilla/5.0 (Macintosh) Chrome/130', method: 'password' }
    ]
  }),
  '/v1/admin/users': () => ({
    users: [
      { username: 'alice', displayName: 'Alice Admin', role: 'admin', accounts: [ACCOUNT], memberships: [{ accountId: ACCOUNT, role: 'admin' }], platformAdmin: true },
      { username: 'bob', displayName: 'Bob', role: 'editor', accounts: [ACCOUNT], memberships: [{ accountId: ACCOUNT, role: 'editor' }], platformAdmin: false }
    ]
  }),
  '/v1/admin/accounts': () => ({
    accounts: [
      { accountId: ACCOUNT, name: 'production', createdAt: ago(300 * DAY) },
      { accountId: '210987654321', name: 'staging', createdAt: ago(200 * DAY) }
    ]
  }),
  '/v1/admin/settings': () => ({
    approvalEnvironments: ['prod'],
    approvalMinApprovers: 1,
    sessionIdleMinutes: 30,
    sessionMaxHours: 12,
    updatedAt: ago(5 * DAY),
    updatedBy: 'alice'
  }),
  '/v1/admin/sso/providers': () => ({ providers: ssoProviders }),
  '/v1/iam/oidc-providers': () => ({
    providers: [
      {
        providerArn: `arn:aws:iam::${ACCOUNT}:oidc-provider/token.actions.githubusercontent.com`,
        url: 'https://token.actions.githubusercontent.com',
        clientIds: ['sts.amazonaws.com'],
        createdAt: ago(50 * DAY)
      }
    ]
  }),
  '/v1/iam/roles': () => ({ roles }),
  '/v1/workload-identity/issuer': () => ({
    issuer: 'https://citadel.acme.test/oidc',
    discoveryUrl: 'https://citadel.acme.test/oidc/.well-known/openid-configuration',
    jwksUrl: 'https://citadel.acme.test/oidc/jwks.json',
    tokenEndpoint: 'https://citadel.acme.test/v1/workload-identity/token',
    signingKey: { kid: 'kid-1', kmsKeyId: keys[2].keyId, kmsAlias: 'alias/wi-signing', algorithm: 'ES256', activatedAt: ago(20 * DAY) },
    previousKeys: [],
    rotationDays: 90,
    nextRotationAt: ahead(70 * DAY)
  }),
  '/v1/workload-identity/clients': () => ({ clients: wiClients })
};

/** Non-GET handlers by "METHOD path". Anything else gets {ok:true}. */
const WRITE: Record<string, Handler> = {
  'POST /v1/login': () => me,
  'POST /v1/logout': () => ({ loggedOut: true }),
  'POST /v1/kms/keys/schedule-deletion': (_, b) => ({ keyId: b.keyId, deletionDate: ahead(Number(b.windowDays ?? 30) * DAY) }),
  'POST /v1/audit/verify': () => GET['/v1/audit/verify'](new URLSearchParams(), {}),
  'POST /v1/audit/stream': (_, b) => ({ enabled: !!b.enabled, url: b.url ?? '', format: b.format ?? 'json', hasToken: typeof b.token === 'string' && b.token !== '' }),
  'POST /v1/audit/stream/test': () => ({ delivered: true, status: 204 }),
  'POST /v1/account/keys': () => ({ accessKeyId: 'AKIACITADELTEST0002', secretKey: 'mockSecretAccessKey0123456789abcdefghijklmn' }),
  'POST /v1/account/profile': (_, b) => ({ username: me.username, displayName: b.displayName }),
  'POST /v1/account/sessions/revoke-others': () => ({ revoked: 1 }),
  'DELETE /v1/account/sessions': () => ({ revoked: true }),
  'POST /v1/admin/settings': (_, b) => ({ ...b, updatedAt: new Date().toISOString(), updatedBy: me.username }),
  'POST /v1/admin/sso/providers': () => ({ id: 'sso-0a1b2c3d4e5f', redirectUri: 'http://localhost:4173/v1/auth/oidc/sso-0a1b2c3d4e5f/callback' }),
  'POST /v1/admin/sso/providers/update': (_, b) => ({ id: b.id, updated: true }),
  'DELETE /v1/admin/sso/providers': () => ({ deleted: true }),
  'POST /v1/admin/sso/providers/test': () => ({ ok: true, message: 'discovery document fetched', authorizationEndpoint: 'https://idp.acme.test/authorize' })
};

/** Non-JSON GET responses (downloads). */
const RAW: Record<string, (q: URLSearchParams) => { contentType: string; body: string }> = {
  '/v1/audit/export': (q) =>
    q.get('format') === 'json'
      ? { contentType: 'application/json', body: JSON.stringify(auditRows) }
      : {
          contentType: 'text/csv',
          body: 'id,chainSeq,createdAt,actor,actorType,action,result\n' + auditRows.map((r) => [r.id, r.chainSeq, r.createdAt, r.actor, r.actorType, r.action, r.result].join(',')).join('\n')
        }
};

/** Endpoints that answer without a session. */
const PUBLIC = new Set(['/v1/server/info', '/v1/auth/providers', '/v1/bootstrap', '/v1/login']);

export interface MockOptions {
  /** Start with a valid session cookie (default true). */
  signedIn?: boolean;
}

export class MockApi {
  signedIn: boolean;
  /** Requests nothing in this file answers; tests assert it stays empty. */
  unhandled: string[] = [];
  /** Every request, as "METHOD /path?query". */
  log: string[] = [];

  constructor(opts: MockOptions = {}) {
    this.signedIn = opts.signedIn ?? true;
  }

  /** The server forgets the session: everything but public endpoints says 401. */
  expireSession() {
    this.signedIn = false;
  }

  async install(page: Page) {
    await page.route('**/v1/**', (route) => this.handle(route));
  }

  private async handle(route: Route) {
    const req = route.request();
    const url = new URL(req.url());
    const method = req.method();
    const path = url.pathname;
    this.log.push(`${method} ${path}${url.search}`);

    if (!PUBLIC.has(path) && !this.signedIn) {
      return route.fulfill({ status: 401, json: { error: 'unauthorized', message: 'Your session has expired.' } });
    }
    let body: Record<string, unknown> = {};
    try {
      body = req.postDataJSON() ?? {};
    } catch {
      /* not JSON */
    }
    if (method === 'POST' && path === '/v1/login') this.signedIn = true;
    if (method === 'POST' && path === '/v1/logout') this.signedIn = false;

    if (method === 'GET' && RAW[path]) {
      const r = RAW[path](url.searchParams);
      return route.fulfill({ status: 200, contentType: r.contentType, body: r.body });
    }
    if (method === 'GET') {
      const h = GET[path];
      if (!h) {
        this.unhandled.push(`GET ${path}`);
        return route.fulfill({ status: 404, json: { error: 'not_found', message: `mock: no fixture for ${path}` } });
      }
      return route.fulfill({ status: 200, json: h(url.searchParams, body) });
    }
    const h = WRITE[`${method} ${path}`];
    return route.fulfill({ status: 200, json: h ? h(url.searchParams, body) : ok });
  }
}

export const fixtures = { projects, keys, parameters, certificates, roles };
