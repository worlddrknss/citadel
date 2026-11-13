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
    items: ['API_KEY', 'STRIPE_KEY'].map((k, i) => ({
      ...secretItem(project, env, '/', k, i),
      // STRIPE_KEY's built-in rotation is failing (the table flags it).
      ...(k === 'STRIPE_KEY' ? { rotationDue: true, rotationStatus: 'failed' } : {})
    })),
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
    aliases: ['alias/legacy'],
    rotation: { enabled: false }
  }
].map((k) => ({ ...k, arn: `arn:aws:kms:us-east-1:${ACCOUNT}:key/${k.keyId}` }));

// The real list has managed/origin/rotation (rotation on symmetric keys
// only) but not usedBy, which only the detail response carries.
const keyList = keys.map(({ usedBy: _usedBy, ...k }) => ({ managed: false, origin: 'AWS_KMS', ...k }));

function keyDetail(keyId: string) {
  const k = keys.find((x) => x.keyId === keyId || x.aliases.includes(keyId)) ?? keys[1];
  return {
    managed: false,
    origin: 'AWS_KMS',
    usedBy: { secrets: 0, parameters: 0 },
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
  // Real list rows: source is pca-ca, pca-cert, lets-encrypt or acm-imported; template is server|client.
  { source: 'pca-ca', id: 'ca-root-1', subject: 'CN=Acme Root CA', commonName: 'Acme Root CA', status: 'ACTIVE', notBefore: ago(100 * DAY), notAfter: ahead(3000 * DAY), caType: 'ROOT', serial: '01', keyAlgorithm: 'EC_secp384r1', expiringSoon: false, isCA: true, outstanding: 1 },
  { source: 'pca-ca', id: 'ca-sub-1', subject: 'CN=Acme Issuing CA', commonName: 'Acme Issuing CA', status: 'ACTIVE', notBefore: ago(90 * DAY), notAfter: ahead(1500 * DAY), caType: 'SUBORDINATE', parentCaId: 'ca-root-1', serial: '04', keyAlgorithm: 'EC_prime256v1', expiringSoon: false, isCA: true, pathLen: 0, outstanding: 0 },
  { source: 'pca-ca', id: 'ca-old-1', subject: 'CN=Acme Old CA', commonName: 'Acme Old CA', status: 'DISABLED', notBefore: ago(400 * DAY), notAfter: ahead(600 * DAY), caType: 'ROOT', serial: '06', keyAlgorithm: 'EC_prime256v1', expiringSoon: false, isCA: true, outstanding: 0 },
  { source: 'pca-ca', id: 'ca-gone-1', subject: 'CN=Acme Retired CA', commonName: 'Acme Retired CA', status: 'DELETED', notBefore: ago(500 * DAY), notAfter: ahead(500 * DAY), caType: 'ROOT', serial: '07', keyAlgorithm: 'EC_prime256v1', expiringSoon: false, isCA: true, restorableUntil: ahead(12 * DAY) },
  { source: 'pca-cert', id: 'cert-api-1', subject: 'api.acme.test', commonName: 'api.acme.test', status: 'ISSUED', notBefore: ago(80 * DAY), notAfter: ahead(10 * DAY), issuerCaId: 'ca-root-1', serial: '02', keyAlgorithm: 'EC_prime256v1', template: 'server', expiringSoon: true },
  { source: 'lets-encrypt', id: 'cert-www-1', subject: 'www.acme.test', commonName: 'www.acme.test', status: 'ISSUED', notBefore: ago(20 * DAY), notAfter: ahead(70 * DAY), serial: '03', keyAlgorithm: 'EC_prime256v1', expiringSoon: false,
    renewal: { kind: 'http-01', autoRenew: true, manual: false, nextRenewalAt: ahead(40 * DAY) } },
  { source: 'lets-encrypt', id: 'cert-dns-1', subject: 'dns.acme.test', commonName: 'dns.acme.test', status: 'ISSUED', notBefore: ago(70 * DAY), notAfter: ahead(20 * DAY), serial: '08', keyAlgorithm: 'EC_prime256v1', expiringSoon: true,
    renewal: { kind: 'dns-01', autoRenew: false, manual: true } },
  { source: 'acm-imported', id: 'arn:aws:acm:us-east-1:000000000000:certificate/imp1', subject: 'legacy.acme.test', commonName: 'legacy.acme.test', status: 'ISSUED', notBefore: ago(30 * DAY), notAfter: ahead(200 * DAY), serial: '05', keyAlgorithm: 'EC_prime256v1', issuer: 'CN=External Issuing CA,O=Example', expiringSoon: false }
];

const pemOf = (tag: string) => `-----BEGIN CERTIFICATE-----\nMII${tag}\n-----END CERTIFICATE-----\n`;

/** The chain GET /v1/certificates/detail returns: leaf first, root last. */
function certChain(c: (typeof certificates)[number]) {
  const link = (role: string, subject: string, issuer: string, serial: string, isCA: boolean) => ({
    role,
    subject,
    issuer,
    serial,
    notBefore: c.notBefore,
    notAfter: c.notAfter,
    isCA,
    selfSigned: role === 'root',
    pem: pemOf(serial)
  });
  if (c.source === 'acm-imported') {
    return [
      link('leaf', `CN=${c.commonName}`, 'CN=External Issuing CA,O=Example', 'a1', false),
      link('intermediate', 'CN=External Issuing CA,O=Example', 'CN=External Root CA,O=Example', 'a2', true),
      link('root', 'CN=External Root CA,O=Example', 'CN=External Root CA,O=Example', 'a3', true)
    ];
  }
  if (c.source === 'pca-ca') {
    const root = link('root', 'CN=Acme Root CA', 'CN=Acme Root CA', '01', true);
    return c.id === 'ca-root-1' ? [root] : [link('intermediate', c.subject, 'CN=Acme Root CA', '04', true), root];
  }
  return [link('leaf', `CN=${c.commonName}`, 'CN=Acme Root CA', c.serial, false), link('root', 'CN=Acme Root CA', 'CN=Acme Root CA', '01', true)];
}

function certDetail(id: string) {
  const c = certificates.find((x) => x.id === id) ?? certificates[1];
  return {
    ...c,
    issuer: c.source === 'acm-imported' ? 'CN=External Issuing CA,O=Example' : 'CN=Acme Root CA',
    keyAlgorithm: 'EC_prime256v1',
    signatureAlgorithm: 'SHA256WITHECDSA',
    sans: [c.commonName],
    isCA: !!c.caType,
    pem: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----',
    chain: certChain(c)
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
  // The server normalizes results to success | denied | error | pending.
  // Event 98 is a write-ahead attempt; event 99 is its outcome.
  result: i === 4 ? 'denied' : i === 2 ? 'pending' : 'success',
  correlationId: i === 1 || i === 2 ? '5f2a9c0d1e3b4a6f8091a2b3c4d5e6f7' : undefined,
  errorType: i === 4 ? 'AccessDeniedException' : undefined,
  sourceIp: '10.0.0.5',
  userAgent: i % 3 ? 'Mozilla/5.0 (Macintosh) Chrome/130' : 'aws-cli/2.17',
  chainSeq: 100 - i,
  prevHash: `h${101 - i}`,
  hash: `h${100 - i}`,
  hashValid: true
}));

const changeRequests = [
  { id: 'cr-1a2b3c4d5e6f', project: 'payments', env: 'prod', path: '/', key: 'STRIPE_KEY', requester: 'bob', status: 'pending', createdAt: ago(2 * 3_600_000), approvals: 0, approvalsRequired: 1, approverRoles: ['admin'], canApprove: true },
  { id: 'cr-0f9e8d7c6b5a', project: 'payments', env: 'prod', path: '/db', key: 'DB_PASSWORD', requester: 'alice', status: 'approved', createdAt: ago(3 * DAY), decidedBy: 'carol', decidedAt: ago(2 * DAY) }
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
    clientId: 'wic-8f2a91c03d5e',
    name: 'billing-worker',
    audiences: ['sts.amazonaws.com'],
    tokenTtlSeconds: 3600,
    subjectFormat: 'system:serviceaccount:{namespace}:{serviceAccount}',
    auth: { method: 'k8s-token-review', apiServer: 'https://k8s.acme.test', serviceAccounts: ['billing:worker'], reviewAudience: 'citadel' },
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


// AI agents (/v1/agents...).
export const AGENT_ID = 'agt_abcdefghijklmnopqrst';
export const AGENT_TOKEN = 'cagt_agt_abcdefghijklmnopqrst_mocksecretmocksecretmocksecretmocksecretmocksecre';
const agentList = [
  {
    agentId: AGENT_ID, name: 'claude-code', description: 'Coding agent for the payments repo', owner: 'alice', status: 'active',
    labels: { team: 'payments' }, createdAt: ago(20 * DAY), createdBy: 'alice', updatedAt: ago(2 * DAY), lastUsedAt: ago(3_600_000),
    grantCount: 2, activeTokenCount: 1, bindingCount: 1, canManage: true
  },
  {
    agentId: 'agt_zyxwvutsrqponmlkjihg', name: 'triage-bot', description: '', owner: 'bob', status: 'suspended', labels: {},
    createdAt: ago(9 * DAY), createdBy: 'bob', updatedAt: ago(DAY), statusChangedAt: ago(DAY), statusChangedBy: 'alice', statusReason: 'investigating',
    grantCount: 0, activeTokenCount: 0, bindingCount: 0, canManage: true
  }
];
const agentCredentials = [
  {
    name: 'stripe-api', secretName: 'payments/dev/STRIPE_KEY', project: 'payments', env: 'dev', key: 'STRIPE_KEY', kind: 'http_header',
    description: 'Stripe test API', allowedHosts: ['api.stripe.com'], allowedMethods: ['GET', 'POST'], allowedPathPrefixes: ['/v1/'],
    headerName: 'Authorization', headerPrefix: 'Bearer ', allowHttp: false, allowedCidrs: [], createdAt: ago(10 * DAY), updatedAt: ago(10 * DAY),
    grants: [{ grantId: 'agr_aaaaaaaaaaaaaaaa', agentId: AGENT_ID, agentName: 'claude-code', actions: ['use'] }]
  },
  {
    name: 'db-password', secretName: 'payments/dev/db/DB_PASSWORD', project: 'payments', env: 'dev', path: 'db', key: 'DB_PASSWORD', kind: 'raw',
    description: '', allowedHosts: [], allowedMethods: [], allowedPathPrefixes: [], allowHttp: false, allowedCidrs: [], createdAt: ago(5 * DAY), updatedAt: ago(5 * DAY),
    grants: [{ grantId: 'agr_bbbbbbbbbbbbbbbb', agentId: AGENT_ID, agentName: 'claude-code', actions: ['reveal'] }]
  }
];
const agentGrants = [
  {
    grantId: 'agr_aaaaaaaaaaaaaaaa', agentId: AGENT_ID, agentName: 'claude-code', credential: 'stripe-api', actions: ['use'],
    window: { start: '09:00', end: '18:00', days: ['mon', 'tue', 'wed', 'thu', 'fri'], timezone: 'Europe/Dublin' }, maxUsesPerHour: 60,
    requiresApproval: null, leaseTtlSeconds: null, createdAt: ago(10 * DAY), updatedAt: ago(10 * DAY), usableNow: true
  },
  {
    grantId: 'agr_bbbbbbbbbbbbbbbb', agentId: AGENT_ID, agentName: 'claude-code', credential: 'db-password', actions: ['reveal'],
    window: null, maxUsesPerHour: 0, notAfter: ago(DAY), requiresApproval: null, leaseTtlSeconds: null, createdAt: ago(5 * DAY), updatedAt: ago(5 * DAY),
    usableNow: false, reason: 'grant_expired'
  }
];
function agentDetail(id: string) {
  const agent = agentList.find((a) => a.agentId === id) ?? agentList[0];
  const mine = agent.agentId === AGENT_ID;
  return {
    agent,
    tokens: mine
      ? [
          { tokenId: 'atk_aaaaaaaaaaaaaaaa', name: 'laptop', prefix: `cagt_${AGENT_ID}_abcdefgh`, status: 'active', createdAt: ago(10 * DAY), createdBy: 'alice', expiresAt: ahead(80 * DAY), lastUsedAt: ago(3_600_000) },
          { tokenId: 'atk_bbbbbbbbbbbbbbbb', name: 'old', prefix: `cagt_${AGENT_ID}_zzzzzzzz`, status: 'revoked', createdAt: ago(40 * DAY), revokedAt: ago(10 * DAY), revokedBy: 'alice' }
        ]
      : [],
    bindings: mine
      ? [{ bindingId: 'abd_aaaaaaaaaaaaaaaa', issuer: 'https://token.actions.githubusercontent.com', subject: 'repo:acme/payments:ref:refs/heads/main', audience: 'citadel', description: 'CI on main', createdAt: ago(8 * DAY) }]
      : [],
    grants: mine ? agentGrants : []
  };
}
const agentSettings = { agentsSuspended: false };

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
      rotation:
        key === 'STRIPE_KEY'
          ? { enabled: true, afterDays: 30, nextRotationDate: ago(DAY), due: true, rotatorType: 'random', status: 'failed' }
          : { enabled: false },
      valueLength: 24,
      fingerprint: 'hmac:3f9a0b1c2d4e',
      version: 2
    };
  },
  '/v1/secrets/versions': (q) => ({
    key: q.get('key'),
    versions: [
      { versionId: 'v-current', version: 2, stages: ['AWSCURRENT'], createdAt: ago(3_600_000), createdBy: 'alice' },
      { versionId: 'v-prev', version: 1, stages: ['AWSPREVIOUS'], createdAt: ago(5 * DAY), createdBy: 'svc/rotation' }
    ]
  }),
  '/v1/secrets/policy': (q) => ({ key: q.get('key'), policyDocument: '' }),
  '/v1/secrets/rotation': (q) => (q.get('key') === 'STRIPE_KEY' ? stripeRotation : { enabled: false, mode: 'none', schedule: {}, status: '', due: false, history: [] }),
  '/v1/secrets/settings': () => ({ viewersCanReveal: false, updatedAt: ago(DAY), updatedBy: 'alice' }),
  '/v1/change-requests': () => ({ changeRequests }),
  // Real shape: project policies plus organization approval environments
  // (Administration → settings) listed per project with source "organization".
  '/v1/change-requests/policies': () => ({
    policies: [
      { project: 'payments', env: 'prod', approvalsRequired: 1, approverRoles: ['admin'], source: 'project' },
      { project: 'web', env: 'prod', approvalsRequired: 1, approverRoles: ['admin'], source: 'organization' }
    ]
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
          // Keyed HMAC fingerprints (12 hex), not hashes of the value.
          previous: { fingerprint: 'hmac:aaaaaaaaaaaa', sha256: 'aaaaaaaaaaaa', length: 20, version: 'v7' },
          proposed: { fingerprint: 'hmac:bbbbbbbbbbbb', sha256: 'bbbbbbbbbbbb', length: 24, version: 'v8' }
        }
      ],
      policy: { name: `${cr.project}/${cr.env} approval`, approvalsRequired: 1, approverRoles: ['admin'] },
      approvals: [],
      requesterRole: 'editor',
      canApprove: cr.requester !== me.username && cr.status === 'pending',
      ...(cr.requester === me.username && cr.status === 'pending'
        ? { cannotApproveReason: "You can't approve your own change request." }
        : cr.status !== 'pending'
          ? { cannotApproveReason: `This request has already been ${cr.status}.` }
          : {}),
      canReject: cr.status === 'pending'
    };
  },
  '/v1/kms/keys': () => ({ keys: keyList }),
  '/v1/kms/keys/detail': (q) => keyDetail(q.get('keyId') ?? ''),
  '/v1/kms/keys/rotation': (q) => ({
    keyId: q.get('keyId'),
    supported: true,
    enabled: false,
    rotationPeriodDays: 365,
    history: []
  }),
  '/v1/kms/keys/tags': (q) => ({ keyId: q.get('keyId'), tags: [{ key: 'team', value: 'payments' }] }),
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
  '/v1/certificates/acme/settings': () => ({
    enabled: true,
    directoryUrl: 'https://citadel.acme.test/acme/directory',
    issuingCaId: '',
    effectiveIssuingCaId: 'ca-root-1',
    allowedDomains: ['acme.test'],
    allowedIpRanges: [],
    validationAllowedCidrs: []
  }),
  '/v1/audit': () => ({ events: auditRows.map(({ id, action, keyId, result, errorType, actor, createdAt }) => ({ id, action, keyId, result, errorType, actor, createdAt })) }),
  '/v1/audit/events': (q) => {
    const limit = Number(q.get('limit') ?? 50);
    const offset = Number(q.get('offset') ?? 0);
    const corr = q.get('correlation');
    const result = q.get('result');
    const rows = auditRows.filter((r) => (!corr || r.correlationId === corr) && (!result || r.result === result));
    return { events: rows.slice(offset, offset + limit), total: rows.length, limit, offset };
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
      { username: 'bob', displayName: 'Bob', role: 'editor', accounts: [ACCOUNT], memberships: [{ accountId: ACCOUNT, role: 'editor' }], platformAdmin: false, mfaEnabled: true }
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
    requireMFA: false,
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
  '/v1/workload-identity/issuer': () => issuerInfo,
  '/v1/workload-identity/clients': () => ({ clients: wiClients }),
  '/v1/agents': () => ({ agents: agentList, settings: agentSettings, canCreate: true }),
  '/v1/agents/detail': (q) => agentDetail(q.get('agentId') ?? ''),
  '/v1/agents/credentials': (q) => ({
    credentials: q.get('key') ? agentCredentials.filter((c) => c.key === q.get('key')) : agentCredentials,
    canEdit: true
  }),
  '/v1/agents/settings': () => agentSettings
};

// GET /v1/workload-identity/issuer (and the settings/rotate responses).
const issuerInfo = {
  configured: true,
  algorithm: 'ES256',
  k8sTokenReview: true,
  issuer: 'https://citadel.acme.test/oidc',
    discoveryUrl: 'https://citadel.acme.test/oidc/.well-known/openid-configuration',
    jwksUrl: 'https://citadel.acme.test/oidc/jwks.json',
    tokenEndpoint: 'https://citadel.acme.test/v1/workload-identity/token',
  signingKey: { kid: 'kid-1', kmsKeyId: keys[2].keyId, algorithm: 'ES256', activatedAt: ago(20 * DAY) },
  previousKeys: [],
  rotationDays: 90,
  nextRotationAt: ahead(70 * DAY)
};

// TOTP enrolment fixtures (the secret is RFC 6238's SHA256 test seed).
export const mfaEnrollment = {
  secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA',
  otpauthUri: 'otpauth://totp/Citadel:alice?algorithm=SHA256&digits=6&issuer=Citadel&period=30&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA',
  issuer: 'Citadel',
  account: 'alice',
  algorithm: 'SHA256',
  digits: 6,
  period: 30
};
export const mfaRecoveryCodes = Array.from({ length: 10 }, (_, i) => `k7qm-x2pa-${String(i).padStart(4, 'a')}`);
/** The code the mock accepts. */
export const MFA_CODE = '123456';
// GET /v1/secrets/rotation for STRIPE_KEY: a random rotator whose retries
// ran out.
const stripeRotation = {
  enabled: true,
  mode: 'builtin',
  lambdaArn: `arn:citadel:rotator:us-east-1:${ACCOUNT}:random`,
  rotator: { type: 'random', config: { length: 40 } },
  schedule: { afterDays: 30 },
  nextRotationDate: ago(DAY),
  windowEnd: ahead(DAY),
  lastRotatedDate: ago(31 * DAY),
  status: 'failed',
  lastStep: 'testSecret',
  lastError: 'the pending value is empty',
  attempts: 5,
  nextAttemptAt: ahead(29 * DAY),
  pendingVersionId: 'v-pending-0123456789',
  due: true,
  history: [
    { versionId: 'v-pending-0123456789', rotator: 'random', trigger: 'retry', status: 'failed', step: 'testSecret', error: 'the pending value is empty', startedAt: ago(DAY), finishedAt: ago(DAY) },
    { versionId: 'v-current', rotator: 'random', trigger: 'schedule', status: 'succeeded', step: 'finishSecret', startedAt: ago(31 * DAY), finishedAt: ago(31 * DAY) }
  ]
};

/** Non-GET handlers by "METHOD path". Anything else gets {ok:true}. */
const WRITE: Record<string, Handler> = {
  'POST /v1/login': () => me,
  'POST /v1/account/mfa/enroll/start': () => mfaEnrollment,
  'POST /v1/account/mfa/disable': () => ({ disabled: true }),
  'POST /v1/account/mfa/recovery-codes': () => ({ recoveryCodes: mfaRecoveryCodes }),
  'POST /v1/admin/users/mfa/reset': (_, b) => ({ reset: b.confirm === b.username, sessionsRevoked: 2 }),
  'POST /v1/secrets/rotation': (_, b) => ({
    configured: true,
    builtin: !!b.rotator,
    ...(b.rotateImmediately ? { versionId: 'v-new-0123456789' } : {}),
    ...((b.rotator as { type?: string } | undefined)?.type === 'webhook' ? { signingSecret: 'whsec_mock0123456789abcdef0123456789abcdef' } : {})
  }),
  'POST /v1/secrets/rotation/rotate': () => ({ started: true, versionId: 'v-new-0123456789' }),
  'POST /v1/secrets/rotation/signing-secret': () => ({ signingSecret: 'whsec_mock_regenerated_0123456789abcdef' }),
  'POST /v1/logout': () => ({ loggedOut: true }),
  'POST /v1/kms/keys/schedule-deletion': (_, b) => ({ keyId: b.keyId, deletionDate: ahead(Number(b.windowDays ?? 30) * DAY) }),
  'POST /v1/kms/keys/cancel-deletion': (_, b) => ({ keyId: b.keyId, restored: true }),
  'POST /v1/kms/keys': () => ({ keyId: '5555eeee-0000-4000-8000-000000000005', arn: `arn:aws:kms:us-east-1:${ACCOUNT}:key/5555eeee-0000-4000-8000-000000000005`, created: true }),
  'POST /v1/kms/keys/enabled': (_, b) => ({ keyId: b.keyId, enabled: b.enabled }),
  'POST /v1/kms/keys/rotation': (_, b) => ({
    keyId: b.keyId,
    supported: true,
    enabled: !!b.enabled,
    rotationPeriodDays: Number(b.rotationPeriodDays ?? 365),
    nextRotationAt: b.enabled ? ahead(Number(b.rotationPeriodDays ?? 365) * DAY) : undefined,
    history: []
  }),
  'POST /v1/kms/keys/rotate': (_, b) => ({
    keyId: b.keyId,
    supported: true,
    enabled: false,
    rotationPeriodDays: 365,
    lastRotatedAt: ago(0),
    history: [{ rotatedAt: ago(0), kind: 'on-demand', keyMaterialId: 'km-2' }]
  }),
  'POST /v1/kms/grants': () => ({ grantId: 'grant-1', grantToken: 'grant-token-1' }),
  'DELETE /v1/kms/grants': () => ({ revoked: true }),
  'DELETE /v1/certificates/acm': (q) => ({ arn: q.get('arn'), deleted: true }),
  'DELETE /v1/certificates': (q) => ({ source: q.get('source'), id: q.get('id'), deleted: true, revoked: q.get('source') === 'pca-cert' }),
  'POST /v1/certificates/authorities/status': (_q, b) => ({ caId: b.caId, status: b.status }),
  'POST /v1/certificates/authorities/delete': (_q, b) => ({ caId: b.caId, status: 'DELETED', restorableUntil: ahead(Number(b.permanentDeletionTimeInDays) * DAY) }),
  'POST /v1/certificates/authorities/restore': (_q, b) => ({ caId: b.caId, status: 'DISABLED' }),
  'POST /v1/certificates/letsencrypt/auto-renew': (_q, b) => ({ certId: b.certId, renewal: { kind: 'http-01', autoRenew: b.autoRenew, manual: false } }),
  'POST /v1/kms/keys/tags': () => ({ tagged: true }),
  'DELETE /v1/kms/keys/tags': () => ({ untagged: true }),
  'POST /v1/kms/encrypt': (_, b) => ({ keyId: b.keyId, ciphertextBlob: 'Y2lwaGVydGV4dA==', encryptionAlgorithm: b.encryptionAlgorithm }),
  'POST /v1/kms/decrypt': (_, b) => ({ keyId: b.keyId, plaintext: 'aGVsbG8=', encryptionAlgorithm: b.encryptionAlgorithm }),
  'POST /v1/kms/sign': (_, b) => ({ keyId: b.keyId, signature: 'c2lnbmF0dXJl', signingAlgorithm: b.signingAlgorithm }),
  'POST /v1/kms/verify': (_, b) => ({ keyId: b.keyId, signatureValid: true, signingAlgorithm: b.signingAlgorithm }),
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
  'POST /v1/admin/sso/providers/test': () => ({ ok: true, message: 'discovery document fetched', authorizationEndpoint: 'https://idp.acme.test/authorize' }),
  'POST /v1/iam/oidc-providers': (_, b) => ({ providerArn: `arn:aws:iam::${ACCOUNT}:oidc-provider/${String(b.url).replace(/^https:\/\//, '')}` }),
  'POST /v1/iam/oidc-providers/update': (_, b) => ({ providerArn: b.providerArn, updated: true }),
  'DELETE /v1/iam/oidc-providers': () => ({ deleted: true }),
  'POST /v1/iam/roles': (_, b) => ({ roleArn: `arn:aws:iam::${ACCOUNT}:role/${b.roleName}` }),
  'POST /v1/iam/roles/update': (_, b) => ({ roleArn: `arn:aws:iam::${ACCOUNT}:role/${b.roleName}`, updated: true }),
  'DELETE /v1/iam/roles': () => ({ deleted: true }),
  'POST /v1/workload-identity/issuer/settings': (_, b) => ({ ...issuerInfo, ...b }),
  'POST /v1/workload-identity/issuer/rotate': () => issuerInfo,
  'POST /v1/workload-identity/clients': () => ({ clientId: 'wic-0123456789ab' }),
  'POST /v1/workload-identity/clients/update': (_, b) => ({ clientId: b.clientId, updated: true }),
  'DELETE /v1/workload-identity/clients': () => ({ deleted: true }),
  'POST /v1/agents': (_, b) => ({ ...agentList[0], agentId: 'agt_newnewnewnewnewnewne', name: b.name, description: b.description ?? '', grantCount: 0, activeTokenCount: 0, bindingCount: 0 }),
  'POST /v1/agents/update': (_, b) => ({ ...agentList[0], ...b }),
  'DELETE /v1/agents': () => ({ deleted: true }),
  'POST /v1/agents/suspend': (_, b) => ({ ...(agentList.find((a) => a.agentId === b.agentId) ?? agentList[0]), status: 'suspended' }),
  'POST /v1/agents/resume': (_, b) => ({ ...(agentList.find((a) => a.agentId === b.agentId) ?? agentList[0]), status: 'active' }),
  'POST /v1/agents/revoke': (_, b) => ({ ...(agentList.find((a) => a.agentId === b.agentId) ?? agentList[0]), status: 'revoked' }),
  'POST /v1/agents/tokens': (_, b) => ({ token: AGENT_TOKEN, tokenInfo: { tokenId: 'atk_cccccccccccccccc', name: b.name, prefix: `cagt_${AGENT_ID}_mocksecr`, status: 'active', createdAt: new Date().toISOString() } }),
  'POST /v1/agents/tokens/revoke': () => ({ revoked: true }),
  'POST /v1/agents/bindings': (_, b) => ({ bindingId: 'abd_bbbbbbbbbbbbbbbb', ...b, createdAt: new Date().toISOString() }),
  'DELETE /v1/agents/bindings': () => ({ deleted: true }),
  'POST /v1/agents/grants': (_, b) => ({ ...agentGrants[0], ...b }),
  'DELETE /v1/agents/grants': () => ({ deleted: true }),
  'POST /v1/agents/credentials': (_, b) => ({ ...agentCredentials[0], ...b, grants: [] }),
  'POST /v1/agents/credentials/update': (_, b) => ({ ...agentCredentials[0], ...b }),
  'DELETE /v1/agents/credentials': () => ({ deleted: true }),
  'POST /v1/agents/settings': (_, b) =>
    b.agentsSuspended ? { agentsSuspended: true, suspendedAt: new Date().toISOString(), suspendedBy: me.username, reason: b.reason } : { agentsSuspended: false }
};

/** A small OpenAPI document in the docs/openapi.yaml subset, for /api-reference. */
export const openapiYaml = `openapi: 3.1.0
info:
  title: Citadel native API
  version: 2.1.0
security:
  - sessionCookie: []
  - bearerAccessKey: []
tags:
  - name: Secrets
    description: Items in project, environment and folder paths.
  - name: KMS
  - name: Server
paths:
  /v1/secrets:
    get:
      operationId: listSecrets
      tags: [Secrets]
      summary: List the items in a folder
      description: |
        Values are never included; use getSecretValue.
      x-citadel-role: viewer
      parameters:
        - name: project
          in: query
          required: true
          schema:
            type: string
        - name: env
          in: query
          required: true
          schema:
            type: string
      responses:
        "200":
          description: The folder listing
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/SecretListing"
        "401":
          $ref: "#/components/responses/Unauthorized"
    post:
      operationId: putSecret
      tags: [Secrets]
      summary: Create or update an item
      x-citadel-role: editor
      x-citadel-audit: citadel.PutItem
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/PutSecretRequest"
      responses:
        "200":
          description: Saved
        "409":
          $ref: "#/components/responses/Conflict"
  /v1/kms/encrypt:
    post:
      operationId: kmsEncrypt
      tags: [KMS]
      summary: Encrypt with a KMS key
      x-citadel-role: editor
      x-citadel-audit: citadel.KMSEncrypt
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [keyId, plaintext]
              properties:
                keyId:
                  type: string
                plaintext:
                  type: string
                  format: byte
      responses:
        "200":
          description: The ciphertext
  /v1/openapi.yaml:
    get:
      operationId: getOpenAPISpec
      tags: [Server]
      summary: This document
      x-citadel-role: public
      security: []
      responses:
        "200":
          description: The OpenAPI document
          content:
            application/yaml:
              schema:
                type: string
components:
  schemas:
    Error:
      type: object
      required: [error, message]
      properties:
        error:
          type: string
          description: Stable machine-readable code
        message:
          type: string
    Tag:
      type: object
      properties:
        key:
          type: string
        value:
          type: string
    SecretItem:
      type: object
      required: [key, updatedAt]
      properties:
        key:
          type: string
        updatedAt:
          type: string
          format: date-time
        tags:
          type: array
          items:
            $ref: "#/components/schemas/Tag"
    SecretListing:
      type: object
      properties:
        folders:
          type: array
          items:
            type: string
        items:
          type: array
          items:
            $ref: "#/components/schemas/SecretItem"
    PutSecretRequest:
      type: object
      required: [project, env, key]
      properties:
        project:
          type: string
        env:
          type: string
        key:
          type: string
        value:
          type: string
  responses:
    Unauthorized:
      description: Authentication required
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/Error"
    Conflict:
      description: Approval required
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/Error"
`;

/** Non-JSON GET responses (downloads). */
const RAW: Record<string, (q: URLSearchParams) => { contentType: string; body: string }> = {
  '/v1/openapi.yaml': () => ({ contentType: 'application/yaml', body: openapiYaml }),
  '/v1/audit/export': (q) =>
    q.get('format') === 'json'
      ? { contentType: 'application/json', body: JSON.stringify(auditRows) }
      : {
          contentType: 'text/csv',
          body: 'id,chainSeq,createdAt,actor,actorType,action,result\n' + auditRows.map((r) => [r.id, r.chainSeq, r.createdAt, r.actor, r.actorType, r.action, r.result].join(',')).join('\n')
        }
};

/** Endpoints that answer without a session. */
const PUBLIC = new Set(['/v1/openapi.yaml', '/v1/server/info', '/v1/auth/providers', '/v1/bootstrap', '/v1/login', '/v1/login/mfa']);

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

  /** POST /v1/login asks for a second factor (MFA_CODE or a recovery code). */
  mfaLogin = false;
  /** The session is restricted to MFA enrolment (organization policy). */
  mfaEnrollmentRequired = false;
  /** GET /v1/account/mfa state. */
  mfaEnabled = false;

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
    if (method === 'POST' && path === '/v1/login' && this.mfaLogin) {
      return route.fulfill({ status: 200, json: { mfaRequired: true, mfaToken: 'mock-mfa-token' } });
    }
    if (method === 'POST' && path === '/v1/login/mfa') {
      const good = body.mfaToken === 'mock-mfa-token' && (body.code === MFA_CODE || mfaRecoveryCodes.includes(String(body.recoveryCode ?? '').toLowerCase()));
      if (!good) return route.fulfill({ status: 401, json: { error: 'invalid_code', message: 'invalid or already used code' } });
      this.signedIn = true;
      return route.fulfill({ status: 200, json: me });
    }
    if (method === 'POST' && path === '/v1/login') this.signedIn = true;
    if (method === 'POST' && path === '/v1/logout') this.signedIn = false;
    if (method === 'GET' && path === '/v1/me' && this.mfaEnrollmentRequired) {
      return route.fulfill({ status: 200, json: { ...me, mfaEnrollmentRequired: true } });
    }
    if (method === 'GET' && path === '/v1/account/mfa') {
      return route.fulfill({
        status: 200,
        json: { enabled: this.mfaEnabled, pending: false, enabledAt: this.mfaEnabled ? ago(DAY) : undefined, recoveryCodesLeft: this.mfaEnabled ? 10 : 0, required: this.mfaEnrollmentRequired, algorithm: 'SHA256', digits: 6, period: 30 }
      });
    }
    if (method === 'POST' && path === '/v1/account/mfa/enroll/confirm') {
      if (body.code !== MFA_CODE) return route.fulfill({ status: 400, json: { error: 'invalid_code', message: 'that code is not valid; check the time on your device and try again' } });
      const upgraded = this.mfaEnrollmentRequired;
      this.mfaEnrollmentRequired = false;
      this.mfaEnabled = true;
      return route.fulfill({ status: 200, json: { enabled: true, recoveryCodes: mfaRecoveryCodes, ...(upgraded ? { me } : {}) } });
    }

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
