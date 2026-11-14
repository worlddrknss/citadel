# TypeScript SDK

`@worlddrknss/citadel` is the TypeScript client for Citadel's native `/v1`
API. It is built for Next.js and Node.js servers: it has no runtime
dependencies, ships ESM and CommonJS builds with types generated from the
OpenAPI spec, retries rate-limited and failed requests, and includes
`loadSecrets` for loading a folder of secrets with a cache. The package also
contains the `citadel mcp` stdio bridge for AI agents.

To choose between this SDK, the Go SDK and the AWS SDKs, see
[SDKs and client libraries](sdks.md).

Every example on this page is also in
[`sdk/typescript/test/docs-examples.test.ts`](../sdk/typescript/test/docs-examples.test.ts),
where it is typechecked and run against a mocked server.

## Install

```sh
npm install @worlddrknss/citadel
npm install server-only   # recommended for Next.js; see "Keep it on the server"
```

The package is published to npm from 2.6.0, with
[provenance](https://docs.npmjs.com/generating-provenance-statements), for
every Citadel release. Install the version that matches your server (see
[Versions and compatibility](sdks.md#versions-and-compatibility)).

To use an unreleased commit, build it from the repository and install the
tarball:

```sh
git clone https://github.com/worlddrknss/citadel.git
cd citadel/sdk/typescript
npm ci
npm run build
npm pack              # writes worlddrknss-citadel-<version>.tgz
```

Installing straight from GitHub (`npm install github:worlddrknss/citadel`)
doesn't work: the package is in a sub-directory and its build output isn't
committed.

## Configure

`new Citadel()` reads its settings from environment variables:

| Variable | Meaning |
| --- | --- |
| `CITADEL_URL` | Citadel's base URL, such as `https://citadel.example.com`. Required. |
| `CITADEL_ACCESS_KEY_ID` | The access key ID (`AKIA...`). |
| `CITADEL_SECRET_ACCESS_KEY` | The access key's secret. Set both or neither. |

Create the access key under **My account → Access keys** in the console. It
acts with its owner's role: a viewer's key can read, an editor's key can
write, and an admin's key can manage. The SDK sends it as
`Authorization: Bearer <id>:<secret>`, which only the native API accepts;
the AWS-compatible APIs need SigV4 (see [Authentication](sdks.md#authentication)).
Agent tokens go to `CitadelAgent` instead (see [The Agent API](#the-agent-api)).

Constructor options override the environment:

```ts
import { Citadel } from '@worlddrknss/citadel';

const citadel = new Citadel({
  baseUrl: 'https://citadel.example.com',
  accessKeyId: process.env.CITADEL_ACCESS_KEY_ID,
  secretAccessKey: process.env.CITADEL_SECRET_ACCESS_KEY,
  timeoutMs: 10_000, // per attempt (default 30 s; 0 disables)
  maxRetries: 3, // see Errors, retries and timeouts (default 3)
  retryBaseDelayMs: 200, // first backoff delay (default 200 ms)
  retryMaxDelayMs: 10_000, // longest single delay, Retry-After included (default 10 s)
  headers: { 'X-Request-Source': 'shop-web' }, // sent with every request
  // fetch: customFetch, // defaults to the global fetch
});
```

A `Citadel` instance is safe to share. Create one per process (a module
singleton) rather than one per request.

## Runtimes

- **Node.js 18 or later**, for the client and `loadSecrets`. The `citadel
  mcp` bridge needs Node.js 20 or later.
- **Edge runtimes**: Next.js middleware and edge route handlers, Vercel Edge
  and Cloudflare Workers. The SDK only needs the global `fetch`. On edge
  runtimes `process.env` may not exist (Cloudflare Workers without Node.js
  compatibility, for example), so pass `baseUrl` and the key to the
  constructor, and remember that each isolate has its own `loadSecrets`
  cache.
- **Browsers: never.** See below.

### Keep it on the server

The client holds an access key and returns secret values, so it must never
run in a browser, and neither the key nor a secret it reads may reach one.
The package guards against mistakes:

1. Its `exports` map sends the `browser` condition to an entry that throws on
   import, so a client component that imports the SDK fails as soon as its
   bundle loads. Server conditions (`node`, `edge-light`, `workerd`,
   `worker`) come first, so server, edge and middleware bundles get the real
   client.
2. The module and the `Citadel` constructor also throw when they run in a
   browser.
3. In Next.js, add `import 'server-only'` to every module that uses the SDK.
   The build then fails if a client component imports that module, even
   indirectly.

Also:

- Don't put secrets in `NEXT_PUBLIC_*` variables or in the `env` key of
  `next.config.js`: Next.js inlines both into the client bundle.
- Pass a value to a client component only when it is meant to be public,
  such as a publishable key.
- Don't render a secret into a statically generated page: the HTML is built
  once and served to everyone.

## Read secrets and parameters

Secrets are addressed by project, environment, optional folder path, and
key. Each value read is an audited reveal.

```ts
const ref = { project: 'shop', env: 'prod', path: 'api', key: 'DATABASE_URL' };

// The current value, as a string (throws `binary_value` for binary secrets).
const databaseUrl = await citadel.secrets.getValue(ref);

// The full response: version ID, and `resolve` expands ${...} references.
const previous = await citadel.secrets.get({ ...ref, versionStage: 'AWSPREVIOUS' });

// One folder: keys and metadata, never values.
const listing = await citadel.secrets.list({ project: 'shop', env: 'prod', path: 'api' });
const keys = listing.items.map((item) => item.key);

// Parameter Store: SecureString values come back decrypted.
const { value: region } = await citadel.parameters.get('/shop/prod/region');
```

A viewer's key can read values only where the account allows it; otherwise
reads fail with `reveal_forbidden`. `secrets.get` also takes `versionId` and
`resolve: true`; `parameters.get(name, { version })` reads an older version.

## Next.js

These examples use the App Router.

### A shared client

```ts
// lib/citadel.ts
import 'server-only';
import { Citadel } from '@worlddrknss/citadel';

export const citadel = new Citadel(); // CITADEL_URL, CITADEL_ACCESS_KEY_ID, CITADEL_SECRET_ACCESS_KEY
```

### Route handler

```ts
// app/api/orders/route.ts
import { CitadelError } from '@worlddrknss/citadel';
import { citadel } from '@/lib/citadel';

export async function GET(): Promise<Response> {
  try {
    const apiKey = await citadel.secrets.getValue({ project: 'shop', env: 'prod', key: 'PAYMENTS_API_KEY' }, { cache: 'no-store' });
    const orders = await fetch('https://payments.example.com/orders', {
      headers: { Authorization: `Bearer ${apiKey}` },
    });
    return Response.json(await orders.json());
  } catch (err) {
    if (CitadelError.is(err, 'not_found')) {
      return new Response('payments are not configured', { status: 503 });
    }
    throw err;
  }
}
```

The same code works in a server action.

### Server components: `loadSecrets`

`loadSecrets` returns every key in one folder as a `Record<string, string>`,
cached in memory:

```ts
// lib/secrets.ts
import 'server-only';
import { loadSecrets } from '@worlddrknss/citadel';

export function appSecrets() {
  return loadSecrets({
    project: 'shop',
    env: process.env.NODE_ENV === 'production' ? 'prod' : 'dev',
    path: 'web',
    prefix: 'STRIPE_',
    ttl: 60_000,
    staleWhileRevalidate: 300_000,
  });
}
```

```tsx
// app/checkout/page.tsx
import { appSecrets } from '@/lib/secrets';
import { CheckoutForm } from './checkout-form';

export default async function Checkout() {
  const { STRIPE_PUBLISHABLE_KEY } = await appSecrets();
  return <CheckoutForm publishableKey={STRIPE_PUBLISHABLE_KEY} />;
}
```

| Option | Default | Meaning |
| --- | --- | --- |
| `project`, `env` | required | The environment to read. |
| `path` | root | Folder path, such as `api/db`. Sub-folders are not included. |
| `prefix` | none | Keep only keys that start with this prefix. Keys are returned unchanged. |
| `ttl` | `60000` | How long a result stays fresh in memory, in ms. `0` disables the cache. |
| `staleWhileRevalidate` | `300000` | After `ttl`, how long (ms) a stale result is still served while a background refresh runs. A failed refresh keeps serving the stale result. |
| `revalidate`, `tags` | none | Passed to `fetch` as `next: { revalidate, tags }` (the Next.js Data Cache; see below). |
| `inject` | `false` | Also set `process.env[KEY]` for each key that isn't already set. |
| `concurrency` | `8` | Maximum value reads in flight at once. |
| `client` | from env | A `Citadel` instance to use instead of one built from environment variables. |
| `signal` | none | Aborts loading. |

Concurrent calls for the same folder share one load. `loadSecrets` lists the
folder, then reads each value; it skips items scheduled for deletion and
binary values.

### Build time: `next.config`

Load secrets once when the server starts or the app builds, as server-side
environment variables:

```js
// next.config.mjs
import { loadSecrets } from '@worlddrknss/citadel';

// Sets process.env.DATABASE_URL etc. for keys that are not already set, so
// local .env files and platform variables still take precedence.
await loadSecrets({ project: 'shop', env: 'prod', path: 'web', inject: true, ttl: 0 });

/** @type {import('next').NextConfig} */
export default {};
```

`next.config.js` runs at build time and again when `next start` starts.
Values loaded there don't change until the next restart, so prefer
`loadSecrets` at request time for secrets that rotate.

### Caching

- **Prefer the in-memory cache.** `loadSecrets` keeps values in the server
  process for `ttl`, then serves them stale for up to
  `staleWhileRevalidate` while it refreshes. That saves latency and audit
  noise, and the values never leave memory. `clearSecretsCache()` empties
  it, for example after a rotation.
- **The Next.js Data Cache persists.** `revalidate`, `tags` and the per-call
  `next: { revalidate }` option store Citadel's responses, secret values
  included, in the Next.js Data Cache: on disk under `.next/cache` when you
  self-host, or in your platform's cache. They never reach the browser, but
  they then live outside Citadel. Use them only if that is acceptable, and
  pass `{ cache: 'no-store' }` for reads that must not be stored.
- **Rotation.** After a secret rotates, the old value can be served for up
  to `ttl + staleWhileRevalidate`. Keep the rotation's overlap window longer
  than that, or lower the TTLs.
- **One cache per process.** Serverless functions and edge isolates each
  have their own cache, so expect one load per cold start.

## KMS

```ts
const context = { tenant: '42' };
const { ciphertextBlob } = await citadel.kms.encrypt({
  keyId: 'alias/payments', // key ID, key ARN, alias or alias ARN
  plaintext: 'card-token', // string (UTF-8) or Uint8Array, up to 4 KB
  encryptionContext: context,
});
// Store ciphertextBlob (base64). Decrypt needs the same encryption context.
const plaintext = await citadel.kms.decryptText({ keyId: 'alias/payments', ciphertextBlob, encryptionContext: context });
```

`kms.decrypt` returns the plaintext as a `Uint8Array`; `kms.listKeys()`
lists the keys the caller can see. Encrypt and decrypt need the editor role.
For signing, key policies, grants and rotation, use `request()` (see
[Generated OpenAPI types](#generated-openapi-types)).

## The Agent API

AI agents authenticate with an agent token (`cagt_...`), not an access key,
and the Agent API (`/v1/agent/*`) accepts nothing else. See
[Credentials for AI agents](agents.md) for grants, kinds and refusals. Most
agents use the [MCP server](agents-mcp.md); call the Agent API from code
when you write the agent yourself.

`CitadelAgent` is the Agent API client. It reads `CITADEL_URL` and
`CITADEL_AGENT_TOKEN`, takes the same connection options as `Citadel`
(`timeoutMs`, `maxRetries`, `fetch`, `headers`...) and, like `Citadel`, is
server-only:

```ts
// lib/citadel-agent.ts
import { CitadelAgent } from '@worlddrknss/citadel';

export const agent = new CitadelAgent({
  baseUrl: 'https://citadel.example.com', // default: CITADEL_URL
  token: process.env.CITADEL_AGENT_TOKEN, // the default
  taskId: 'fix-issue-1234', // optional: X-Citadel-Task-Id on every call
});
```

The token is sent only in the `Authorization` header. It is kept in a
private field, so it doesn't show up when the client is logged, and never
appears in errors.

With a [federated token](agents.md#workload-identity-federation) (such as a
GitHub Actions ID token), pass it as `token`. If the identity is bound to
more than one agent, also pass the agent's ID: `agentId: 'agt_...'` (sent as
`X-Citadel-Agent-Id`).

| Method | Endpoint |
| --- | --- |
| `whoami()` | `GET /v1/agent/whoami` |
| `listCredentials()` | `GET /v1/agent/credentials` |
| `http(input)` | `POST /v1/agent/http` (brokered request) |
| `reveal(credential)` | `POST /v1/agent/credentials/reveal` |
| `getLogin({ credential, url })` | `POST /v1/agent/login` |
| `getTotpCode(credential)` | `POST /v1/agent/totp` |
| `requestAccess(input)` | `POST /v1/agent/access-requests` |
| `getAccessRequest(requestId)` | `GET /v1/agent/access-requests/{id}` |
| `waitForAccess(requestId, { intervalMs, signal })` | polls `getAccessRequest` until decided |
| `listLeases({ credential })` | `GET /v1/agent/leases` |

### Who am I, and brokered HTTP

```ts
const me = await agent.whoami();
const usable = (await agent.listCredentials()).filter((c) => c.usable).map((c) => c.name);

// Brokered HTTP: Citadel injects the credential; the agent never sees it.
const res = await agent.http({
  credential: 'github-pat',
  url: 'https://api.github.com/user/repos',
  headers: { Accept: 'application/vnd.github+json' },
});
const repos = res.ok ? res.json<unknown[]>() : [];

// A JSON body (`json`), text (`body: string`) or bytes (`body: Uint8Array`).
const issue = await agent.http({
  credential: 'github-pat',
  method: 'POST',
  url: 'https://api.github.com/repos/acme/app/issues',
  json: { title: 'Flaky test in CI' },
});
```

`method` defaults to `GET`. `json` sets `Content-Type: application/json`
unless `headers` has one; bytes are sent base64 encoded (the SDK sets
`bodyEncoding`). The result has the upstream's `status`, `headers`,
`truncated` and `redacted`, plus `ok`, `text()`, `bytes()` and `json()`,
which decode a base64 body for you. An upstream error status is a
successful brokered call: check `res.ok` or `res.status`.

### Reveal, logins and TOTP

```ts
// Needs a grant with `reveal`. Prefer brokered use when you only call an API.
const deployKey = await agent.reveal({ credential: 'deploy-key', taskId: 'release-42' });

// Browser agents: a login for one page (`reveal`), and its TOTP code (`totp`).
const login = await agent.getLogin({ credential: 'acme-admin', url: 'https://admin.acme.example/login' });
const { code, secondsRemaining } = await agent.getTotpCode('acme-admin');
```

Minted credentials (`github_app`, `oauth2_client_credentials`, `aws_sts`)
reveal a short-lived token with `expiresAt`; a reveal under a lease returns
`leaseId` and `leaseExpiresAt`. See
[Revealing a credential](agents.md#revealing-a-credential) and
[Logins for browser agents](agents.md#logins-for-browser-agents).

### Access requests and leases

```ts
// Ask a person for access, then wait for the decision (polls every 5 s by
// default; pass `signal` to give up).
const request = await agent.requestAccess({
  credential: 'deploy-key',
  actions: ['reveal'],
  reason: 'Tag the release; the pipeline needs the deploy key',
  duration: '15m',
  taskId: 'release-42',
});
const decided = await agent.waitForAccess(request.requestId);
if (decided.status !== 'approved') {
  throw new Error(`access ${decided.status}: ${decided.decisionComment ?? ''}`);
}
const leases = await agent.listLeases({ credential: 'deploy-key' });
```

Approving and denying happen in the console only. See
[Approvals and leases](agents.md#approvals-and-leases).

### Agent API errors

Agent API errors are JSON `{ error, reason, message }`, plus `requestId` for
`approval_required`. `CitadelError` carries all of them: `code` is `error`
(`forbidden`, `approval_required`, `upstream_error`...), `reason` the stable
reason (`no_grant`, `host_not_allowed`, `upstream_timeout`...) and
`requestId` the access request a `requiresApproval` grant opened. Wait for
that request and retry; there is no need to ask again:

```ts
try {
  return (await agent.reveal('deploy-key')).value;
} catch (err) {
  // A grant with requiresApproval: the error names the access request
  // Citadel opened. Wait for it, then retry under the lease.
  if (CitadelError.is(err, 'approval_required') && err.requestId) {
    const decided = await agent.waitForAccess(err.requestId);
    if (decided.status === 'approved') return (await agent.reveal('deploy-key')).value;
    return `not approved: ${decided.decisionComment ?? decided.status}`;
  }
  if (CitadelError.is(err) && err.isForbidden) {
    // err.reason: no_grant, action_not_granted, host_not_allowed, agent_suspended...
    return `refused: ${err.reason ?? err.code}`;
  }
  throw err;
}
```

`requestId` is missing when the agent already has 20 pending requests.

### Brokered calls and retries

`http`, `reveal`, `getLogin`, `getTotpCode` and `requestAccess` are POSTs, so
the client doesn't repeat them after a 500, 502 or 504, a 503 without
`Retry-After`, a timeout or a network error: the broker answers 502 or 504
when the upstream failed or timed out, possibly after it acted, and a retry
could charge a card or post a message twice. Rate limits (429) and a busy
broker (503 with `Retry-After`), which Citadel answers before sending
anything, are retried. When an upstream call is safe to repeat, opt in per
call:

```ts
// Not retried after a 502/504 or a timeout: the upstream may have acted.
const once = await agent.http({ credential: 'payments', method: 'POST', url: 'https://pay.example.com/charges', json: { amount: 100 } });
// An idempotent upstream call (an Idempotency-Key header): safe to retry.
const retried = await agent.http(
  {
    credential: 'payments',
    method: 'POST',
    url: 'https://pay.example.com/charges',
    headers: { 'Idempotency-Key': 'order-42' },
    json: { amount: 100 },
  },
  { retryNonIdempotent: true },
);
```

## Management

Typed methods cover the common management calls:

| Area | Methods |
| --- | --- |
| Caller | `me()` |
| Hierarchy | `projects.list`, `projects.create`, `projects.delete`, `environments.create`, `environments.delete`, `folders.create`, `folders.delete` |
| Secrets | `secrets.list`, `secrets.get`, `secrets.getValue`, `secrets.put`, `secrets.delete`, `secrets.restore`, `secrets.versions` |
| Parameters | `parameters.list`, `parameters.get`, `parameters.put`, `parameters.delete`, `parameters.history` |
| KMS | `kms.listKeys`, `kms.encrypt`, `kms.decrypt`, `kms.decryptText` |
| Certificates | `certificates.list`, `certificates.issue` (sign a CSR), `certificates.issueGenerated` (Citadel generates the key) |
| Workload identity | `workloadIdentity.token` |
| Access keys | `accessKeys.create` |

```ts
await citadel.projects.create({ slug: 'shop', name: 'Shop' });
await citadel.environments.create({ project: 'shop', slug: 'prod' });
await citadel.folders.create({ project: 'shop', env: 'prod', path: 'api' });
await citadel.secrets.put({ project: 'shop', env: 'prod', path: 'api', key: 'DATABASE_URL', value: 'postgres://example' });
const versions = await citadel.secrets.versions({ project: 'shop', env: 'prod', path: 'api', key: 'DATABASE_URL' });
await citadel.parameters.put({ name: '/shop/prod/region', type: 'String', value: 'eu-west-1', overwrite: true });

// Anything without a typed method: request() with the generated types.
const { agents } = await citadel.request<S['AgentList']>({ method: 'GET', path: '/v1/agents' });
```

`secrets.delete` schedules deletion (restorable with `secrets.restore`
during the recovery window) unless you pass `force: true`. Writing to an
environment that requires approval fails with `approval_required`; submit a
change request instead. Managing agents and grants, notification channels,
audit and the other areas have no typed methods; use `request()` or the
[Go SDK](sdk-go.md). (Agents themselves use [`CitadelAgent`](#the-agent-api).)

## Errors, retries and timeouts

Every failure throws a `CitadelError`:

| Field | Meaning |
| --- | --- |
| `status` | HTTP status. `0` means no response arrived. |
| `code` | The API's stable `error` code: `not_found`, `unauthorized`, `forbidden`, `invalid_request`, `approval_required`, `reveal_forbidden`, `rate_limited`, and others. The client's own codes are `timeout`, `connection_error`, `invalid_response` and `binary_value`. |
| `message` | A human-readable explanation. Don't branch on it. |
| `operation`, `attempts`, `retryAfterMs` | The request (`GET /v1/secrets`), how many attempts were made, and the server's `Retry-After` hint. |
| `reason`, `requestId` | Agent API only: the stable denial or failure reason (`no_grant`, `upstream_timeout`...) and, for `approval_required`, the access request to wait for. |
| `isNotFound`, `isUnauthorized`, `isForbidden`, `isApprovalRequired` | Shortcuts for 404, 401, 403 and `approval_required`. |

`CitadelTimeoutError` and `CitadelConnectionError` are subclasses.
`CitadelError.is(err, 'not_found')` checks an error without `instanceof`, so
it also works across bundles.

```ts
try {
  await citadel.secrets.put({ project: 'shop', env: 'prod', key: 'FEATURE_FLAG', value: 'on' });
} catch (err) {
  if (CitadelError.is(err, 'approval_required')) {
    // prod is protected: submit a change request instead.
  } else if (CitadelError.is(err, 'rate_limited')) {
    // Still limited after the retries; err.retryAfterMs says how long to wait.
  } else {
    throw err;
  }
}
```

Retries:

- Retries happen up to `maxRetries` times, with full-jitter exponential
  backoff from `retryBaseDelayMs`. A `Retry-After` header is honoured,
  capped at `retryMaxDelayMs`.
- 429, and 503 with `Retry-After`, are retried for every method: Citadel
  answers them before acting.
- 500, 502, 504, a 503 without `Retry-After`, network errors and timeouts
  are retried only for idempotent methods (GET, HEAD, PUT, DELETE). For a
  POST they can come after the request took effect (see
  [Brokered calls and retries](#brokered-calls-and-retries)); pass
  `retryNonIdempotent: true` for a call that is safe to repeat.
- `timeoutMs` bounds each attempt, not the whole call. Pass an
  `AbortSignal` to bound or cancel the call, retries included.

Every method takes per-call options as its last argument:

```ts
const ac = new AbortController();
await citadel.secrets.list({ project: 'shop', env: 'prod' }, { signal: ac.signal, timeoutMs: 5_000, maxRetries: 0, cache: 'no-store' });
```

`next: { revalidate, tags }` is accepted there too (see [Caching](#caching)).

## Generated OpenAPI types

The package exports the types generated from Citadel's
[OpenAPI spec](openapi.yaml): `components` (schemas), `paths` and
`operations`. Use them with `request()` for any `/v1` operation the client
doesn't wrap:

```ts
import type { components } from '@worlddrknss/citadel';

type Detail = components['schemas']['SecretDetail'];
const detail = await citadel.request<Detail>({
  method: 'GET',
  path: '/v1/secrets/detail',
  query: { project: 'shop', env: 'prod', key: 'DATABASE_URL' },
});
```

`request()` takes `method` (`GET`, `POST` or `DELETE`), `path`, `query`,
`body`, and `authorization` to override the `Authorization` header for one
call. It applies the same retries, timeouts and errors as the typed methods.
The request and response types of the typed methods (`SecretValue`,
`Parameter`, `KmsKey`...) are exported by name too.

## The `citadel mcp` stdio bridge

The package's `citadel` command includes a stdio bridge to Citadel's MCP
server, for MCP clients that only start local servers (Claude Desktop, for
example). It needs Node.js 20 or later and an agent token:

```sh
CITADEL_URL=https://citadel.example.com CITADEL_AGENT_TOKEN=cagt_... npx citadel mcp
```

In an MCP client's configuration, use `npx -y @worlddrknss/citadel mcp` as
the command; `npx` downloads the package on first use. Settings, behaviour and
per-client configuration are in [Connecting MCP clients](agents-mcp.md#the-stdio-bridge).

## Development

The source is in `sdk/typescript`:

```sh
npm ci
npm run generate   # regenerate src/generated/openapi.ts from docs/openapi.yaml
npm run lint && npm run typecheck
npm test           # unit tests, docs examples, and integration tests against the real server
npm run build      # dist/esm and dist/cjs
```

The integration tests build `cmd/server` with Go and are skipped without it
(or with `CITADEL_SDK_SKIP_INTEGRATION=1`).
