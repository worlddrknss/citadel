# @worlddrknss/citadel

TypeScript client for [Citadel](https://github.com/worlddrknss/citadel)'s native `/v1` API: secrets, parameters, KMS, certificates and workload identity.

- No runtime dependencies. It uses the global `fetch` and runs on Node 18+ and edge runtimes (Next.js route handlers, server components, middleware, Vercel Edge, Cloudflare Workers).
- Ships ESM and CommonJS builds with `.d.ts` types. Request and response types are generated from Citadel's OpenAPI spec (`docs/openapi.yaml`).
- Retries 429 and 5xx responses with exponential backoff and jitter, and honours `Retry-After`. Every attempt has a timeout, enforced with an `AbortSignal`.
- Failed calls throw `CitadelError`, which carries the API's stable error code.
- **Server-only.** The client holds an access key and returns secret values. See [Keep it on the server](#keep-it-on-the-server).

## Install

```sh
npm install @worlddrknss/citadel
```

## Credentials

Create an access key in the Citadel console (**Account → Access keys**) or with `POST /v1/account/keys`. The key acts with its owner's role in the key's account: viewers can read, editors can write, and admins can manage. Configure it through environment variables:

```sh
CITADEL_URL=https://citadel.example.com
CITADEL_ACCESS_KEY_ID=AKIA...
CITADEL_SECRET_ACCESS_KEY=...
```

`new Citadel()` reads these variables when you don't pass the options yourself.

## Next.js (App Router)

### Route handler

```ts
// app/api/orders/route.ts
import 'server-only';
import { Citadel, CitadelError } from '@worlddrknss/citadel';

const citadel = new Citadel({
  baseUrl: process.env.CITADEL_URL,
  accessKeyId: process.env.CITADEL_ACCESS_KEY_ID,
  secretAccessKey: process.env.CITADEL_SECRET_ACCESS_KEY,
});

export async function GET() {
  try {
    const apiKey = await citadel.secrets.getValue(
      { project: 'shop', env: 'prod', key: 'PAYMENTS_API_KEY' },
      { next: { revalidate: 300 } }, // Next.js data cache, server-side only
    );
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

### Loading a folder: `loadSecrets`

`loadSecrets` returns every key in one folder as a `Record<string, string>`:

```ts
// lib/secrets.ts
import 'server-only';
import { loadSecrets } from '@worlddrknss/citadel';

export function appSecrets() {
  return loadSecrets({
    project: 'shop',
    env: process.env.NODE_ENV === 'production' ? 'prod' : 'dev',
    path: 'web',                 // optional folder; omit for the environment root
    prefix: 'STRIPE_',           // optional: only keys starting with this
    ttl: 60_000,                 // in-memory freshness (ms), default 60s; 0 disables
    staleWhileRevalidate: 300_000, // serve stale for up to 5 more minutes while refreshing
    revalidate: 300,             // passed to fetch as next: { revalidate }
  });
}
```

```tsx
// app/checkout/page.tsx (server component)
import { appSecrets } from '@/lib/secrets';

export default async function Checkout() {
  const { STRIPE_PUBLISHABLE_KEY } = await appSecrets();
  return <CheckoutForm publishableKey={STRIPE_PUBLISHABLE_KEY} />;
}
```

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `project`, `env` | required | The environment to read. |
| `path` | root | Folder path, e.g. `api/db`. Sub-folders are not included. |
| `prefix` | none | Keep only keys that start with this prefix. Keys are returned unchanged. |
| `ttl` | `60000` | How long a result stays fresh in memory, in ms. `0` disables the cache. |
| `staleWhileRevalidate` | `300000` | After `ttl` expires, how long (in ms) a stale result is still served while a background refresh runs. A failed refresh keeps serving the stale result. |
| `revalidate`, `tags` | none | Passed to `fetch` as `next: { revalidate, tags }` for the Next.js data cache. |
| `inject` | `false` | Also sets `process.env[KEY]` for each key that isn't already set. |
| `concurrency` | `8` | Maximum number of value reads in flight at once. |
| `client` | from env | A `Citadel` instance to use instead of one built from environment variables. |

Concurrent calls for the same folder share a single load. The listing API returns a whole folder in one response, so there is no pagination. `loadSecrets` lists the folder, then reads each value (each read is audited in Citadel). It skips items that are scheduled for deletion and binary values.

### Build-time loading in `next.config.js`

Load secrets once when the server starts or the app builds, and expose them as server-side environment variables:

```js
// next.config.mjs
import { loadSecrets } from '@worlddrknss/citadel';

// Sets process.env.DATABASE_URL etc. for keys that are not already set, so
// local .env files and platform variables still take precedence.
await loadSecrets({ project: 'shop', env: 'prod', path: 'web', inject: true, ttl: 0 });

/** @type {import('next').NextConfig} */
export default {};
```

Do **not** copy secrets into the `env` key of `next.config.js` or into `NEXT_PUBLIC_*` variables. Next.js inlines both into the client bundle.

CommonJS works too:

```js
// next.config.js
const { loadSecrets } = require('@worlddrknss/citadel');

module.exports = async () => {
  await loadSecrets({ project: 'shop', env: 'prod', inject: true, ttl: 0 });
  return {};
};
```

### Keep it on the server

Secrets must never reach the browser. The package protects you in three ways:

1. Its `package.json` `exports` map sends the `browser` condition to an entry that throws on import. When a client component imports the SDK, the bundle fails as soon as it loads. Server conditions (`node`, `edge-light`, `workerd`, `worker`) come first, so server, edge and middleware bundles get the real client.
2. The module also throws when it's evaluated in a browser (a `window` and `document` without Node.js), and so does the `Citadel` constructor.
3. Next.js has its own guard. Add `import 'server-only'` to every module that uses the SDK. Next.js then fails the **build** with a clear error if a client component imports that module, even indirectly:

   ```sh
   npm install server-only
   ```

   ```ts
   // lib/citadel.ts
   import 'server-only';
   import { Citadel } from '@worlddrknss/citadel';
   export const citadel = new Citadel();
   ```

Pass values to client components only when they are meant to be public, such as a publishable key.

## Node.js

```ts
import { Citadel, CitadelError } from '@worlddrknss/citadel';

const citadel = new Citadel({
  baseUrl: 'https://citadel.example.com',
  accessKeyId: process.env.CITADEL_ACCESS_KEY_ID,
  secretAccessKey: process.env.CITADEL_SECRET_ACCESS_KEY,
  timeoutMs: 10_000, // per attempt (default 30s)
  maxRetries: 3,     // for 429/5xx and network errors (default 3)
});

// Secrets: project / environment / folder / key
await citadel.secrets.put({ project: 'billing', env: 'prod', path: 'db', key: 'PASSWORD', value: 'hunter2hunter2' });
const listing = await citadel.secrets.list({ project: 'billing', env: 'prod', path: 'db' }); // no values
const password = await citadel.secrets.getValue({ project: 'billing', env: 'prod', path: 'db', key: 'PASSWORD' });
const versions = await citadel.secrets.versions({ project: 'billing', env: 'prod', path: 'db', key: 'PASSWORD' });
await citadel.secrets.delete({ project: 'billing', env: 'prod', path: 'db', key: 'PASSWORD' }); // restorable
await citadel.secrets.restore({ project: 'billing', env: 'prod', path: 'db', key: 'PASSWORD' });

// Parameters
await citadel.parameters.put({ name: '/billing/prod/region', type: 'String', value: 'eu-west-1' });
const { value } = await citadel.parameters.get('/billing/prod/region');

// KMS
const [key] = await citadel.kms.listKeys();
const { ciphertextBlob } = await citadel.kms.encrypt({ keyId: key.keyId, plaintext: 'card-token' });
const plaintext = await citadel.kms.decryptText({ keyId: key.keyId, ciphertextBlob });

// Certificates
const certs = await citadel.certificates.list();
const issued = await citadel.certificates.issueGenerated({
  caId: 'ca-id', commonName: 'api.internal', keyAlgorithm: 'EC_prime256v1', validityDays: 30,
});

// Workload identity: a short-lived OIDC ID token for a registered client
const { token, expiresAt } = await citadel.workloadIdentity.token({ clientId: 'ci-deployer', audience: 'sts.amazonaws.com' });
```

Access-key workload clients authenticate with the client's own access key. For Kubernetes clients, pass `kubernetesToken` (the pod's projected service account token).

For any `/v1` operation without a typed method, use `citadel.request()` with the generated types:

```ts
import type { components } from '@worlddrknss/citadel';
type Detail = components['schemas']['SecretDetail'];
const detail = await citadel.request<Detail>({
  method: 'GET', path: '/v1/secrets/detail', query: { project: 'billing', env: 'prod', key: 'PASSWORD' },
});
```

## Errors, retries and timeouts

Every failure throws a `CitadelError`:

| Field | Meaning |
| --- | --- |
| `status` | HTTP status. `0` means no response arrived. |
| `code` | The API's stable `error` code: `not_found`, `unauthorized`, `forbidden`, `invalid_request`, `approval_required` (the environment needs a change request), `reveal_forbidden` (viewers can't read values in this account), `rate_limited`, and others. The client's own codes are `timeout`, `connection_error` and `invalid_response`. |
| `message` | A human-readable explanation. Don't branch on it. |
| `operation`, `attempts`, `retryAfterMs` | The request, how many attempts were made, and the server's `Retry-After` hint. |

`CitadelTimeoutError` and `CitadelConnectionError` are subclasses. `CitadelError.is(err, 'not_found')` checks an error without `instanceof`, so it also works across bundles.

Retry rules:

- 429, 500, 502, 503 and 504 responses are retried for every method, up to `maxRetries` times (3 by default), with full-jitter exponential backoff starting at `retryBaseDelayMs` (200 ms).
- A `Retry-After` header is honoured, capped at `retryMaxDelayMs` (10 s).
- Network errors and timeouts are retried only for GET and DELETE. Without a response, the client can't know whether the server already applied the request.

Every method takes per-call options as its last argument:

```ts
const ac = new AbortController();
await citadel.secrets.list(
  { project: 'web', env: 'prod' },
  { signal: ac.signal, timeoutMs: 5_000, maxRetries: 0, next: { revalidate: 60 }, cache: 'no-store' },
);
```

## Development

The source lives in `sdk/typescript` in the Citadel repository:

```sh
npm ci
npm run generate   # regenerate src/generated/openapi.ts from ../../docs/openapi.yaml
npm run lint && npm run typecheck
npm test           # unit tests and integration tests against the real server
npm run build      # dist/esm and dist/cjs
```

The integration tests build `cmd/server` with Go. They run it with the in-memory store in insecure dev mode. When `CITADEL_SDK_TEST_DB_URL` points at an **empty** PostgreSQL database, they also bootstrap a deployment and exercise bearer access-key authentication. Without Go, they are skipped; you can also skip them with `CITADEL_SDK_SKIP_INTEGRATION=1`. The first line of the generated types records the spec's SHA-256, and the Go test `TestOpenAPITypeScriptTypesCurrent` fails when it no longer matches.

## License

AGPL-3.0-or-later, the same license as Citadel.
