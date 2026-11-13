# @worlddrknss/citadel

TypeScript client for [Citadel](https://github.com/worlddrknss/citadel)'s native `/v1` API: secrets, parameters, KMS, certificates and workload identity, built for Next.js and Node.js.

- No runtime dependencies. It uses the global `fetch` and runs on Node 18+ and edge runtimes.
- ESM and CommonJS builds with types generated from Citadel's OpenAPI spec.
- Retries rate limits and transient failures with backoff (never repeating a POST that may have taken effect), honours `Retry-After`, and times out each attempt.
- `CitadelAgent`: typed Agent API client for AI agents (brokered HTTP, reveal, logins, TOTP, access requests and leases).
- `loadSecrets` loads a folder of secrets with an in-memory cache.
- Includes the `citadel mcp` stdio bridge for AI agents.
- **Server-only.** The client holds an access key and returns secret values; it refuses to load in a browser.

**Documentation:** [docs/sdk-typescript.md](https://github.com/worlddrknss/citadel/blob/main/docs/sdk-typescript.md) (also in the console under **Docs → SDKs → TypeScript SDK**): configuration, Next.js route handlers, server components and `next.config`, caching, KMS, the Agent API, errors and retries, and the MCP bridge. Which SDK to use and how each authenticates: [docs/sdks.md](https://github.com/worlddrknss/citadel/blob/main/docs/sdks.md).

## Install

The package is not published to npm yet. Build it from the repository and install the tarball:

```sh
git clone https://github.com/worlddrknss/citadel.git
cd citadel/sdk/typescript && npm ci && npm run build && npm pack
# in your app:
npm install /path/to/worlddrknss-citadel-2.6.0.tgz
```

See [Install](https://github.com/worlddrknss/citadel/blob/main/docs/sdk-typescript.md#install) for vendoring the tarball so CI can install it.

## Quick start

Create an access key in the Citadel console (**My account → Access keys**) and set `CITADEL_URL`, `CITADEL_ACCESS_KEY_ID` and `CITADEL_SECRET_ACCESS_KEY`.

```ts
// app/api/orders/route.ts (Next.js)
import 'server-only';
import { Citadel } from '@worlddrknss/citadel';

const citadel = new Citadel();

export async function GET() {
  const apiKey = await citadel.secrets.getValue({ project: 'shop', env: 'prod', key: 'PAYMENTS_API_KEY' });
  const orders = await fetch('https://payments.example.com/orders', { headers: { Authorization: `Bearer ${apiKey}` } });
  return Response.json(await orders.json());
}
```

## Development

```sh
npm ci
npm run generate   # regenerate src/generated/openapi.ts from ../../docs/openapi.yaml
npm run lint && npm run typecheck
npm test           # unit tests, docs examples, and integration tests against the real server
npm run build      # dist/esm and dist/cjs
```

The integration tests build `cmd/server` with Go and run it with the in-memory store. When `CITADEL_SDK_TEST_DB_URL` points at an **empty** PostgreSQL database, they also bootstrap a deployment and exercise bearer access-key authentication. Without Go they are skipped; `CITADEL_SDK_SKIP_INTEGRATION=1` skips them too. The examples in `docs/sdk-typescript.md` are kept in `test/docs-examples.test.ts`, where they are typechecked and run. The first line of the generated types records the spec's SHA-256, and the Go test `TestOpenAPITypeScriptTypesCurrent` fails when it no longer matches.

## License

AGPL-3.0-or-later, the same license as Citadel.
