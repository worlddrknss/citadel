# SDKs and client libraries

Applications reach Citadel in one of four ways. This page helps you pick
one, shows how each authenticates, and explains how SDK versions relate to
server versions.

| You are building | Use | API |
| --- | --- | --- |
| A Next.js site, a Node.js service, or code on an edge runtime | [TypeScript SDK](sdk-typescript.md) (`@worlddrknss/citadel`) | Native `/v1` |
| A Go service, CLI or operator | [Go SDK](sdk-go.md) (`github.com/worlddrknss/citadel/sdk/citadel`) | Native `/v1` |
| Code that already uses AWS Secrets Manager, SSM Parameter Store or KMS, Terraform, External Secrets, or the AWS CLI | The official AWS SDKs and tools with a custom endpoint | AWS-compatible ([AWS compatibility](aws-compatibility.md)) |
| Another language, or a quick script | Plain HTTP against the [API reference](openapi.yaml) | Native `/v1` |
| An AI agent (Claude Code, Cursor, a browser agent) | The MCP server, directly or through the `citadel mcp` stdio bridge | `/mcp` ([Connecting MCP clients](agents-mcp.md)) |

## Which one?

**TypeScript, for Next.js and Node.js.** The TypeScript SDK has no runtime
dependencies, runs in route handlers, server components, server actions,
middleware and edge runtimes, and includes `loadSecrets`, which loads a
whole folder of secrets with an in-memory cache. Its types are generated
from the OpenAPI spec, so you can call any `/v1` operation with types, not
only the ones it wraps. Its `CitadelAgent` client covers the Agent API for
agents you write yourself, and it contains the `citadel mcp` stdio bridge
for AI agents.

**Go.** The Go SDK uses only the standard library. It wraps more of the API
than the TypeScript SDK: besides secrets, parameters, KMS and certificates,
it covers agent management and the Agent API, logins and TOTP, access
requests and leases, notification channels, and audit retention and chain
verification. Its `VerifyNotificationSignature` checks Citadel's webhook
signatures.

**The AWS SDKs.** Citadel serves AWS-compatible Secrets Manager, SSM
Parameter Store, KMS, STS and ACM APIs. If your code already uses
`@aws-sdk/client-secrets-manager`, `aws-sdk-go-v2`, boto3 or the AWS CLI,
point it at Citadel with a custom endpoint and nothing else changes. The
AWS APIs see a flat namespace: the secret `KEY` in folder `api` of
`shop/prod` is the Secrets Manager secret `shop/prod/api/KEY`. Projects,
folders, change requests, agents and the other Citadel features are only in
the native API.

```bash
export AWS_ACCESS_KEY_ID=AKIA... AWS_SECRET_ACCESS_KEY=... AWS_REGION=us-east-1
export AWS_ENDPOINT_URL=https://citadel.example.com
aws secretsmanager get-secret-value --secret-id shop/prod/api/DATABASE_URL
```

```ts
import { GetSecretValueCommand, SecretsManagerClient } from '@aws-sdk/client-secrets-manager';

// Credentials come from AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.
const sm = new SecretsManagerClient({ endpoint: 'https://citadel.example.com', region: 'us-east-1' });
const { SecretString } = await sm.send(new GetSecretValueCommand({ SecretId: 'shop/prod/api/DATABASE_URL' }));
```

**Plain HTTP.** Every server publishes its OpenAPI 3.1 description at
`GET /v1/openapi.yaml`, and the console renders it under **Help → API
reference**. Generate a client from it, or call it directly:

```bash
curl -H "Authorization: Bearer $CITADEL_ACCESS_KEY_ID:$CITADEL_SECRET_ACCESS_KEY" \
  "https://citadel.example.com/v1/secrets/value?project=shop&env=prod&path=api&key=DATABASE_URL"
```

## Authentication

Citadel has several kinds of credentials. Each API accepts only some of
them:

| Credential | Native `/v1` (TypeScript and Go SDKs, HTTP) | AWS-compatible APIs (AWS SDKs) | Agent API and `/mcp` |
| --- | --- | --- | --- |
| Access key (`AKIA...` and a secret) | Yes: `Authorization: Bearer <id>:<secret>`. The SDKs do this for you. | Yes: SigV4-signed | No |
| STS temporary credentials (`AssumeRole`, `AssumeRoleWithWebIdentity`) | No | Yes | No |
| Agent token (`cagt_...`) | No | No | Yes |
| Workload identity token matching an agent's federation binding | No | No | Yes |
| Console session | Used by the console only | No | No |

- **Access keys** are for applications. Create one under **My account →
  Access keys** (or with `POST /v1/account/keys`). A key acts with its
  owner's role in the key's account, never more: a viewer's key can read, an
  editor's key can write, and an admin's key can manage. Create a dedicated
  user with the least role an application needs, and give each application
  its own key so you can revoke it alone. The same key works for the native
  API and, signed with SigV4, for the AWS-compatible APIs.
- **Console sessions** are for people in the browser. They need a CSRF
  header and expire, so don't use them from code.
- **Agent tokens** are for AI agents, which never get secret values unless
  a grant allows a reveal. The Agent API (`/v1/agent/*`) and `/mcp` accept
  only agent credentials, and agent credentials work nowhere else. See
  [Credentials for AI agents](agents.md).
- **Workload identity.** Without a stored key, a pod or CI job can:
  - authenticate as an **agent** with its own OIDC token (for example a
    GitHub Actions ID token), sent as the bearer token, when the agent has a
    matching federation binding
    ([Workload identity federation](agents.md#workload-identity-federation));
  - exchange its OIDC token for **STS temporary credentials** with
    `AssumeRoleWithWebIdentity` and use the AWS SDKs
    ([AWS compatibility](aws-compatibility.md#sts-query-protocol)).

  In the other direction, Citadel can **issue** short-lived OIDC ID tokens to
  registered workload clients (`workloadIdentity.token` in TypeScript,
  `IssueWorkloadToken` in Go), for example for AWS STS or another system that
  trusts Citadel's issuer.

Keep credentials in your platform's secret store or environment variables,
never in source code. Code that holds an access key must run on a server:
never send it, or a secret it reads, to a browser.

## Install

| SDK | Install |
| --- | --- |
| TypeScript | Not yet published to npm. Build it from the repository; see [Install](sdk-typescript.md#install). |
| Go | `go get github.com/worlddrknss/citadel/sdk/citadel@main`, or pin a release; see [Install](sdk-go.md#install). |
| AWS SDKs | Your language's official AWS SDK, unchanged. |

## Versions and compatibility

Both SDKs live in the Citadel repository, next to the server, and change
with it. Use the SDK from the same release as your server, or an older one:

- **Newer servers add, older SDKs keep working.** Releases add operations
  and response fields; the SDKs ignore fields they don't know, so an older
  SDK keeps working against a newer server. A breaking change would be
  called out in the [changelog](../CHANGELOG.md). A newer SDK calling an
  operation that an older server doesn't have gets an error, usually `404`.
- **Features arrive with server versions.** Agents and the Agent API need
  Citadel 2.2, access requests and leases 2.3, logins, TOTP and minted
  credentials 2.4, and audit retention 2.5. The API deliberately doesn't
  disclose the server's version (`GET /v1/server/info` doesn't include it),
  so check the release you deployed, such as the image tag.
- **The SDK's own version number** (`package.json` and `VERSION` in
  TypeScript, `citadel.Version` in Go, sent in the `User-Agent` header) is
  the Citadel release the SDK ships with, from 2.6.0 on; the release
  workflow refuses a tag the SDKs don't match. (Before 2.6.0 it stayed at
  `2.1.0`.)
- **Go module versions.** The repository's Go module is
  `github.com/worlddrknss/citadel`, without a `/v2` suffix, so Go can't use
  the `v2.x.y` release tags directly and a bare `go get` resolves to an old
  `v1` release. Install from `@main` or from a release's commit, as shown in
  [Install](sdk-go.md#install).
- **The AWS-compatible APIs** follow the AWS wire protocols, so current AWS
  SDK versions work. Members Citadel doesn't model are ignored. The
  supported actions are listed in [AWS compatibility](aws-compatibility.md).

## Next steps

- [TypeScript SDK](sdk-typescript.md): Next.js examples, caching, KMS, the
  Agent API and the MCP bridge.
- [Go SDK](sdk-go.md): secrets, agents, approvals, notifications and audit.
- [API reference](openapi.yaml): every native operation.
