# Getting started

This page takes you from a fresh install to an application reading its
first secret. Each step links to the detailed guide when you need more.

## 1. Run Citadel

For a local evaluation with PostgreSQL, use the Compose stack:

```bash
cd deploy/compose
./generate-env.sh       # writes .env with random secrets, mode 0600
docker compose up -d
docker compose logs citadel | grep -i bootstrap   # one-time setup token
```

It serves plain HTTP on `http://localhost:8080`. It is for trying Citadel
out, not for production.

For production, install the Helm chart (`deploy/helm/citadel`) with its
keys in a Kubernetes Secret, and put TLS in front. [Deployment](deployment.md)
covers TLS, ingress, sizing, backups, upgrades, FIPS mode and verifying the
signed image; every setting is in [Configuration](configuration.md).

Back up the wrapping key (`KMS_WRAPPING_KEY_B64`) somewhere other than the
database backups as soon as it exists: without it, the data can't be
decrypted.

## 2. Create your organization

With no users yet, Citadel starts in **bootstrap mode**. Open
`<your Citadel URL>/app/`, enter the **Setup token** from the log, and fill
in the organization, the first account and the first administrator
(**Admin username** and password). Choose **Create organization**, then sign
in. The token works once; see [First run](deployment.md#first-run) for how
it is generated on Kubernetes.

Then:

- **Add people** under **Administration → Users → Create user**, with a
  role per account: viewer, editor or admin.
- **Turn on MFA** for your own sign-in under **My account**, and consider
  requiring it for the organization under **Administration → Settings**.
- **Sign in with your identity provider** (Okta, Entra ID, Google,
  Keycloak) instead of passwords: add an OIDC provider under
  **Administration → Settings → Single sign-on**.

## 3. Store your first secret

Secrets are organized as **project → environment → folder → key**.

1. Go to **Secrets** and choose **New project** (for example *Payments*).
2. In the project, choose **New environment** (*dev*, *prod*...).
   Environments can require approvals for changes, so a production change
   needs a second person.
3. In the environment, choose **Add secret**, enter a key such as
   `DATABASE_URL` and its value, and save.

Click a secret to open its drawer: its value, versions, rotation, access and
**Agent access**. Each secret is also an ordinary AWS Secrets Manager secret
named `project/env/KEY` (with folders in between), which is how the AWS
tools below find it. To rotate it on a schedule, see
[Secret rotation](rotation.md).

## 4. Read it from an application

Create an access key under **My account → Access keys**, then point any AWS
SDK or the AWS CLI at Citadel:

```bash
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=us-east-1

aws --endpoint-url https://citadel.example.com \
  secretsmanager get-secret-value --secret-id payments/prod/DATABASE_URL
```

Supported actions and the differences from AWS are in
[AWS compatibility](aws-compatibility.md). The native `/v1` API, which the
console and the Go and TypeScript SDKs use, is described in the
[API reference](openapi.yaml).

## 5. Sync secrets into Kubernetes with External Secrets

The [External Secrets Operator](https://external-secrets.io) reads Citadel
through its AWS provider. Use `service: SecretsManager` and set ESO's
`AWS_SECRETSMANAGER_ENDPOINT` (and `AWS_STS_ENDPOINT` for service-account
federation) to your Citadel URL. Then read one environment's secrets at
once:

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: payments
spec:
  refreshInterval: 1h
  secretStoreRef:
    kind: ClusterSecretStore
    name: citadel
  target:
    name: payments
  dataFrom:
    - find:
        name:
          regexp: "^payments/prod/"
      rewrite:
        - regexp: { source: "payments/prod/(.*)", target: "$1" }
```

Each key in `payments/prod` becomes a key of the `payments` Kubernetes
Secret.

## Next steps

- **AI agents.** Let coding and browser agents use credentials without
  holding them: [Getting started with AI agents](getting-started-agents.md).
- **Keys and certificates.** KMS keys, signing, a private CA and an ACME
  server are under **KMS keys** and **Certificates** in the console.
- **Workload identity.** Let CI jobs and pods authenticate without stored
  keys: **Identity → Workload identity**.
- **Notifications.** Email, Slack and webhook alerts for approvals,
  expiring certificates and agent events: [Notifications](notifications.md).
- **Security.** What Citadel protects and what it relies on you for:
  [Security model](security-model.md).
