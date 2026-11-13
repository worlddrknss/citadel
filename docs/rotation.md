# Secret rotation

Citadel rotates Secrets Manager secrets with built-in **rotators**. AWS
rotates a secret by invoking a Lambda function; Citadel can't run Lambda
functions, so it runs the same four steps itself, with the same staging
labels, and keeps rotation schedules working with the AWS SDKs, Terraform and
External Secrets Operator.

## How a rotation runs

Every rotation has a token (the new version's ID) and runs AWS's four steps:

1. **createSecret**: store a new value as a version labelled `AWSPENDING`.
2. **setSecret**: apply the new value where it is used (for example, change a
   database password).
3. **testSecret**: check the new value works.
4. **finishSecret**: move `AWSCURRENT` to the new version. The version that
   was current becomes `AWSPREVIOUS`, and `AWSPENDING` is removed.

Clients reading `AWSCURRENT` get the new value on their next read, and
`AWSPREVIOUS` stays available for clients that are still using the old one.

When a step fails, the `AWSPENDING` version is **kept**, as AWS keeps it, and
`AWSCURRENT` doesn't move. The rotation is retried with the same token after
1, 2, 4 and 8 minutes, and every step is idempotent: createSecret doesn't
create a second value, and setSecret first checks whether the new value
already works. This matters for databases: if setSecret changed the password
and testSecret then failed, the new password is still in `AWSPENDING` and the
retry completes the rotation instead of losing it. After five failed attempts
the rotation is marked **failed** and reattempted, with the same version, when
the next window opens. The console flags failed and retrying rotations in the
secrets table.

`CancelRotateSecret` (or **Turn off** in the console) stops the schedule. As in
AWS it leaves an unfinished rotation's `AWSPENDING` version in place: either
turn rotation back on (the next rotation resumes it) or remove the label with
`UpdateSecretVersionStage`.

## Rotators

| Type | What it changes |
|---|---|
| `random` | The secret's value (or one field of a JSON secret) becomes a random password. Nothing outside Citadel changes. |
| `postgresql` | A PostgreSQL user's password, using the user's own credentials or an admin secret. |
| `webhook` | Anything: each step is POSTed to your https endpoint, which does the work, like a Lambda function. |

### Configuration

Every rotator takes [`GetRandomPassword`](aws-compatibility.md)'s options for
the values it generates:

| Option | Default | Description |
|---|---|---|
| `length` | 32 | Password length, 1 to 4096. |
| `excludeCharacters` | — | Characters never used. |
| `excludeNumbers`, `excludePunctuation`, `excludeUppercase`, `excludeLowercase` | false | Leave out a character class. |
| `includeSpace` | false | Allow spaces. |
| `requireEachIncludedType` | true | At least one character of each class used. |

Members that don't apply to the rotator are refused.

### random

| Option | Description |
|---|---|
| `jsonKey` | Rotate this string field of a JSON object secret and keep the other fields (and their number formatting). Without it the whole value is replaced. |

setSecret does nothing; testSecret checks the new value is present.

### postgresql

The secret uses AWS's standard JSON:

```json
{"engine": "postgres", "host": "db.internal", "port": 5432,
 "username": "app", "password": "…", "dbname": "app", "sslmode": "require"}
```

`dbname` defaults to `postgres` and `sslmode` to `require` (`disable`,
`require`, `verify-ca` and `verify-full` are accepted). Generated passwords
never contain `:/@"'\`, as in AWS's templates.

| Option | Description |
|---|---|
| `strategy` | `single-user` or `alternating-users`. Empty picks alternating users when an admin secret is known, single user otherwise. |
| `adminSecretArn` | The admin secret (same JSON shape, same account) for alternating users. Without it the secret's own `masterarn` field is used, as in AWS's templates. |

- **Single user**: setSecret signs in with the user's current credentials
  (falling back to `AWSPREVIOUS`) and runs `ALTER ROLE … WITH PASSWORD`. The
  user needs no other privilege. Briefly, clients that haven't read the new
  value fail to sign in.
- **Alternating users**: rotations alternate between `username` and
  `username_clone`. The admin creates the clone on the first rotation
  (`CREATE ROLE … LOGIN` and `GRANT <user> TO <user>_clone`, so it has the
  same privileges) and afterwards changes the password of whichever user is
  not current. Clients using the previous credentials keep working until the
  next rotation. The admin secret must be for the same host and port.

testSecret signs in with the new credentials. Role names and password literals
are quoted by the driver; connections use a 10-second connect timeout and
30-second statement timeout, and refuse loopback, link-local and cloud
metadata addresses (use the database's network address, not `localhost`).

### webhook

| Option | Description |
|---|---|
| `url` | An `https` URL. Loopback, link-local, multicast and cloud metadata addresses are refused after DNS resolution, and redirects aren't followed. Private networks are allowed. |

Citadel POSTs JSON for each step:

```json
{"step": "setSecret", "secretId": "arn:aws:secretsmanager:…", "secretName": "pay/prod/STRIPE_KEY",
 "clientRequestToken": "…", "currentValue": "…", "pendingValue": "…"}
```

`currentValue` is sent to createSecret and setSecret, `pendingValue` to
setSecret and testSecret; finishSecret gets neither. Any 2xx answer is
success. createSecret may answer `{"secretString": "…"}` to supply the new
value (for example an API key issued by a third party); otherwise Citadel
generates one with the password options. Citadel moves the labels after
finishSecret succeeds.

Requests carry:

| Header | Value |
|---|---|
| `X-Citadel-Timestamp` | Unix seconds when the request was signed. |
| `X-Citadel-Signature` | `v1=` + hex HMAC-SHA256, keyed with the signing secret, of `<timestamp>.<body>`. |
| `X-Citadel-Rotation-Step` | The step, also in the body. |

Verify the signature with a constant-time comparison and reject timestamps
more than five minutes old, so a captured request can't be replayed:

```python
import hashlib, hmac, time

def verify(secret: bytes, ts: str, body: bytes, sig: str) -> bool:
    if abs(time.time() - int(ts)) > 300:
        return False
    want = "v1=" + hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, sig)
```

The signing secret is generated by Citadel when you set up the rotator,
shown once, and stored sealed (AES-256-GCM under a key derived from the
deployment root secret). **Replace signing secret** in the console (or
`POST /v1/secrets/rotation/signing-secret`) issues a new one. Webhook
requests contain secret values: keep the endpoint on TLS and treat it as you
would a Lambda function with access to the secret.

## Choosing a rotator

### Console

Open a secret and select the **Rotation** tab: pick the rotator, its options,
the schedule (every N days, every N hours, or a cron expression) and the
window, then save, optionally rotating once straight away. The tab shows the
state, the next window, the last error and the history of attempts, and has
**Rotate now** and **Turn off**. Built-in rotators are not available in
environments that require approval, because they change values without a
change request.

### AWS API

`RotateSecret` selects a rotator with a `RotationLambdaARN` of the form

```
arn:citadel:rotator:<region>:<account>:<type>[/<config-id>]
```

- `<region>` is the deployment region (`KMS_AWS_REGION`) and `<account>` the
  caller's account.
- `<type>` is `random`, `postgresql` or `webhook`.
- `<config-id>`, optional, names a secret in the same account whose JSON value
  is the rotator's configuration (the options above; a webhook's also has
  `signingSecret`, at least 32 characters). It is read at every rotation, so
  editing it takes effect on the next one. Without it, the configuration set
  in the console is used if the type matches, otherwise the defaults (a
  webhook needs a configuration).

```bash
aws secretsmanager rotate-secret --secret-id pay/prod/db \
  --rotation-lambda-arn arn:citadel:rotator:us-west-2:123456789012:postgresql \
  --rotation-rules '{"ScheduleExpression": "cron(0 4 ? * SUN *)", "Duration": "2h"}'
```

`RotateImmediately` defaults to true, as in AWS: the rotation starts in the
background and `VersionId` is its token. If a rotation is unfinished the call
returns `InvalidRequestException` ("A previous rotation isn't complete") and
that rotation is reattempted. `DescribeSecret` reports `RotationRules`,
`NextRotationDate` (the start of the next window) and `LastRotatedDate`.

A real Lambda ARN is still accepted and recorded, but nothing runs: the
console shows the schedule as **schedule only** and marks the secret as due
when its date passes. `RotateImmediately` does nothing for it.

### Native API

| Request | Role | Description |
|---|---|---|
| `GET /v1/secrets/rotation?project&env&path&key` | viewer | Configuration, state, next window and history. |
| `POST /v1/secrets/rotation` | editor | `{project, env, path, key, rotator: {type, config?, configSecret?}, afterDays? \| scheduleExpression?, duration?, rotateImmediately}`. Returns `signingSecret` once for a new webhook rotator. A `lambdaArn` instead of `rotator` records a schedule only. |
| `POST /v1/secrets/rotation/rotate` | editor | Start a rotation now (202, runs in the background). |
| `POST /v1/secrets/rotation/signing-secret` | editor | Replace a webhook rotator's signing secret. |
| `DELETE /v1/secrets/rotation?project&env&path&key` | editor | Turn rotation off. The configuration is kept. |

See [openapi.yaml](openapi.yaml) for the schemas.

## Schedules

Schedules follow AWS's `RotationRules`, in UTC:

| Rule | Window opens | Default window |
|---|---|---|
| `AutomaticallyAfterDays: N` or `rate(N days)` (1 to 1000) | 00:00 on the day N days after the last rotation | the rest of that day |
| `rate(N hours)` (4 to 23) | on the hour, N hours after the last rotation | 1 hour |
| `cron(Minutes Hours Day-of-month Month Day-of-week Year)` | at each match | 1 hour when Hours repeats (`*` or a step), otherwise the rest of the day |

`Duration` (`1h` to `24h`) sets the window; it must not run past the end of
the UTC day for daily schedules, or into the next window. Cron expressions use
AWS syntax: one of Day-of-month and Day-of-week is `?`; Day-of-week runs 1
(SUN) to 7 (SAT); names (`JAN`, `MON`), ranges, lists, steps, `L` (last day of
the month), `nL` (last weekday n) and `n#k` (k-th weekday n) are supported.

Citadel starts a rotation as soon as its window opens: the rotation job runs
every minute on every replica. If no replica was running during a window, the
rotation runs at the next tick instead of waiting a whole period. The next
window is computed from when the rotation finished.

## Replicas

Each rotation holds a lease (a conditional update on the secret's rotation
row, compared on the database clock) for up to five minutes, and the job
re-checks that the rotation is still due once it holds the lease. Two replicas
therefore never rotate the same secret, and a replica that dies mid-rotation
only delays it until the lease expires; the next attempt resumes from
`AWSPENDING`.

## Audit

Each step is audited as `secretsmanager.RotationStep.<step>` with the result,
and each rotation as `secretsmanager.RotationSucceeded` or
`secretsmanager.RotationFailed`, all by the `system:rotation` actor. Versions
written by a rotation are attributed to `system:rotation`. Configuration
changes are audited with the user who made them (`citadel.ConfigureItemRotation`,
`citadel.RotateItemNow`, `citadel.RegenerateRotationSigningSecret`,
`secretsmanager.RotateSecret`). Error messages stored in the history are the
rotator's own (for example `postgres: password authentication failed … (28P01)`
or `testSecret: the webhook returned HTTP 500`) and never contain secret
values.
