# Citadel Go SDK

`github.com/worlddrknss/citadel/sdk/citadel` is a typed client for Citadel's
native `/v1` API (the API the console uses, described by
[`docs/openapi.yaml`](../../docs/openapi.yaml)). It uses only the Go standard
library. For the AWS-compatible APIs (KMS, Secrets Manager, SSM, ACM, STS),
use the AWS SDK instead.

```sh
go get github.com/worlddrknss/citadel/sdk/citadel
```

## Quick start

Create an access key in the console (Account, then Access keys). The key acts
with your role in that account.

```go
c, err := citadel.New(citadel.Config{
	BaseURL:         "https://citadel.example.com", // or $CITADEL_URL
	AccessKeyID:     os.Getenv("CITADEL_ACCESS_KEY_ID"),
	SecretAccessKey: os.Getenv("CITADEL_SECRET_ACCESS_KEY"),
})
if err != nil {
	log.Fatal(err)
}

ref := citadel.SecretRef{Project: "shop", Env: "prod", Path: "api", Key: "DATABASE_URL"}
v, err := c.GetSecret(ctx, ref, nil)
```

Empty `Config` fields fall back to `CITADEL_URL`, `CITADEL_ACCESS_KEY_ID` and
`CITADEL_SECRET_ACCESS_KEY`, so `citadel.New(citadel.Config{})` works when
those are set.

## Operations

| Area | Methods |
| --- | --- |
| Caller | `Me` |
| Hierarchy | `ListProjects`, `CreateProject`, `DeleteProject`, `CreateEnvironment`, `DeleteEnvironment`, `CreateFolder`, `DeleteFolder` |
| Secrets | `ListSecrets`, `GetSecret`, `PutSecret`, `DeleteSecret`, `RestoreSecret`, `ListSecretVersions` |
| Parameters | `ListParameters`, `GetParameter`, `PutParameter`, `DeleteParameter`, `ParameterHistory` |
| KMS | `ListKeys`, `Encrypt`, `Decrypt` |
| Certificates | `ListCertificates`, `GetCertificate`, `IssueCertificate`, `IssueGeneratedCertificate` |
| Workload identity | `IssueWorkloadToken` |

For any other operation, see the API reference in the console (Help, then API
reference) or `GET /v1/openapi.yaml`.

## Errors

Failed calls return an `*citadel.APIError` with the HTTP status, the API's
stable error code (`not_found`, `approval_required`, `reveal_forbidden`, ...)
and its message:

```go
_, err := c.PutSecret(ctx, in)
switch {
case citadel.IsApprovalRequired(err):
	// The environment is protected: submit a change request.
case citadel.IsNotFound(err), citadel.IsForbidden(err):
	// ...
case err != nil:
	var apiErr *citadel.APIError
	if errors.As(err, &apiErr) {
		log.Printf("%s (%d): %s", apiErr.Code, apiErr.StatusCode, apiErr.Message)
	}
}
```

## Timeouts and retries

- `Config.Timeout` (default 30s) bounds each HTTP attempt. The context you
  pass bounds the whole call, retries included.
- 429, 502, 503 and 504 are retried for every method, and 500 and network
  errors only for reads. Retries use exponential backoff with full jitter
  (`RetryBaseDelay` 200ms, `RetryMaxDelay` 5s by default) and honour
  `Retry-After`. `MaxRetries` defaults to 3; set it negative to turn retries
  off.

## Tests

The SDK's tests run against the real Citadel server over the in-memory store
(`internal/servertest`), so they check real API behaviour:

```sh
go test ./sdk/citadel/
```
