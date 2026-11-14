# Citadel Go SDK

`github.com/worlddrknss/citadel/sdk/citadel` is a typed client for Citadel's
native `/v1` API: secrets, parameters, KMS, certificates, workload identity,
agents and the Agent API, access requests and leases, notifications, and
audit retention. It uses only the Go standard library. For the
AWS-compatible APIs, use the AWS SDK instead.

**Documentation:** [docs/sdk-go.md](../../docs/sdk-go.md) (also in the
console under **Docs → SDKs → Go SDK**). Which SDK to use and how each
authenticates: [docs/sdks.md](../../docs/sdks.md).

## Install

```sh
go get github.com/worlddrknss/citadel/sdk/citadel@main
```

Name a version (`@main`, or a release's commit): the module path has no
`/v2` suffix, so a bare `go get` resolves to an old `v1` release. See
[Install](../../docs/sdk-go.md#install).

## Quick start

Create an access key in the console (**My account → Access keys**). The key
acts with your role in that account.

```go
c, err := citadel.New(citadel.Config{}) // CITADEL_URL, CITADEL_ACCESS_KEY_ID, CITADEL_SECRET_ACCESS_KEY
if err != nil {
	log.Fatal(err)
}
v, err := c.GetSecret(ctx, citadel.SecretRef{Project: "shop", Env: "prod", Path: "api", Key: "DATABASE_URL"}, nil)
switch {
case citadel.IsNotFound(err):
	log.Fatal("no such secret")
case err != nil:
	log.Fatal(err)
}
fmt.Println(v.Value)
```

More examples are in [example_test.go](example_test.go) and on
[pkg.go.dev](https://pkg.go.dev/github.com/worlddrknss/citadel/sdk/citadel).

## Tests

The SDK's tests run against the real Citadel server over the in-memory store:

```sh
go test ./sdk/citadel/
```
