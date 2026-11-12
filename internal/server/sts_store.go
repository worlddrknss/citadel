package server

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
)

// STS / IAM identity federation store.
//
// This layer backs Citadel's AWS-compatible Security Token Service (STS) and
// the IAM primitives it depends on:
//
//   - OIDC identity providers  (iam_oidc_providers): external token issuers
//     (e.g. a Kubernetes cluster) whose JWTs may be exchanged for temporary
//     Citadel credentials, IRSA-style.
//   - IAM roles                (iam_roles):          named identities with a
//     trust policy describing who may assume them.
//   - STS sessions             (sts_sessions):       short-lived ASIA-prefixed
//     credentials minted by AssumeRole / AssumeRoleWithWebIdentity.
//
// The design intentionally mirrors the existing iam_access_keys plumbing: the
// temporary secret is wrapped with the store's wrapping key (AES-GCM, key ID
// bound as AAD) exactly like a long-lived access key, so the same SigV4
// verification path validates both once GetAccessKeyByID learns to resolve
// ASIA-prefixed keys from sts_sessions.

// trustPolicyType discriminates the two supported trust relationships.
const (
	trustTypeOIDC    = "oidc"
	trustTypeAccount = "account"
)

// generateTempAccessKeyID returns an AWS-style temporary access key ID. STS keys
// use the "ASIA" prefix (vs "AKIA" for long-lived keys); the base32 suffix keeps
// the ID free of characters that would corrupt a SigV4 Credential scope.
func generateTempAccessKeyID() string {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "ASIA" + base32.StdEncoding.EncodeToString(b)
}

// generateSessionToken returns an opaque session token carried in the
// X-Amz-Security-Token header by SDK clients using temporary credentials.
func generateSessionToken() string {
	b := make([]byte, 48)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
