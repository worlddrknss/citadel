// Package docs embeds documentation assets that the Citadel server serves at
// runtime. Today that is the OpenAPI 3.1 description of the native /v1 API.
package docs

import _ "embed"

// OpenAPI is docs/openapi.yaml, the OpenAPI 3.1 description of the native
// /v1 API, served at GET /v1/openapi.yaml.
//
//go:embed openapi.yaml
var OpenAPI []byte
