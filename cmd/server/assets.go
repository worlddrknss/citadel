package main

import (
	"embed"
	"io/fs"
)

// webDistFS holds the compiled Svelte (SvelteKit static adapter) control plane.
// The build output is copied into cmd/server/webdist (by scripts/build-web.sh
// or the Dockerfile) and embedded so Citadel ships as one executable. It is not
// committed: a plain `go build` without it serves a "console not built" page.
//
//go:embed all:webdist
var webDistFS embed.FS

// webDistSub returns the embedded build directory rooted at its contents.
func webDistSub() fs.FS {
	sub, err := fs.Sub(webDistFS, "webdist")
	if err != nil {
		// Should never happen: webdist is embedded at build time.
		panic(err)
	}
	return sub
}
