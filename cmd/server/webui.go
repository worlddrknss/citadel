package main

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
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

// handleApp serves the Svelte single-page application under /app/. Files are
// served directly (not via http.FileServer) so that index.html is returned
// in-place rather than triggering FileServer's automatic redirect. Unknown,
// non-asset paths fall back to index.html so client-side routing works on deep
// links and refreshes.
func (s *server) handleApp(w http.ResponseWriter, r *http.Request) {
	dist := webDistSub()

	reqPath := strings.TrimPrefix(r.URL.Path, "/app")
	reqPath = strings.TrimPrefix(reqPath, "/")
	if reqPath == "" {
		reqPath = "index.html"
	}
	reqPath = path.Clean(reqPath)
	if reqPath == "." || strings.HasPrefix(reqPath, "..") {
		reqPath = "index.html"
	}

	data, err := fs.ReadFile(dist, reqPath)
	if err != nil {
		// SPA fallback: serve the HTML shell for any unmatched route.
		reqPath = "index.html"
		data, err = fs.ReadFile(dist, reqPath)
		if err != nil {
			http.Error(w, "web console not built: run scripts/build-web.sh before go build", http.StatusServiceUnavailable)
			return
		}
	}

	if ctype := mime.TypeByExtension(path.Ext(reqPath)); ctype != "" {
		w.Header().Set("Content-Type", ctype)
	}
	// Long-cache fingerprinted assets; never cache the HTML shell.
	if strings.HasPrefix(reqPath, "_app/") || strings.HasPrefix(reqPath, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
