package server

import (
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

// webDist returns the web console build the server was given, or an empty
// file system when it was started without one.
func (s *Server) webDist() fs.FS {
	if s.webFS == nil {
		return emptyFS{}
	}
	return s.webFS
}

// emptyFS is a file system with no files.
type emptyFS struct{}

func (emptyFS) Open(name string) (fs.File, error) {
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

// handleApp serves the Svelte single-page application under /app/. Files are
// served directly (not via http.FileServer) so that index.html is returned
// in-place rather than triggering FileServer's automatic redirect. Unknown,
// non-asset paths fall back to index.html so client-side routing works on deep
// links and refreshes.
func (s *Server) handleApp(w http.ResponseWriter, r *http.Request) {
	dist := s.webDist()

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
