package server

import (
	"net/http"

	"github.com/worlddrknss/citadel/docs"
)

// registerOpenAPIRoutes serves the OpenAPI description of the native API.
// It is public, including in bootstrap mode: the document describes the API
// and holds no data. The console's API reference page and the SDK type
// generators read it.
func (s *Server) registerOpenAPIRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/openapi.yaml", s.handleV1OpenAPI)
}

func (s *Server) handleV1OpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(docs.OpenAPI)
	}
}
