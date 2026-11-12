package server

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// registerIdentityRoutes wires console SSO (sign-in and provider
// administration), the workload identity issuer and its administration,
// and the identity background jobs.
func (s *Server) registerIdentityRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/auth/oidc/{id}/start", s.handleSSOStart)
	mux.HandleFunc("GET /v1/auth/oidc/{id}/callback", s.handleSSOCallback)

	mux.HandleFunc("GET /v1/admin/sso/providers", s.handleV1ListSSOProviders)
	mux.HandleFunc("POST /v1/admin/sso/providers", s.handleV1CreateSSOProvider)
	mux.HandleFunc("POST /v1/admin/sso/providers/update", s.handleV1UpdateSSOProvider)
	mux.HandleFunc("DELETE /v1/admin/sso/providers", s.handleV1DeleteSSOProvider)
	mux.HandleFunc("POST /v1/admin/sso/providers/test", s.handleV1TestSSOProvider)

	mux.HandleFunc("/oidc/", s.handleOIDC)
	mux.HandleFunc("POST /v1/workload-identity/token", s.handleV1WorkloadToken)
	mux.HandleFunc("GET /v1/workload-identity/issuer", s.handleV1WorkloadIssuer)
	mux.HandleFunc("POST /v1/workload-identity/issuer/settings", s.handleV1WorkloadIssuerSettings)
	mux.HandleFunc("POST /v1/workload-identity/issuer/rotate", s.handleV1WorkloadIssuerRotate)
	mux.HandleFunc("GET /v1/workload-identity/clients", s.handleV1ListWorkloadClients)
	mux.HandleFunc("POST /v1/workload-identity/clients", s.handleV1CreateWorkloadClient)
	mux.HandleFunc("POST /v1/workload-identity/clients/update", s.handleV1UpdateWorkloadClient)
	mux.HandleFunc("DELETE /v1/workload-identity/clients", s.handleV1DeleteWorkloadClient)

	s.jobs.Every("workload-signing-key-rotation", time.Hour, func(ctx context.Context) error {
		if s.publicURL() == "" {
			return nil
		}
		return s.workloadRotationJob(ctx)
	})
	s.jobs.Every("consumed-once-purge", 15*time.Minute, func(ctx context.Context) error {
		_, err := s.store.PurgeConsumed(ctx, time.Now().UTC())
		return err
	})
}

func parseFormBody(b []byte) (url.Values, error) { return url.ParseQuery(string(b)) }
