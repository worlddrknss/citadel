package server

import "net/http"

// registerSecretsRoutes adds the secrets-domain routes that are not in
// server.go's original table: change-request review and policies, secrets
// settings, and parameter edits.
func (s *Server) registerSecretsRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/change-requests/detail", s.handleV1ChangeRequestDetail)
	mux.HandleFunc("GET /v1/change-requests/values", s.handleV1ChangeRequestValues)
	mux.HandleFunc("GET /v1/change-requests/policies", s.handleV1ListApprovalPolicies)
	mux.HandleFunc("POST /v1/change-requests/policies", s.handleV1PutApprovalPolicy)

	mux.HandleFunc("GET /v1/secrets/settings", s.handleV1GetSecretSettings)
	mux.HandleFunc("POST /v1/secrets/settings", s.handleV1PutSecretSettings)

	mux.HandleFunc("POST /v1/parameters/update", s.handleV1UpdateParameter)
	mux.HandleFunc("DELETE /v1/parameters/label", s.handleV1UnlabelParameter)
}
