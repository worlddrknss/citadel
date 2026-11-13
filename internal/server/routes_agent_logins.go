package server

import "net/http"

// Routes added in 2.4: login credentials for browser agents (agent and
// console sides) and anomaly alerts. Minted credentials need no routes of
// their own: they are used through /v1/agent/http and revealed through
// /v1/agent/credentials/reveal.
func (s *Server) registerAgentLoginRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/agent/totp", s.handleAgentTOTP)
	mux.HandleFunc("POST /v1/agent/login", s.handleAgentLogin)

	mux.HandleFunc("GET /v1/agents/credentials/login", s.handleV1GetAgentLogin)
	mux.HandleFunc("POST /v1/agents/credentials/login", s.handleV1PutAgentLogin)
	mux.HandleFunc("GET /v1/agents/anomalies", s.handleV1AgentAnomalies)
	mux.HandleFunc("POST /v1/agents/anomaly-settings", s.handleV1PutAgentAnomalySettings)
}
