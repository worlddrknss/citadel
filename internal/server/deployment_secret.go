package server

// deploymentSecret is the secret per-purpose keys (value fingerprints, the
// audit-stream token, SSO keys) are HKDF-derived from. With PostgreSQL it is
// the store's persisted root secret, which keeps its value when the wrapping
// key is rotated; otherwise it is the wrapping key, else the legacy master
// key. Nil when none is configured.
func (s *Server) deploymentSecret() []byte {
	if r, ok := s.store.(interface{ ServiceRoot() []byte }); ok {
		if root := r.ServiceRoot(); len(root) > 0 {
			return root
		}
	}
	if len(s.cfg.WrappingKey) > 0 {
		return s.cfg.WrappingKey
	}
	if len(s.cfg.LegacyMasterKey) > 0 {
		return s.cfg.LegacyMasterKey
	}
	return nil
}
