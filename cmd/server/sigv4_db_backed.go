package main

import "github.com/worlddrknss/citadel/internal/store/postgres"

// isDBBacked returns true if the store is database-backed.
func (s *server) isDBBacked() bool {
	_, ok := s.store.(*postgres.Store)
	return ok
}
