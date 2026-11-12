package main

// isDBBacked returns true if the store is database-backed.
func (s *server) isDBBacked() bool {
	_, ok := s.store.(*dbStore)
	return ok
}
