package main

import "github.com/worlddrknss/citadel/internal/arn"

// serverARN builds an ARN for the given service and resource using the active
// store's deployment identity.
func (s *server) serverARN(service, resource string) string {
	region, accountID := s.store.DeploymentIdentity()
	return arn.Build(service, region, accountID, resource)
}
