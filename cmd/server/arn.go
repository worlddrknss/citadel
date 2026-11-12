package main

import "github.com/worlddrknss/citadel/internal/arn"

// DeploymentIdentity returns the region and account ID embedded in resource ARNs.
func (s *dbStore) DeploymentIdentity() (string, string) {
	return arn.EffectiveRegion(s.region), arn.EffectiveAccountID(s.accountID)
}

// DeploymentIdentity returns the region and account ID embedded in resource ARNs.
func (s *inMemoryStore) DeploymentIdentity() (string, string) {
	return arn.EffectiveRegion(s.region), arn.EffectiveAccountID(s.accountID)
}

func (s *dbStore) keyARN(id string) string {
	r, a := s.DeploymentIdentity()
	return arn.Build("kms", r, a, "key/"+id)
}

func (s *inMemoryStore) keyARN(id string) string {
	r, a := s.DeploymentIdentity()
	return arn.Build("kms", r, a, "key/"+id)
}

func (s *dbStore) secretARNFor(name string) string {
	r, a := s.DeploymentIdentity()
	return arn.Build("secretsmanager", r, a, "secret:"+name)
}

func (s *inMemoryStore) secretARNFor(name string) string {
	r, a := s.DeploymentIdentity()
	return arn.Build("secretsmanager", r, a, "secret:"+name)
}

// serverARN builds an ARN for the given service and resource using the active
// store's deployment identity.
func (s *server) serverARN(service, resource string) string {
	region, accountID := s.store.DeploymentIdentity()
	return arn.Build(service, region, accountID, resource)
}
