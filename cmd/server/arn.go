package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

const (
	// defaultAWSRegion is the region embedded in resource ARNs when no region has
	// been configured for the deployment.
	defaultAWSRegion = "us-west-2"
	// placeholderAccountID is the all-zero account ID used by older records before
	// a real deployment account ID was assigned.
	placeholderAccountID = "000000000000"
)

// awsRegions is the set of regions selectable in the master admin console. It is
// intentionally a curated subset of common AWS commercial regions.
var awsRegions = []string{
	"us-east-1",
	"us-east-2",
	"us-west-1",
	"us-west-2",
	"ca-central-1",
	"eu-west-1",
	"eu-west-2",
	"eu-central-1",
	"ap-south-1",
	"ap-southeast-1",
	"ap-southeast-2",
	"ap-northeast-1",
	"sa-east-1",
}

// arnFor builds an AWS-style ARN. Global services (e.g. IAM) pass an empty region
// which yields the conventional double-colon form arn:aws:iam::<account>:<resource>.
func arnFor(service, region, accountID, resource string) string {
	if strings.TrimSpace(accountID) == "" {
		accountID = placeholderAccountID
	}
	return fmt.Sprintf("arn:aws:%s:%s:%s:%s", service, region, accountID, resource)
}

// generateAccountID returns a random 12-digit account identifier that resembles a
// real AWS account number (no leading zero).
func generateAccountID() string {
	var sb strings.Builder
	first, _ := rand.Int(rand.Reader, big.NewInt(9))
	sb.WriteString(fmt.Sprintf("%d", first.Int64()+1))
	for i := 0; i < 11; i++ {
		d, _ := rand.Int(rand.Reader, big.NewInt(10))
		sb.WriteString(fmt.Sprintf("%d", d.Int64()))
	}
	return sb.String()
}

// isValidAccountID reports whether s is a 12-digit numeric account ID.
func isValidAccountID(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != 12 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// isValidRegion reports whether region is one of the supported AWS regions.
func isValidRegion(region string) bool {
	region = strings.TrimSpace(region)
	for _, r := range awsRegions {
		if r == region {
			return true
		}
	}
	return false
}

// DeploymentIdentity returns the region and account ID embedded in resource ARNs.
func (s *dbStore) DeploymentIdentity() (string, string) {
	return effectiveRegion(s.region), effectiveAccountID(s.accountID)
}

// DeploymentIdentity returns the region and account ID embedded in resource ARNs.
func (s *inMemoryStore) DeploymentIdentity() (string, string) {
	return effectiveRegion(s.region), effectiveAccountID(s.accountID)
}

func effectiveRegion(region string) string {
	if strings.TrimSpace(region) == "" {
		return defaultAWSRegion
	}
	return region
}

func effectiveAccountID(accountID string) string {
	if strings.TrimSpace(accountID) == "" {
		return placeholderAccountID
	}
	return accountID
}

func (s *dbStore) keyARN(id string) string {
	r, a := s.DeploymentIdentity()
	return arnFor("kms", r, a, "key/"+id)
}

func (s *inMemoryStore) keyARN(id string) string {
	r, a := s.DeploymentIdentity()
	return arnFor("kms", r, a, "key/"+id)
}

func (s *dbStore) secretARNFor(name string) string {
	r, a := s.DeploymentIdentity()
	return arnFor("secretsmanager", r, a, "secret:"+name)
}

func (s *inMemoryStore) secretARNFor(name string) string {
	r, a := s.DeploymentIdentity()
	return arnFor("secretsmanager", r, a, "secret:"+name)
}

// serverARN builds an ARN for the given service and resource using the active
// store's deployment identity.
func (s *server) serverARN(service, resource string) string {
	region, accountID := s.store.DeploymentIdentity()
	return arnFor(service, region, accountID, resource)
}
