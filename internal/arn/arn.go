package arn

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

const (
	// DefaultRegion is the region embedded in resource ARNs when no region has
	// been configured for the deployment.
	DefaultRegion = "us-west-2"
	// PlaceholderAccountID is the all-zero account ID used by older records before
	// a real deployment account ID was assigned.
	PlaceholderAccountID = "000000000000"
)

// regions is the set of regions selectable in the master admin console. It is
// intentionally a curated subset of common AWS commercial regions.
var regions = []string{
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

// Build builds an AWS-style ARN. Global services (e.g. IAM) pass an empty region
// which yields the conventional double-colon form arn:aws:iam::<account>:<resource>.
func Build(service, region, accountID, resource string) string {
	if strings.TrimSpace(accountID) == "" {
		accountID = PlaceholderAccountID
	}
	return fmt.Sprintf("arn:aws:%s:%s:%s:%s", service, region, accountID, resource)
}

// GenerateAccountID returns a random 12-digit account identifier that resembles a
// real AWS account number (no leading zero).
func GenerateAccountID() string {
	var sb strings.Builder
	first, _ := rand.Int(rand.Reader, big.NewInt(9))
	sb.WriteString(fmt.Sprintf("%d", first.Int64()+1))
	for i := 0; i < 11; i++ {
		d, _ := rand.Int(rand.Reader, big.NewInt(10))
		sb.WriteString(fmt.Sprintf("%d", d.Int64()))
	}
	return sb.String()
}

// IsValidAccountID reports whether s is a 12-digit numeric account ID.
func IsValidAccountID(s string) bool {
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

// IsValidRegion reports whether region is one of the supported AWS regions.
func IsValidRegion(region string) bool {
	region = strings.TrimSpace(region)
	for _, r := range regions {
		if r == region {
			return true
		}
	}
	return false
}

func EffectiveRegion(region string) string {
	if strings.TrimSpace(region) == "" {
		return DefaultRegion
	}
	return region
}

func EffectiveAccountID(accountID string) string {
	if strings.TrimSpace(accountID) == "" {
		return PlaceholderAccountID
	}
	return accountID
}
