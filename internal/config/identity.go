package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// MinBootstrapTokenLen is the shortest KMS_BOOTSTRAP_TOKEN accepted.
const MinBootstrapTokenLen = 16

// loadIdentityEnv reads the identity settings: the first-run bootstrap token
// and the Kubernetes TokenReview reviewer token for workload identity.
func loadIdentityEnv(cfg *Config) error {
	if tok := strings.TrimSpace(os.Getenv("KMS_BOOTSTRAP_TOKEN")); tok != "" {
		if len(tok) < MinBootstrapTokenLen {
			return fmt.Errorf("KMS_BOOTSTRAP_TOKEN must be at least %d characters", MinBootstrapTokenLen)
		}
		cfg.BootstrapToken = tok
	}
	reviewer := strings.TrimSpace(os.Getenv("KMS_WORKLOAD_K8S_REVIEWER_TOKEN"))
	if file := strings.TrimSpace(os.Getenv("KMS_WORKLOAD_K8S_REVIEWER_TOKEN_FILE")); file != "" {
		if reviewer != "" {
			return errors.New("set KMS_WORKLOAD_K8S_REVIEWER_TOKEN or KMS_WORKLOAD_K8S_REVIEWER_TOKEN_FILE, not both")
		}
		b, err := os.ReadFile(file)
		if err != nil {
			return errors.New("KMS_WORKLOAD_K8S_REVIEWER_TOKEN_FILE could not be read")
		}
		reviewer = strings.TrimSpace(string(b))
	}
	cfg.WorkloadK8sReviewerToken = reviewer
	return nil
}
