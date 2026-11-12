package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// MinBootstrapTokenLen is the shortest KMS_BOOTSTRAP_TOKEN accepted.
const MinBootstrapTokenLen = 16

// DefaultK8sReviewerTokenFile is the in-cluster service account token,
// used for TokenReview when running in Kubernetes and
// KMS_WORKLOAD_K8S_REVIEWER_TOKEN_FILE is unset.
const DefaultK8sReviewerTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// loadIdentityEnv reads the identity settings: the first-run bootstrap token
// and the Kubernetes TokenReview reviewer token for workload identity.
func loadIdentityEnv(cfg *Config) error {
	if tok := strings.TrimSpace(os.Getenv("KMS_BOOTSTRAP_TOKEN")); tok != "" {
		if len(tok) < MinBootstrapTokenLen {
			return fmt.Errorf("KMS_BOOTSTRAP_TOKEN must be at least %d characters", MinBootstrapTokenLen)
		}
		cfg.BootstrapToken = tok
	}
	cfg.WorkloadK8sReviewerToken = strings.TrimSpace(os.Getenv("KMS_WORKLOAD_K8S_REVIEWER_TOKEN"))
	file := strings.TrimSpace(os.Getenv("KMS_WORKLOAD_K8S_REVIEWER_TOKEN_FILE"))
	if file != "" && cfg.WorkloadK8sReviewerToken != "" {
		return errors.New("set KMS_WORKLOAD_K8S_REVIEWER_TOKEN or KMS_WORKLOAD_K8S_REVIEWER_TOKEN_FILE, not both")
	}
	if file == "" && cfg.WorkloadK8sReviewerToken == "" && os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		if _, err := os.Stat(DefaultK8sReviewerTokenFile); err == nil {
			file = DefaultK8sReviewerTokenFile
		}
	}
	cfg.WorkloadK8sReviewerTokenFile = file
	return nil
}

// K8sReviewerToken returns the TokenReview bearer token: the static
// KMS_WORKLOAD_K8S_REVIEWER_TOKEN, or the token file read now (so projected
// token rotation is picked up). "" means the method is not configured.
func (c Config) K8sReviewerToken() (string, error) {
	if c.WorkloadK8sReviewerToken != "" {
		return c.WorkloadK8sReviewerToken, nil
	}
	if c.WorkloadK8sReviewerTokenFile == "" {
		return "", nil
	}
	b, err := os.ReadFile(c.WorkloadK8sReviewerTokenFile)
	if err != nil {
		return "", errors.New("the Kubernetes reviewer token file could not be read")
	}
	return strings.TrimSpace(string(b)), nil
}

// K8sReviewConfigured reports whether a TokenReview reviewer token source
// is configured.
func (c Config) K8sReviewConfigured() bool {
	return c.WorkloadK8sReviewerToken != "" || c.WorkloadK8sReviewerTokenFile != ""
}
