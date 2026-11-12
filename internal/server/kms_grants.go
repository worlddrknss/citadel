package server

import (
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/worlddrknss/citadel/internal/store"
)

// Grant request validation shared by TrentService.CreateGrant and
// POST /v1/kms/grants.

var grantNameRe = regexp.MustCompile(`^[a-zA-Z0-9:/_-]{1,256}$`)

var (
	symmetricGrantOps  = map[string]bool{"Encrypt": true, "Decrypt": true, "GenerateDataKey": true, "GenerateDataKeyWithoutPlaintext": true, "ReEncryptFrom": true, "ReEncryptTo": true, "GenerateDataKeyPair": true, "GenerateDataKeyPairWithoutPlaintext": true}
	rsaEncryptGrantOps = map[string]bool{"Encrypt": true, "Decrypt": true, "ReEncryptFrom": true, "ReEncryptTo": true, "GetPublicKey": true}
	signingGrantOps    = map[string]bool{"Sign": true, "Verify": true, "GetPublicKey": true}
	commonGrantOps     = map[string]bool{"DescribeKey": true, "CreateGrant": true, "RetireGrant": true}
)

func validGrantPrincipal(p string) bool {
	return strings.HasPrefix(p, "arn:") && len(p) <= 256 && !strings.ContainsAny(p, "* \t\r\n")
}

// validateGrantRequest normalizes req in place and checks it against the
// key: an IAM principal ARN for the grantee (and retiring principal), and
// operations that exist and fit the key's type. Error messages are safe to
// return to clients.
func validateGrantRequest(key store.KMSKey, req *store.CreateGrantRequest) error {
	req.GranteePrincipal = strings.TrimSpace(req.GranteePrincipal)
	req.RetiringPrincipal = strings.TrimSpace(req.RetiringPrincipal)
	req.Name = strings.TrimSpace(req.Name)
	if !validGrantPrincipal(req.GranteePrincipal) {
		return errors.New("granteePrincipal must be an IAM principal ARN without wildcards")
	}
	if req.RetiringPrincipal != "" && !validGrantPrincipal(req.RetiringPrincipal) {
		return errors.New("retiringPrincipal must be an IAM principal ARN without wildcards")
	}
	if req.Name != "" && !grantNameRe.MatchString(req.Name) {
		return errors.New("grant name must be 1-256 characters of letters, digits, : / _ -")
	}
	if len(req.Operations) == 0 {
		return errors.New("at least one operation is required")
	}
	usage, spec := keyUsageAndSpecForMetadata(key)
	allowed := signingGrantOps
	if usage == store.KeyUsageEncryptDecrypt {
		allowed = rsaEncryptGrantOps
		if spec == store.KeySpecSymmetricDefault {
			allowed = symmetricGrantOps
		}
	}
	seen := map[string]bool{}
	ops := make([]string, 0, len(req.Operations))
	for _, op := range req.Operations {
		op = strings.TrimSpace(op)
		if !grantOperations[op] {
			return errors.New("unknown grant operation " + quoteOp(op))
		}
		if !allowed[op] && !commonGrantOps[op] {
			return errors.New("operation " + quoteOp(op) + " does not apply to this key's type")
		}
		if !seen[op] {
			seen[op] = true
			ops = append(ops, op)
		}
	}
	req.Operations = ops
	req.KeyID = key.ID
	return nil
}

// mayRetireGrant applies AWS's RetireGrant rule for the request's principal.
func (s *Server) mayRetireGrant(r *http.Request, g store.KMSGrant) bool {
	principal := requestPrincipal(r)
	if g.RetiringPrincipal != "" && g.RetiringPrincipal == principal {
		return true
	}
	if g.GranteePrincipal == principal {
		for _, op := range g.Operations {
			if op == "RetireGrant" {
				return true
			}
		}
	}
	key, err := s.store.ResolveByID(r.Context(), g.KeyID)
	if err != nil {
		return false
	}
	return s.authorizeKeyAction(r.Context(), r, key, "kms:RetireGrant") == nil
}

func quoteOp(op string) string {
	if len(op) > 64 {
		op = op[:64]
	}
	return `"` + op + `"`
}
