package server

import "net/http"

// handleAWSCompatTarget dispatches the AWS JSON actions added for SDK
// compatibility. handleKMS calls it after authentication and before its own
// switch; it reports whether it handled the target.
func (s *Server) handleAWSCompatTarget(w http.ResponseWriter, r *http.Request, target string) bool {
	switch target {
	case "TrentService.GenerateDataKey":
		s.handleGenerateDataKey(w, r, true)
	case "TrentService.GenerateDataKeyWithoutPlaintext":
		s.handleGenerateDataKey(w, r, false)
	case "TrentService.GenerateDataKeyPair":
		s.handleGenerateDataKeyPair(w, r, true)
	case "TrentService.GenerateDataKeyPairWithoutPlaintext":
		s.handleGenerateDataKeyPair(w, r, false)
	case "TrentService.ReEncrypt":
		s.handleReEncrypt(w, r)
	case "TrentService.DeleteAlias":
		s.handleDeleteAlias(w, r)
	case "secretsmanager.BatchGetSecretValue":
		s.handleBatchGetSecretValue(w, r)
	case "secretsmanager.GetRandomPassword":
		s.handleGetRandomPassword(w, r)
	default:
		return false
	}
	return true
}
