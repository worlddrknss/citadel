package main

import (
	"context"
	"crypto/sha1"
	"encoding/base32"
	"encoding/xml"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// AWS-compatible Security Token Service (STS).
//
// Unlike the JSON-RPC services (KMS, Secrets Manager, SSM) that dispatch on the
// X-Amz-Target header, STS speaks the older AWS *Query* protocol: requests are
// application/x-www-form-urlencoded with an "Action" field, and responses are
// XML in the https://sts.amazonaws.com/doc/2011-06-15/ namespace. This matches
// what the real AWS SDKs and External Secrets Operator expect, so a workload can
// run the standard web-identity credential provider against Citadel unchanged.
//
// Supported actions:
//   - GetCallerIdentity          (SigV4 signed)
//   - AssumeRole                 (SigV4 signed; trust policy: type "account")
//   - AssumeRoleWithWebIdentity  (unsigned; trust policy: type "oidc")

const stsXMLNamespace = "https://sts.amazonaws.com/doc/2011-06-15/"

// stsMaxBody bounds the form body STS will read.
const stsMaxBody = 1 << 20

// handleSTS is the entry point for STS Query-protocol requests routed from "/".
func (s *server) handleSTS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeSTSError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "method not allowed")
		return
	}
	// Read the body once: we need its SHA-256 for SigV4 verification AND the
	// parsed form for the action parameters. drainAndHashBody restores r.Body so
	// ParseForm can read it again.
	bodyHash, err := drainAndHashBody(r, stsMaxBody)
	if err != nil {
		writeSTSError(w, http.StatusBadRequest, "InvalidAction", "unable to read request body")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeSTSError(w, http.StatusBadRequest, "InvalidAction", "unable to parse request")
		return
	}

	switch r.PostForm.Get("Action") {
	case "GetCallerIdentity":
		s.handleSTSGetCallerIdentity(w, r, bodyHash)
	case "AssumeRole":
		s.handleSTSAssumeRole(w, r, bodyHash)
	case "AssumeRoleWithWebIdentity":
		s.handleSTSAssumeRoleWithWebIdentity(w, r)
	default:
		writeSTSError(w, http.StatusBadRequest, "InvalidAction", "unsupported STS Action")
	}
}

// isSTSRequest reports whether a POST to "/" is an STS Query-protocol call. STS
// requests are form-encoded and carry an STS Action; they never set
// X-Amz-Target (which the JSON-RPC services use).
func isSTSRequest(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	if strings.TrimSpace(r.Header.Get("X-Amz-Target")) != "" {
		return false
	}
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	return strings.Contains(ct, "application/x-www-form-urlencoded")
}

// ---- caller resolution -----------------------------------------------------

// resolveSignedSTSCaller verifies the request's SigV4 signature (DB-backed) and
// returns the caller's account. When strict SigV4 is disabled and no signature
// is present, it falls back to the deployment identity so local/dev use keeps
// working.
func (s *server) resolveSignedSTSCaller(r *http.Request, bodyHash string) (accountID, principalARN string, err error) {
	if strings.TrimSpace(r.Header.Get("Authorization")) != "" && s.isDBBacked() {
		username, acct, verr := s.verifyDBBackedSigV4(r, bodyHash)
		if verr != nil {
			return "", "", verr
		}
		return acct, arnFor("iam", "", acct, "user/"+username), nil
	}
	if s.cfg.strictSigV4 {
		return "", "", errors.New("request is not signed")
	}
	_, acct := s.store.DeploymentIdentity()
	return acct, arnFor("iam", "", acct, "user/local"), nil
}

// ---- GetCallerIdentity -----------------------------------------------------

func (s *server) handleSTSGetCallerIdentity(w http.ResponseWriter, r *http.Request, bodyHash string) {
	accountID, principalARN, err := s.resolveSignedSTSCaller(r, bodyHash)
	if err != nil {
		writeSTSError(w, http.StatusForbidden, "InvalidClientTokenId", "the security token included in the request is invalid")
		return
	}
	resp := stsGetCallerIdentityResponse{}
	resp.XMLNS = stsXMLNamespace
	resp.Result.Account = accountID
	resp.Result.Arn = principalARN
	resp.Result.UserID = principalUserID(principalARN)
	resp.Metadata.RequestID = newSTSRequestID()
	writeSTSXML(w, http.StatusOK, resp)
}

// ---- AssumeRole ------------------------------------------------------------

func (s *server) handleSTSAssumeRole(w http.ResponseWriter, r *http.Request, bodyHash string) {
	callerAccount, _, err := s.resolveSignedSTSCaller(r, bodyHash)
	if err != nil {
		writeSTSError(w, http.StatusForbidden, "AccessDenied", "the caller is not authorized to perform sts:AssumeRole")
		return
	}
	roleARN := strings.TrimSpace(r.PostForm.Get("RoleArn"))
	sessionName := strings.TrimSpace(r.PostForm.Get("RoleSessionName"))
	if roleARN == "" || sessionName == "" {
		writeSTSError(w, http.StatusBadRequest, "ValidationError", "RoleArn and RoleSessionName are required")
		return
	}
	ctx := context.Background()
	role, err := s.store.GetIAMRoleByARN(ctx, roleARN)
	if err != nil {
		writeSTSError(w, http.StatusBadRequest, "NoSuchEntity", "the requested role does not exist")
		return
	}
	if role.Trust.Type != trustTypeAccount || !role.Trust.principalAllowed(callerAccount) {
		writeSTSError(w, http.StatusForbidden, "AccessDenied", "the role trust policy does not allow this principal")
		return
	}

	duration := clampDuration(r.PostForm.Get("DurationSeconds"), role.MaxSessionSecs)
	creds, assumedARN, assumedUserID, err := s.mintTempCredentials(ctx, role, sessionName, "", duration)
	if err != nil {
		log.Printf("sts AssumeRole mint failed: %v", err)
		writeSTSError(w, http.StatusInternalServerError, "InternalFailure", "failed to issue credentials")
		return
	}
	s.recordAudit(withCallerAccount(ctx, role.AccountID), auditEvent{Action: "sts.AssumeRole", Result: "ok", Actor: r.RemoteAddr})

	resp := stsAssumeRoleResponse{}
	resp.XMLNS = stsXMLNamespace
	resp.Result.Credentials = creds
	resp.Result.AssumedRoleUser = stsAssumedRoleUser{Arn: assumedARN, AssumedRoleID: assumedUserID}
	resp.Metadata.RequestID = newSTSRequestID()
	writeSTSXML(w, http.StatusOK, resp)
}

// ---- AssumeRoleWithWebIdentity ---------------------------------------------

func (s *server) handleSTSAssumeRoleWithWebIdentity(w http.ResponseWriter, r *http.Request) {
	roleARN := strings.TrimSpace(r.PostForm.Get("RoleArn"))
	sessionName := strings.TrimSpace(r.PostForm.Get("RoleSessionName"))
	token := strings.TrimSpace(r.PostForm.Get("WebIdentityToken"))
	if roleARN == "" || sessionName == "" || token == "" {
		writeSTSError(w, http.StatusBadRequest, "ValidationError", "RoleArn, RoleSessionName and WebIdentityToken are required")
		return
	}
	ctx := context.Background()
	role, err := s.store.GetIAMRoleByARN(ctx, roleARN)
	if err != nil {
		writeSTSError(w, http.StatusBadRequest, "NoSuchEntity", "the requested role does not exist")
		return
	}
	if role.Trust.Type != trustTypeOIDC {
		writeSTSError(w, http.StatusForbidden, "AccessDenied", "the role does not trust a web identity provider")
		return
	}

	// The issuer must be a provider registered for the role's account.
	claims, err := verifyWebIdentityToken(ctx, s.oidcHTTPClient(), token)
	if err != nil {
		log.Printf("sts web identity token rejected: %v", err)
		writeSTSError(w, http.StatusBadRequest, "InvalidIdentityToken", "the web identity token could not be validated")
		return
	}
	if normalizeIssuerURL(role.Trust.ProviderURL) != claims.Issuer {
		writeSTSError(w, http.StatusForbidden, "AccessDenied", "token issuer does not match the role's identity provider")
		return
	}
	if _, perr := s.store.GetOIDCProviderByURL(ctx, role.AccountID, claims.Issuer); perr != nil {
		writeSTSError(w, http.StatusForbidden, "AccessDenied", "no identity provider is registered for this issuer")
		return
	}
	if !role.Trust.audienceAllowed(claims.Audiences) {
		writeSTSError(w, http.StatusForbidden, "AccessDenied", "token audience is not allowed by the role trust policy")
		return
	}
	if !role.Trust.subjectAllowed(claims.Subject) {
		writeSTSError(w, http.StatusForbidden, "AccessDenied", "token subject is not allowed by the role trust policy")
		return
	}

	duration := clampDuration(r.PostForm.Get("DurationSeconds"), role.MaxSessionSecs)
	creds, assumedARN, assumedUserID, err := s.mintTempCredentials(ctx, role, sessionName, claims.Subject, duration)
	if err != nil {
		log.Printf("sts AssumeRoleWithWebIdentity mint failed: %v", err)
		writeSTSError(w, http.StatusInternalServerError, "InternalFailure", "failed to issue credentials")
		return
	}
	s.recordAudit(withCallerAccount(ctx, role.AccountID), auditEvent{Action: "sts.AssumeRoleWithWebIdentity", Result: "ok", Actor: r.RemoteAddr})

	resp := stsAssumeRoleWithWebIdentityResponse{}
	resp.XMLNS = stsXMLNamespace
	resp.Result.Credentials = creds
	resp.Result.AssumedRoleUser = stsAssumedRoleUser{Arn: assumedARN, AssumedRoleID: assumedUserID}
	resp.Result.SubjectFromWebIdentityToken = claims.Subject
	resp.Result.Audience = strings.Join(claims.Audiences, ",")
	resp.Result.Provider = claims.Issuer
	resp.Metadata.RequestID = newSTSRequestID()
	writeSTSXML(w, http.StatusOK, resp)
}

// ---- credential minting ----------------------------------------------------

// mintTempCredentials issues, persists and returns a temporary credential set
// bound to the given role. subject is the OIDC subject for web-identity flows
// (empty for AssumeRole).
func (s *server) mintTempCredentials(ctx context.Context, role iamRole, sessionName, subject string, duration time.Duration) (stsCredentials, string, string, error) {
	keyID := generateTempAccessKeyID()
	secret := generateAccessKeySecret()
	sessionToken := generateSessionToken()
	expiry := time.Now().UTC().Add(duration)

	sess := stsSession{
		AccessKeyID:     keyID,
		AccountID:       role.AccountID,
		RoleARN:         role.RoleARN,
		RoleSessionName: sessionName,
		Subject:         subject,
		ExpiresAt:       expiry,
	}
	if err := s.store.CreateSTSSession(ctx, sess, secret, sessionToken); err != nil {
		return stsCredentials{}, "", "", err
	}

	assumedARN := arnFor("sts", "", role.AccountID, "assumed-role/"+role.RoleName+"/"+sessionName)
	assumedUserID := roleUniqueID(role.RoleName) + ":" + sessionName
	creds := stsCredentials{
		AccessKeyID:     keyID,
		SecretAccessKey: secret,
		SessionToken:    sessionToken,
		Expiration:      expiry.Format(time.RFC3339),
	}
	return creds, assumedARN, assumedUserID, nil
}

// oidcHTTPClient returns the HTTP client used for OIDC discovery / JWKS fetch.
func (s *server) oidcHTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}

// ---- helpers ---------------------------------------------------------------

// clampDuration parses a requested DurationSeconds and clamps it to [900, max].
func clampDuration(raw string, maxSecs int) time.Duration {
	if maxSecs <= 0 {
		maxSecs = 3600
	}
	secs := maxSecs
	if v, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && v > 0 {
		secs = v
	}
	if secs < 900 {
		secs = 900
	}
	if secs > maxSecs {
		secs = maxSecs
	}
	return time.Duration(secs) * time.Second
}

// roleUniqueID derives a stable AROA-prefixed unique ID for a role name.
func roleUniqueID(roleName string) string {
	sum := sha1.Sum([]byte("role:" + roleName))
	return "AROA" + strings.ToUpper(base32.StdEncoding.EncodeToString(sum[:])[:16])
}

// principalUserID derives the UserId field for GetCallerIdentity from an ARN.
func principalUserID(arn string) string {
	sum := sha1.Sum([]byte(arn))
	return "AIDA" + strings.ToUpper(base32.StdEncoding.EncodeToString(sum[:])[:16])
}

// newSTSRequestID returns an opaque request id for the response metadata.
func newSTSRequestID() string {
	return generateSessionToken()[:32]
}

// ---- XML response shapes ---------------------------------------------------

type stsCredentials struct {
	AccessKeyID     string `xml:"AccessKeyId"`
	SecretAccessKey string `xml:"SecretAccessKey"`
	SessionToken    string `xml:"SessionToken"`
	Expiration      string `xml:"Expiration"`
}

type stsAssumedRoleUser struct {
	Arn           string `xml:"Arn"`
	AssumedRoleID string `xml:"AssumedRoleId"`
}

type stsResponseMetadata struct {
	RequestID string `xml:"RequestId"`
}

type stsAssumeRoleResponse struct {
	XMLName xml.Name `xml:"AssumeRoleResponse"`
	XMLNS   string   `xml:"xmlns,attr"`
	Result  struct {
		Credentials     stsCredentials     `xml:"Credentials"`
		AssumedRoleUser stsAssumedRoleUser `xml:"AssumedRoleUser"`
	} `xml:"AssumeRoleResult"`
	Metadata stsResponseMetadata `xml:"ResponseMetadata"`
}

type stsAssumeRoleWithWebIdentityResponse struct {
	XMLName xml.Name `xml:"AssumeRoleWithWebIdentityResponse"`
	XMLNS   string   `xml:"xmlns,attr"`
	Result  struct {
		Credentials                 stsCredentials     `xml:"Credentials"`
		AssumedRoleUser             stsAssumedRoleUser `xml:"AssumedRoleUser"`
		SubjectFromWebIdentityToken string             `xml:"SubjectFromWebIdentityToken"`
		Audience                    string             `xml:"Audience"`
		Provider                    string             `xml:"Provider"`
	} `xml:"AssumeRoleWithWebIdentityResult"`
	Metadata stsResponseMetadata `xml:"ResponseMetadata"`
}

type stsGetCallerIdentityResponse struct {
	XMLName xml.Name `xml:"GetCallerIdentityResponse"`
	XMLNS   string   `xml:"xmlns,attr"`
	Result  struct {
		Arn     string `xml:"Arn"`
		UserID  string `xml:"UserId"`
		Account string `xml:"Account"`
	} `xml:"GetCallerIdentityResult"`
	Metadata stsResponseMetadata `xml:"ResponseMetadata"`
}

type stsErrorResponse struct {
	XMLName xml.Name `xml:"ErrorResponse"`
	XMLNS   string   `xml:"xmlns,attr"`
	Error   struct {
		Type    string `xml:"Type"`
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
	RequestID string `xml:"RequestId"`
}

func writeSTSXML(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(payload)
}

func writeSTSError(w http.ResponseWriter, status int, code, message string) {
	resp := stsErrorResponse{XMLNS: stsXMLNamespace}
	resp.Error.Type = "Sender"
	resp.Error.Code = code
	resp.Error.Message = message
	resp.RequestID = newSTSRequestID()
	writeSTSXML(w, status, resp)
}
