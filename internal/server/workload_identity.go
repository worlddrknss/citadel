package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/jose"
	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/workloadid"
)

// Workload identity: Citadel as an OIDC issuer for machines.
//
// The issuer is <KMS_PUBLIC_URL>/oidc (discovery at
// /oidc/.well-known/openid-configuration, keys at /oidc/jwks.json). Tokens
// are requested at POST /oidc/token (OAuth-style body) or POST
// /v1/workload-identity/token ({clientId, audience, kubernetesToken?}).
// A client authenticates its workloads either with a Citadel access key — a
// SigV4-signed request, or "Authorization: Bearer <keyId>:<secret>" — whose
// owner must be in the client's allowedUsers and belong to its account, or
// with a Kubernetes service account token checked through TokenReview with
// the reviewer token from configuration and a dedicated audience. Every
// request, allowed or denied, is audited as citadel.IssueWorkloadToken
// (keyId = client ID) and rate limited per source address and per client.

const (
	workloadMaxTTL       = time.Hour
	maxWorkloadReqBytes  = 64 << 10
	workloadClaimsNSpace = "citadel"
)

func (s *Server) workloadIssuerURL() string {
	if base := s.publicURL(); base != "" {
		return base + "/oidc"
	}
	return ""
}

// workloadIssuer returns the issuer, built once; nil without KMS_PUBLIC_URL.
func (s *Server) workloadIssuer() (*workloadid.Issuer, error) {
	st := s.identity()
	st.issuerOnce.Do(func() {
		iss := s.workloadIssuerURL()
		if iss == "" {
			st.issuerErr = errors.New("KMS_PUBLIC_URL is not set")
			return
		}
		st.k8sAuth = &workloadid.KubernetesAuthenticator{
			ReviewerToken: func(context.Context, workloadid.Client) (string, error) {
				tok, err := s.cfg.K8sReviewerToken()
				if err == nil && tok == "" {
					err = errors.New("no TokenReview reviewer token configured")
				}
				return tok, err
			},
			AllowInsecureHTTP: s.insecureIdentityURLs(),
		}
		if st.httpClient != nil {
			hc := st.httpClient
			st.k8sAuth.HTTPClient = func(workloadid.KubernetesConfig) (*http.Client, error) { return hc, nil }
		}
		st.issuer, st.issuerErr = workloadid.New(workloadid.Config{
			IssuerURL: iss,
			Signers:   s.workloadSigners(),
			Clients:   workloadClientStore{s},
			Authenticator: workloadid.MethodRouter{
				workloadid.AuthAccessKey:  workloadid.AuthenticatorFunc(s.authenticateAccessKeyWorkload),
				workloadid.AuthKubernetes: workloadid.AuthenticatorFunc(s.authenticateK8sWorkload),
			},
			Clock:               func() time.Time { return st.now() },
			MaxTTL:              workloadMaxTTL,
			ClaimsNamespace:     workloadClaimsNSpace,
			OnIssue:             s.onWorkloadTokenIssued,
			AllowInsecureIssuer: s.insecureIdentityURLs(),
		})
	})
	return st.issuer, st.issuerErr
}

// workloadClientStore adapts the store's clients to workloadid.ClientStore.
// Only Get is used by the issuer; clients are managed through the /v1 API.
type workloadClientStore struct{ s *Server }

var errClientStoreReadOnly = errors.New("workload clients are managed through the Citadel API")

func toIssuerClient(c store.WorkloadClient) workloadid.Client {
	out := workloadid.Client{
		ID: c.ClientID, AccountRef: c.AccountID, Name: c.Name, AllowedAudiences: c.Audiences,
		TTL: time.Duration(c.TokenTTLSeconds) * time.Second, SubjectTemplate: c.SubjectFormat,
		CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt,
	}
	switch c.AuthMethod {
	case store.WorkloadAuthAccessKey:
		out.AuthMethod = workloadid.AuthAccessKey
	case store.WorkloadAuthK8s:
		out.AuthMethod = workloadid.AuthKubernetes
		sas := make([]string, 0, len(c.ServiceAccounts))
		for _, sa := range c.ServiceAccounts {
			sas = append(sas, strings.Replace(sa, ":", "/", 1))
		}
		out.Kubernetes = &workloadid.KubernetesConfig{APIServer: c.APIServer, CA: c.CAPEM, Audiences: []string{c.ReviewAudience}, ServiceAccounts: sas}
	}
	return out
}

func (w workloadClientStore) Get(ctx context.Context, id string) (workloadid.Client, error) {
	c, err := w.s.store.GetWorkloadClient(ctx, id)
	if errors.Is(err, store.ErrWorkloadClientNotFound) {
		return workloadid.Client{}, workloadid.ErrClientNotFound
	}
	if err != nil {
		return workloadid.Client{}, err
	}
	return toIssuerClient(c), nil
}

func (workloadClientStore) Create(context.Context, workloadid.Client) (workloadid.Client, error) {
	return workloadid.Client{}, errClientStoreReadOnly
}
func (workloadClientStore) List(context.Context, string) ([]workloadid.Client, error) {
	return nil, errClientStoreReadOnly
}
func (workloadClientStore) Update(context.Context, workloadid.Client) (workloadid.Client, error) {
	return workloadid.Client{}, errClientStoreReadOnly
}
func (workloadClientStore) Delete(context.Context, string) error { return errClientStoreReadOnly }

// workloadAttrs builds the subject template values. Values containing ':'
// (the subject separator) or control characters are refused so a workload
// cannot forge another subject.
func workloadAttrs(c workloadid.Client, extra map[string]string) (map[string]string, error) {
	attrs := map[string]string{"clientId": c.ID, "name": c.Name, "accountId": c.AccountRef}
	for k, v := range extra {
		attrs[k] = v
	}
	for k, v := range attrs {
		if strings.ContainsAny(v, ":{}") || strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return nil, fmt.Errorf("%w: attribute %s has a disallowed character", workloadid.ErrForbidden, k)
		}
	}
	return attrs, nil
}

// workloadReqInfo carries per-request results from the authenticators and
// OnIssue back to the token handler (for the audit event).
type workloadReqInfo struct {
	actor, actorType, accessKeyID string
	workload                      *workloadid.Workload
}

type workloadReqKey struct{}

func workloadInfo(ctx context.Context) *workloadReqInfo {
	if v, ok := ctx.Value(workloadReqKey{}).(*workloadReqInfo); ok {
		return v
	}
	return &workloadReqInfo{}
}

// authenticateAccessKeyWorkload authenticates an access-key client's
// request: a verified SigV4 caller (attached by the token handler) or a
// bearer "<keyId>:<secret>" credential.
func (s *Server) authenticateAccessKeyWorkload(ctx context.Context, req *workloadid.AuthRequest) (workloadid.Workload, error) {
	stored, err := s.store.GetWorkloadClient(ctx, req.Client.ID)
	if err != nil {
		return workloadid.Workload{}, fmt.Errorf("%w: client lookup", workloadid.ErrUnauthenticated)
	}
	var caller awsCaller
	if req.HTTP != nil {
		if c, ok := awsCallerFromContext(req.HTTP.Context()); ok {
			caller = c
		}
	}
	if caller.AccessKeyID == "" {
		keyID, secret, found := strings.Cut(req.Credential, ":")
		if !found || keyID == "" || secret == "" || store.IsTempAccessKeyID(keyID) {
			return workloadid.Workload{}, fmt.Errorf("%w: no access key credential", workloadid.ErrUnauthenticated)
		}
		owner, acct, storedSecret, status, err := s.store.GetAccessKeyByID(ctx, keyID)
		if err != nil || !strings.EqualFold(status, "active") || subtle.ConstantTimeCompare([]byte(secret), []byte(storedSecret)) != 1 {
			return workloadid.Workload{}, fmt.Errorf("%w: invalid access key", workloadid.ErrUnauthenticated)
		}
		_ = s.store.TouchAccessKeyLastUsed(ctx, keyID)
		caller = awsCaller{AccessKeyID: keyID, Username: owner, AccountID: acct}
	}
	info := workloadInfo(ctx)
	info.actor, info.actorType, info.accessKeyID = caller.Username, store.AuditActorAccessKey, caller.AccessKeyID
	if caller.Temporary || (s.cfg.ExpectedAccessKey != "" && caller.AccessKeyID == s.cfg.ExpectedAccessKey) {
		return workloadid.Workload{}, fmt.Errorf("%w: only user access keys may obtain workload tokens", workloadid.ErrForbidden)
	}
	if caller.AccountID != stored.AccountID || !slices.Contains(stored.AllowedUsers, caller.Username) {
		return workloadid.Workload{}, fmt.Errorf("%w: %s is not allowed to use this client", workloadid.ErrForbidden, caller.Username)
	}
	user, found := s.lookupUser(ctx, caller.Username)
	if !found {
		return workloadid.Workload{}, fmt.Errorf("%w: key owner no longer exists", workloadid.ErrForbidden)
	}
	if _, member := accountRole(s.userMemberships(ctx, user), stored.AccountID); !member {
		return workloadid.Workload{}, fmt.Errorf("%w: key owner left the account", workloadid.ErrForbidden)
	}
	attrs, err := workloadAttrs(req.Client, map[string]string{"username": caller.Username, "accessKeyId": caller.AccessKeyID})
	if err != nil {
		return workloadid.Workload{}, err
	}
	return workloadid.Workload{AccountRef: req.Client.AccountRef, ClientID: req.Client.ID, Subject: caller.Username, Attributes: attrs}, nil
}

// authenticateK8sWorkload checks a Kubernetes service account token with
// TokenReview and maps its attributes to the subject template names.
func (s *Server) authenticateK8sWorkload(ctx context.Context, req *workloadid.AuthRequest) (workloadid.Workload, error) {
	if !s.cfg.K8sReviewConfigured() {
		return workloadid.Workload{}, fmt.Errorf("%w: Kubernetes TokenReview is not configured", workloadid.ErrUnauthenticated)
	}
	w, err := s.identity().k8sAuth.Authenticate(ctx, req)
	if err != nil {
		return w, err
	}
	info := workloadInfo(ctx)
	info.actor, info.actorType = w.Subject, store.AuditActorWebIdentity
	extra := map[string]string{"namespace": w.Attributes["namespace"], "serviceAccount": w.Attributes["service_account"]}
	if pod := w.Attributes["pod"]; pod != "" {
		extra["podName"] = pod
	}
	attrs, err := workloadAttrs(req.Client, extra)
	if err != nil {
		return workloadid.Workload{}, err
	}
	w.Attributes = attrs
	return w, nil
}

func (s *Server) onWorkloadTokenIssued(ctx context.Context, w workloadid.Workload, c workloadid.Client, _, _ string, _ time.Time) {
	info := workloadInfo(ctx)
	info.workload = &w
	if err := s.store.TouchWorkloadClientIssued(ctx, c.ID, s.identity().now().UTC()); err != nil {
		log.Printf("workload identity: touch client: %v", err)
	}
}

type workloadTokenRequest struct {
	clientID, audience, credential string
	ttl                            time.Duration
}

// issueWorkloadToken runs one token request: rate limits, optional SigV4
// verification, issuance and the audit event. It returns the token or an
// issuer error (always *workloadid.Error).
func (s *Server) issueWorkloadToken(r *http.Request, body []byte, parse func([]byte) (workloadTokenRequest, *workloadid.Error)) (*workloadid.Token, *workloadid.Error) {
	st := s.identity()
	if ok, _ := st.tokenIP.Reserve(s.clientIP(r)); !ok {
		return nil, &workloadid.Error{Status: http.StatusTooManyRequests, Code: "rate_limited", Description: "too many token requests; slow down"}
	}
	iss, err := s.workloadIssuer()
	if err != nil {
		return nil, &workloadid.Error{Status: http.StatusServiceUnavailable, Code: "not_configured", Description: "workload identity needs KMS_PUBLIC_URL"}
	}
	req, perr := parse(body)
	if perr != nil {
		return nil, perr
	}
	if ok, _ := st.tokenCli.Reserve(req.clientID); !ok {
		return nil, &workloadid.Error{Status: http.StatusTooManyRequests, Code: "rate_limited", Description: "too many token requests for this client; slow down"}
	}
	info := &workloadReqInfo{actor: "anonymous", actorType: store.AuditActorAnonymous}
	ctx := context.WithValue(r.Context(), workloadReqKey{}, info)
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(strings.TrimSpace(auth), "AWS4-HMAC-SHA256") {
		sum := sha256.Sum256(body)
		bodyHash := hex.EncodeToString(sum[:])
		caller, verr := s.verifyAWSRequest(r, bodyHash)
		if verr != nil {
			log.Printf("workload identity: sigv4: %v", verr)
			e := &workloadid.Error{Status: http.StatusUnauthorized, Code: "invalid_client", Description: "workload authentication failed"}
			s.auditWorkloadToken(r, ctx, req.clientID, info, e)
			return nil, e
		}
		ctx = withAWSCaller(ctx, caller)
	}
	r = r.WithContext(ctx)
	tok, ierr := iss.Issue(ctx, workloadid.TokenRequest{ClientID: req.clientID, Audience: req.audience, TTL: req.ttl, Credential: req.credential, HTTP: r})
	if ierr != nil {
		var e *workloadid.Error
		if !errors.As(ierr, &e) {
			e = &workloadid.Error{Status: 500, Code: "server_error", Description: "internal error", Err: ierr}
		}
		if e.Err != nil {
			log.Printf("workload identity: client %q: %v", req.clientID, e.Err)
		}
		s.auditWorkloadToken(r, ctx, req.clientID, info, e)
		return nil, e
	}
	s.auditWorkloadToken(r, ctx, req.clientID, info, nil)
	return tok, nil
}

func (s *Server) auditWorkloadToken(r *http.Request, ctx context.Context, clientID string, info *workloadReqInfo, e *workloadid.Error) {
	o := s.auditOrigin(r)
	o.Actor, o.ActorType, o.ActorDisplayName, o.AccessKeyID = truncate(info.actor, 200), info.actorType, "", info.accessKeyID
	if info.workload != nil && info.workload.Subject != "" {
		o.Resource = truncate(info.workload.Subject, 200)
	}
	ev := store.AuditEvent{Action: "citadel.IssueWorkloadToken", KeyID: truncate(clientID, 128), Result: "ok", AuditOrigin: o}
	actx := store.WithCallerAccount(context.WithoutCancel(ctx), "")
	if c, err := s.store.GetWorkloadClient(ctx, clientID); err == nil {
		actx = store.WithCallerAccount(actx, c.AccountID)
	}
	if e != nil {
		ev.Result = "denied"
		if e.Status >= 500 {
			ev.Result = "error"
		}
		ev.ErrorType = e.Code
	}
	s.recordAudit(actx, ev)
}

func writeWorkloadError(w http.ResponseWriter, e *workloadid.Error, native bool) {
	if e.Status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="citadel-workload-identity"`)
	}
	if e.Status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "1")
	}
	if native {
		writeNativeError(w, e.Status, e.Code, e.Description)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(e)
}

func readWorkloadBody(w http.ResponseWriter, r *http.Request) ([]byte, *workloadid.Error) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWorkloadReqBytes))
	if err != nil {
		return nil, &workloadid.Error{Status: http.StatusRequestEntityTooLarge, Code: "invalid_request", Description: "request body too large"}
	}
	return body, nil
}

// handleV1WorkloadToken is POST /v1/workload-identity/token:
// {clientId, audience, kubernetesToken?, ttlSeconds?} -> {token, expiresAt, tokenType}.
func (s *Server) handleV1WorkloadToken(w http.ResponseWriter, r *http.Request) {
	body, e := readWorkloadBody(w, r)
	if e != nil {
		writeWorkloadError(w, e, true)
		return
	}
	tok, e := s.issueWorkloadToken(r, body, func(b []byte) (workloadTokenRequest, *workloadid.Error) {
		var in struct {
			ClientID        string `json:"clientId"`
			Audience        string `json:"audience"`
			KubernetesToken string `json:"kubernetesToken"`
			TTLSeconds      int64  `json:"ttlSeconds"`
		}
		dec := json.NewDecoder(strings.NewReader(string(b)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil {
			return workloadTokenRequest{}, &workloadid.Error{Status: 400, Code: "invalid_request", Description: "invalid JSON body"}
		}
		if in.TTLSeconds < 0 || in.TTLSeconds > int64(workloadMaxTTL/time.Second) {
			return workloadTokenRequest{}, &workloadid.Error{Status: 400, Code: "invalid_request", Description: "ttlSeconds out of range"}
		}
		cred := in.KubernetesToken
		if cred == "" {
			cred = bearerCredential(r)
		}
		return workloadTokenRequest{clientID: in.ClientID, audience: in.Audience, credential: cred, ttl: time.Duration(in.TTLSeconds) * time.Second}, nil
	})
	if e != nil {
		writeWorkloadError(w, e, true)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeNativeJSON(w, http.StatusOK, map[string]string{"token": tok.Token, "expiresAt": tok.ExpiresAt.Format(time.RFC3339), "tokenType": "id_token"})
}

func bearerCredential(r *http.Request) string {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// handleOIDCToken is POST /oidc/token with the issuer's OAuth-style body
// (JSON or form: client_id, audience, ttl_seconds, credential).
func (s *Server) handleOIDCToken(w http.ResponseWriter, r *http.Request) {
	body, e := readWorkloadBody(w, r)
	if e != nil {
		writeWorkloadError(w, e, false)
		return
	}
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	tok, e := s.issueWorkloadToken(r, body, func(b []byte) (workloadTokenRequest, *workloadid.Error) {
		var in struct {
			ClientID   string `json:"client_id"`
			Audience   string `json:"audience"`
			TTLSeconds int64  `json:"ttl_seconds"`
			Credential string `json:"credential"`
		}
		switch mt {
		case "application/json":
			dec := json.NewDecoder(strings.NewReader(string(b)))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&in); err != nil {
				return workloadTokenRequest{}, &workloadid.Error{Status: 400, Code: "invalid_request", Description: "malformed JSON body"}
			}
		case "application/x-www-form-urlencoded":
			form, err := parseFormBody(b)
			if err != nil {
				return workloadTokenRequest{}, &workloadid.Error{Status: 400, Code: "invalid_request", Description: "malformed form body"}
			}
			in.ClientID, in.Audience, in.Credential = form.Get("client_id"), form.Get("audience"), form.Get("credential")
			if v := form.Get("ttl_seconds"); v != "" {
				if in.TTLSeconds, err = strconv.ParseInt(v, 10, 64); err != nil {
					return workloadTokenRequest{}, &workloadid.Error{Status: 400, Code: "invalid_request", Description: "ttl_seconds must be an integer"}
				}
			}
		default:
			return workloadTokenRequest{}, &workloadid.Error{Status: 415, Code: "invalid_request", Description: "content type must be application/json or application/x-www-form-urlencoded"}
		}
		if in.TTLSeconds < 0 || in.TTLSeconds > int64(workloadMaxTTL/time.Second) {
			return workloadTokenRequest{}, &workloadid.Error{Status: 400, Code: "invalid_request", Description: "ttl_seconds out of range"}
		}
		if in.Credential == "" {
			in.Credential = bearerCredential(r)
		}
		return workloadTokenRequest{clientID: in.ClientID, audience: in.Audience, credential: in.Credential, ttl: time.Duration(in.TTLSeconds) * time.Second}, nil
	})
	if e != nil {
		writeWorkloadError(w, e, false)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(tok)
}

// handleOIDC serves the issuer's public documents under /oidc/.
func (s *Server) handleOIDC(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/oidc/token" {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeWorkloadError(w, &workloadid.Error{Status: http.StatusMethodNotAllowed, Code: "invalid_request", Description: "method not allowed"}, false)
			return
		}
		s.handleOIDCToken(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeWorkloadError(w, &workloadid.Error{Status: http.StatusMethodNotAllowed, Code: "invalid_request", Description: "method not allowed"}, false)
		return
	}
	iss, err := s.workloadIssuer()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var (
		doc   any
		cache string
	)
	switch r.URL.Path {
	case "/oidc" + workloadid.DiscoveryPath:
		doc, err = iss.Discovery(r.Context())
		cache = "public, max-age=3600"
	case "/oidc" + workloadid.JWKSPath:
		doc, err = iss.JWKS(r.Context())
		cache = "public, max-age=300"
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		log.Printf("workload identity: keys: %v", err)
		writeWorkloadError(w, &workloadid.Error{Status: 500, Code: "server_error", Description: "keys unavailable"}, false)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", cache)
	_ = json.NewEncoder(w).Encode(doc)
}

// ---- issuer administration --------------------------------------------------

type signingKeyJSON struct {
	KID         string `json:"kid"`
	KMSKeyID    string `json:"kmsKeyId"`
	Algorithm   string `json:"algorithm"`
	ActivatedAt string `json:"activatedAt"`
}

type retiredKeyJSON struct {
	KID         string `json:"kid"`
	KMSKeyID    string `json:"kmsKeyId"`
	Algorithm   string `json:"algorithm"`
	RetiredAt   string `json:"retiredAt"`
	UnpublishAt string `json:"unpublishAt"`
}

func (s *Server) issuerInfo(ctx context.Context) (map[string]any, error) {
	cur, keys, err := s.currentWorkloadKey(ctx)
	if err != nil {
		return nil, err
	}
	settings := s.workloadIssuerSettings(ctx)
	iss := s.workloadIssuerURL()
	out := map[string]any{
		"issuer": iss, "discoveryUrl": "", "jwksUrl": "", "tokenEndpoint": "",
		"signingKey": nil, "previousKeys": []retiredKeyJSON{}, "rotationDays": settings.RotationDays,
		"algorithm": settings.Algorithm, "configured": iss != "",
	}
	if iss != "" {
		out["discoveryUrl"] = iss + workloadid.DiscoveryPath
		out["jwksUrl"] = iss + workloadid.JWKSPath
		out["tokenEndpoint"] = s.publicURL() + "/v1/workload-identity/token"
	}
	now := s.identity().now()
	prev := []retiredKeyJSON{}
	for _, k := range keys {
		if k.RetiredAt.IsZero() || !now.Before(k.UnpublishAt) {
			continue
		}
		prev = append(prev, retiredKeyJSON{KID: k.KID, KMSKeyID: k.KMSKeyID, Algorithm: k.Algorithm,
			RetiredAt: k.RetiredAt.Format(time.RFC3339), UnpublishAt: k.UnpublishAt.Format(time.RFC3339)})
	}
	out["previousKeys"] = prev
	if cur.KID != "" {
		out["signingKey"] = signingKeyJSON{KID: cur.KID, KMSKeyID: cur.KMSKeyID, Algorithm: cur.Algorithm, ActivatedAt: cur.ActivatedAt.Format(time.RFC3339)}
		out["nextRotationAt"] = cur.ActivatedAt.Add(time.Duration(settings.RotationDays) * 24 * time.Hour).Format(time.RFC3339)
	}
	return out, nil
}

func (s *Server) writeIssuerInfo(w http.ResponseWriter, ctx context.Context) {
	info, err := s.issuerInfo(ctx)
	if err != nil {
		log.Printf("workload identity: issuer info: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "load_failed", "could not load the issuer")
		return
	}
	writeNativeJSON(w, http.StatusOK, info)
}

func (s *Server) handleV1WorkloadIssuer(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	s.writeIssuerInfo(w, ctx)
}

// platformAdminSession requires a platform admin console session: the issuer
// is shared by every account.
func (s *Server) platformAdminSession(w http.ResponseWriter, r *http.Request, action string) (*uiSession, context.Context, bool) {
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return nil, nil, false
	}
	if !sess.PlatformAdmin || sess.ViaToken {
		s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "denied", ErrorType: "AccessDenied", AuditOrigin: s.auditOrigin(r)})
		writeNativeError(w, http.StatusForbidden, "forbidden", "only platform admins can manage the workload identity issuer")
		return nil, nil, false
	}
	return sess, ctx, true
}

func (s *Server) handleV1WorkloadIssuerSettings(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.UpdateWorkloadIssuerSettings"
	sess, ctx, ok := s.platformAdminSession(w, r, action)
	if !ok {
		return
	}
	var in struct {
		Algorithm    string `json:"algorithm"`
		RotationDays int    `json:"rotationDays"`
	}
	if err := decodeJSONBody(r, &in); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	if !jose.IsSupported(in.Algorithm) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "algorithm must be ES256, ES384, RS256 or PS256")
		return
	}
	if in.RotationDays < 7 || in.RotationDays > 365 {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "rotationDays must be 7-365")
		return
	}
	if err := s.store.PutWorkloadIssuerSettings(ctx, store.WorkloadIssuerSettings{Algorithm: in.Algorithm, RotationDays: in.RotationDays, UpdatedAt: time.Now().UTC().Truncate(time.Second), UpdatedBy: sess.Username}); err != nil {
		log.Printf("workload identity: save settings: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "save_failed", "could not save the issuer settings")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: in.Algorithm + "/" + strconv.Itoa(in.RotationDays) + "d", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	// A new algorithm takes effect at once: rotate to a key of that type.
	if cur, _, err := s.currentWorkloadKey(ctx); err == nil && cur.KID != "" && cur.Algorithm != in.Algorithm {
		if next, err := s.rotateWorkloadKey(ctx, cur.KID); err == nil {
			s.recordAudit(ctx, store.AuditEvent{Action: "citadel.RotateWorkloadSigningKey", KeyID: next.KID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
		} else {
			log.Printf("workload identity: rotate after algorithm change: %v", err)
		}
	}
	s.writeIssuerInfo(w, ctx)
}

func (s *Server) handleV1WorkloadIssuerRotate(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.RotateWorkloadSigningKey"
	_, ctx, ok := s.platformAdminSession(w, r, action)
	if !ok {
		return
	}
	cur, _, err := s.currentWorkloadKey(ctx)
	if err == nil {
		var next store.WorkloadSigningKey
		next, err = s.rotateWorkloadKey(ctx, cur.KID)
		if err == nil {
			s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: next.KID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
			s.writeIssuerInfo(w, ctx)
			return
		}
	}
	if errors.Is(err, store.ErrWorkloadRotationConflict) {
		writeNativeError(w, http.StatusConflict, "conflict", "the signing key changed concurrently; reload and retry")
		return
	}
	log.Printf("workload identity: rotate: %v", err)
	s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "error", ErrorType: "RotationFailed", AuditOrigin: s.auditOrigin(r)})
	writeNativeError(w, http.StatusInternalServerError, "rotate_failed", "could not rotate the signing key")
}

// ---- clients ----------------------------------------------------------------

type workloadClientAuthJSON struct {
	Method          string   `json:"method"`
	AllowedUsers    []string `json:"allowedUsers,omitempty"`
	APIServer       string   `json:"apiServer,omitempty"`
	CAPEM           string   `json:"caPem,omitempty"`
	ServiceAccounts []string `json:"serviceAccounts,omitempty"`
	ReviewAudience  string   `json:"reviewAudience,omitempty"`
}

type workloadClientJSON struct {
	ClientID        string                 `json:"clientId"`
	Name            string                 `json:"name"`
	Audiences       []string               `json:"audiences"`
	TokenTTLSeconds int                    `json:"tokenTtlSeconds"`
	SubjectFormat   string                 `json:"subjectFormat"`
	Auth            workloadClientAuthJSON `json:"auth"`
	CreatedAt       string                 `json:"createdAt,omitempty"`
	UpdatedAt       string                 `json:"updatedAt,omitempty"`
	LastIssuedAt    string                 `json:"lastIssuedAt,omitempty"`
}

func workloadClientOut(c store.WorkloadClient) workloadClientJSON {
	out := workloadClientJSON{
		ClientID: c.ClientID, Name: c.Name, Audiences: c.Audiences, TokenTTLSeconds: c.TokenTTLSeconds, SubjectFormat: c.SubjectFormat,
		Auth:      workloadClientAuthJSON{Method: c.AuthMethod},
		CreatedAt: c.CreatedAt.Format(time.RFC3339), UpdatedAt: c.UpdatedAt.Format(time.RFC3339),
	}
	if out.Audiences == nil {
		out.Audiences = []string{}
	}
	switch c.AuthMethod {
	case store.WorkloadAuthAccessKey:
		out.Auth.AllowedUsers = c.AllowedUsers
		if out.Auth.AllowedUsers == nil {
			out.Auth.AllowedUsers = []string{}
		}
	case store.WorkloadAuthK8s:
		out.Auth.APIServer, out.Auth.CAPEM, out.Auth.ReviewAudience = c.APIServer, c.CAPEM, c.ReviewAudience
		out.Auth.ServiceAccounts = c.ServiceAccounts
		if out.Auth.ServiceAccounts == nil {
			out.Auth.ServiceAccounts = []string{}
		}
	}
	if !c.LastIssuedAt.IsZero() {
		out.LastIssuedAt = c.LastIssuedAt.Format(time.RFC3339)
	}
	return out
}

var (
	workloadNameRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)
	k8sNameRe          = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)
	subjectPlaceholder = regexp.MustCompile(`\{([^{}]*)\}`)
	placeholdersFor    = map[string][]string{
		store.WorkloadAuthAccessKey: {"clientId", "name", "accountId", "username", "accessKeyId"},
		store.WorkloadAuthK8s:       {"clientId", "name", "accountId", "namespace", "serviceAccount", "podName"},
	}
)

// validateWorkloadClient checks in for account accountID and fills c.
func (s *Server) validateWorkloadClient(ctx context.Context, accountID string, in workloadClientJSON, c *store.WorkloadClient) string {
	c.Name = strings.TrimSpace(in.Name)
	c.SubjectFormat = strings.TrimSpace(in.SubjectFormat)
	c.TokenTTLSeconds = in.TokenTTLSeconds
	c.AuthMethod = in.Auth.Method
	if !workloadNameRe.MatchString(c.Name) {
		return "name must be 1-64 letters, digits, spaces, dots, dashes or underscores"
	}
	if len(in.Audiences) == 0 || len(in.Audiences) > 10 {
		return "between 1 and 10 audiences are required"
	}
	c.Audiences = nil
	for _, a := range in.Audiences {
		a = strings.TrimSpace(a)
		if !printable(a, 256) || strings.ContainsAny(a, " \t") {
			return "invalid audience"
		}
		if !slices.Contains(c.Audiences, a) {
			c.Audiences = append(c.Audiences, a)
		}
	}
	if c.TokenTTLSeconds < 60 || c.TokenTTLSeconds > int(workloadMaxTTL/time.Second) {
		return "tokenTtlSeconds must be 60-3600"
	}
	allowed, ok := placeholdersFor[c.AuthMethod]
	if !ok {
		return "auth.method must be access-key or k8s-token-review"
	}
	if !printable(c.SubjectFormat, 255) || strings.Count(c.SubjectFormat, "{") != strings.Count(c.SubjectFormat, "}") {
		return "subjectFormat must be 1-255 characters with balanced braces"
	}
	for _, m := range subjectPlaceholder.FindAllStringSubmatch(c.SubjectFormat, -1) {
		if !slices.Contains(allowed, m[1]) {
			return "unknown placeholder {" + m[1] + "} for this auth method"
		}
	}
	switch c.AuthMethod {
	case store.WorkloadAuthAccessKey:
		if len(in.Auth.AllowedUsers) == 0 || len(in.Auth.AllowedUsers) > 100 {
			return "between 1 and 100 allowedUsers are required"
		}
		for _, u := range in.Auth.AllowedUsers {
			u = strings.TrimSpace(u)
			user, found := s.lookupUser(ctx, u)
			if !found {
				return "allowed user " + strconv.Quote(u) + " does not exist"
			}
			if _, member := accountRole(s.userMemberships(ctx, user), accountID); !member {
				return "allowed user " + strconv.Quote(u) + " is not a member of this account"
			}
			if !slices.Contains(c.AllowedUsers, u) {
				c.AllowedUsers = append(c.AllowedUsers, u)
			}
		}
		if in.Auth.APIServer != "" || in.Auth.CAPEM != "" || len(in.Auth.ServiceAccounts) > 0 || in.Auth.ReviewAudience != "" {
			return "kubernetes settings on an access-key client"
		}
	case store.WorkloadAuthK8s:
		if !s.cfg.K8sReviewConfigured() {
			return "Kubernetes TokenReview is not configured on this server (KMS_WORKLOAD_K8S_REVIEWER_TOKEN_FILE)"
		}
		c.APIServer = strings.TrimRight(strings.TrimSpace(in.Auth.APIServer), "/")
		if err := jose.CheckURL(c.APIServer, s.insecureIdentityURLs()); err != nil || len(c.APIServer) > 512 {
			return "apiServer must be an https URL"
		}
		c.CAPEM = strings.TrimSpace(in.Auth.CAPEM)
		if c.CAPEM != "" {
			if len(c.CAPEM) > 64<<10 || !validCertPEM(c.CAPEM) {
				return "caPem must contain PEM certificates"
			}
		}
		c.ReviewAudience = strings.TrimSpace(in.Auth.ReviewAudience)
		if !printable(c.ReviewAudience, 256) {
			return "reviewAudience is required: use a dedicated audience (for example \"citadel\") via a projected service account token"
		}
		if strings.Contains(c.ReviewAudience, "kubernetes.default.svc") || c.ReviewAudience == c.APIServer {
			return "reviewAudience must be dedicated to Citadel, not the API server's own audience"
		}
		if len(in.Auth.ServiceAccounts) == 0 || len(in.Auth.ServiceAccounts) > 100 {
			return "between 1 and 100 serviceAccounts are required"
		}
		for _, sa := range in.Auth.ServiceAccounts {
			sa = strings.TrimSpace(sa)
			ns, name, ok := strings.Cut(sa, ":")
			if !ok || !k8sNameRe.MatchString(ns) || !k8sNameRe.MatchString(name) || len(ns) > 63 {
				return "serviceAccounts must be \"namespace:name\""
			}
			if !slices.Contains(c.ServiceAccounts, sa) {
				c.ServiceAccounts = append(c.ServiceAccounts, sa)
			}
		}
		if len(in.Auth.AllowedUsers) > 0 {
			return "allowedUsers on a k8s-token-review client"
		}
	}
	return ""
}

func validCertPEM(s string) bool {
	rest := []byte(s)
	n := 0
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return false
		}
		if _, err := x509.ParseCertificate(b.Bytes); err != nil {
			return false
		}
		n++
	}
	return n > 0 && strings.TrimSpace(string(rest)) == ""
}

func (s *Server) handleV1ListWorkloadClients(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	cs, err := s.store.ListWorkloadClients(ctx, sess.AccountID)
	if err != nil {
		log.Printf("workload identity: list clients: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "list_failed", "could not list clients")
		return
	}
	out := make([]workloadClientJSON, 0, len(cs))
	for _, c := range cs {
		out = append(out, workloadClientOut(c))
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{"clients": out})
}

func (s *Server) handleV1CreateWorkloadClient(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.CreateWorkloadClient"
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	var in workloadClientJSON
	if err := decodeJSONBody(r, &in); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	if in.ClientID != "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "clientId is assigned by the server")
		return
	}
	c := store.WorkloadClient{AccountID: sess.AccountID}
	if msg := s.validateWorkloadClient(ctx, sess.AccountID, in, &c); msg != "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", msg)
		return
	}
	c.ClientID = "wic-" + cryptoutil.RandomHex(10)
	now := time.Now().UTC().Truncate(time.Second)
	c.CreatedAt, c.UpdatedAt = now, now
	if err := s.store.CreateWorkloadClient(ctx, c); err != nil {
		log.Printf("workload identity: create client: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "create_failed", "could not create the client")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: c.ClientID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusCreated, map[string]string{"clientId": c.ClientID})
}

func (s *Server) handleV1UpdateWorkloadClient(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.UpdateWorkloadClient"
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	var in workloadClientJSON
	if err := decodeJSONBody(r, &in); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	cur, err := s.store.GetWorkloadClient(ctx, strings.TrimSpace(in.ClientID))
	if err != nil || cur.AccountID != sess.AccountID {
		if err != nil && !errors.Is(err, store.ErrWorkloadClientNotFound) {
			log.Printf("workload identity: load client: %v", err)
		}
		writeNativeError(w, http.StatusNotFound, "not_found", "client not found")
		return
	}
	next := store.WorkloadClient{ClientID: cur.ClientID, AccountID: cur.AccountID}
	if msg := s.validateWorkloadClient(ctx, sess.AccountID, in, &next); msg != "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", msg)
		return
	}
	next.UpdatedAt = time.Now().UTC().Truncate(time.Second)
	if err := s.store.UpdateWorkloadClient(ctx, next); err != nil {
		if errors.Is(err, store.ErrWorkloadClientNotFound) {
			writeNativeError(w, http.StatusNotFound, "not_found", "client not found")
			return
		}
		log.Printf("workload identity: update client: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "update_failed", "could not update the client")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: cur.ClientID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"clientId": cur.ClientID, "updated": true})
}

func (s *Server) handleV1DeleteWorkloadClient(w http.ResponseWriter, r *http.Request) {
	const action = "citadel.DeleteWorkloadClient"
	sess, ctx, ok := s.nativeSession(w, r, "admin")
	if !ok {
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("clientId"))
	if id == "" || len(id) > 128 {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "clientId is required")
		return
	}
	err := s.store.DeleteWorkloadClient(ctx, sess.AccountID, id)
	if errors.Is(err, store.ErrWorkloadClientNotFound) {
		writeNativeError(w, http.StatusNotFound, "not_found", "client not found")
		return
	}
	if err != nil {
		log.Printf("workload identity: delete client: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "delete_failed", "could not delete the client")
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: id, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}
