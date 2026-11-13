package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// registerRotationRoutes adds the built-in rotation API and its job. POST
// and DELETE /v1/secrets/rotation (configure, turn off) predate it and are
// registered in server.go.
func (s *Server) registerRotationRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/secrets/rotation", s.handleV1GetRotation)
	mux.HandleFunc("POST /v1/secrets/rotation/rotate", s.handleV1RotateNow)
	mux.HandleFunc("POST /v1/secrets/rotation/signing-secret", s.handleV1RegenerateSigningSecret)
	s.jobs.Every("secret-rotation", rotationJobInterval, s.rotationJob)
}

// rotationInputError is a request validation failure; its text is safe to
// return.
type rotationInputError struct{ msg string }

func (e rotationInputError) Error() string { return e.msg }

func inputErr(err error) error { return rotationInputError{msg: err.Error()} }

// secretRotationRequest is a RotateSecret call, from either API.
type secretRotationRequest struct {
	SecretID     string
	LambdaARN    string
	RotatorType  string
	ConfigSecret string
	// Config is the inline configuration JSON; nil keeps the stored one
	// when the rotator type is unchanged.
	Config             *string
	AfterDays          int
	ScheduleExpression string
	Duration           string
	RotateImmediately  bool
	Token              string
	// checkApproval runs once a built-in rotator is selected; an error
	// refuses the change (approval-required environments).
	checkApproval func() error
}

type secretRotationResult struct {
	Meta    store.SecretMetadataRecord
	Token   string
	Builtin bool
	// SigningSecret is a newly generated webhook signing secret, returned
	// once.
	SigningSecret string
}

func (s *Server) callerAccount(ctx context.Context) string {
	if acct, ok := store.CallerAccountFromContext(ctx); ok {
		return acct
	}
	_, acct := s.store.DeploymentIdentity()
	return acct
}

// configureRotation validates and stores a rotation configuration, and
// starts a rotation when asked.
func (s *Server) configureRotation(ctx context.Context, req secretRotationRequest) (secretRotationResult, error) {
	meta, err := s.store.DescribeSecret(ctx, req.SecretID)
	if err != nil {
		return secretRotationResult{}, err
	}
	if meta.DeletedDate != nil {
		return secretRotationResult{}, store.ErrSecretPendingDeletion
	}
	region, _ := s.store.DeploymentIdentity()
	account := s.callerAccount(ctx)
	existing, err := s.store.GetSecretRotation(ctx, meta.Name)
	hasExisting := err == nil
	if err != nil && !errors.Is(err, store.ErrRotationNotConfigured) {
		return secretRotationResult{}, err
	}

	typ, configID := strings.TrimSpace(req.RotatorType), strings.TrimSpace(req.ConfigSecret)
	lambda := strings.TrimSpace(req.LambdaARN)
	if len(lambda) > 2048 {
		return secretRotationResult{}, rotationInputError{"RotationLambdaARN is too long"}
	}
	if ra, ok, err := parseRotatorARN(lambda, region, account); ok {
		if err != nil {
			return secretRotationResult{}, inputErr(err)
		}
		if typ != "" && typ != ra.Type {
			return secretRotationResult{}, rotationInputError{"the rotator type doesn't match RotationLambdaARN"}
		}
		typ, configID = ra.Type, ra.ConfigID
	} else if lambda == "" && typ == "" {
		// RotateSecret without an ARN keeps what is configured.
		if hasExisting && existing.RotatorType != "" {
			typ, configID = existing.RotatorType, existing.ConfigSecret
		} else {
			lambda = meta.RotationLambdaARN
		}
	}
	if typ != "" {
		switch typ {
		case store.RotatorRandom, store.RotatorPostgreSQL, store.RotatorWebhook:
		default:
			return secretRotationResult{}, rotationInputError{"rotator type must be random, postgresql or webhook"}
		}
		lambda = buildRotatorARN(region, account, typ, configID)
		if req.checkApproval != nil {
			if err := req.checkApproval(); err != nil {
				return secretRotationResult{}, err
			}
		}
	}

	afterDays, expr, duration := req.AfterDays, strings.TrimSpace(req.ScheduleExpression), strings.TrimSpace(req.Duration)
	if afterDays == 0 && expr == "" && duration == "" && hasExisting && (meta.RotationDays > 0 || existing.ScheduleExpression != "") {
		afterDays, expr, duration = meta.RotationDays, existing.ScheduleExpression, existing.Duration
	}
	sch, err := parseRotationSchedule(afterDays, expr, duration)
	if err != nil {
		return secretRotationResult{}, inputErr(err)
	}

	cfg := store.SecretRotationConfig{
		SecretID: meta.Name, LambdaARN: lambda, ScheduleExpression: sch.expr, Duration: sch.durationString(),
		RotatorType: typ, ConfigSecret: configID, ClearSigningKey: true,
	}
	if sch.expr == "" {
		cfg.AfterDays = sch.n
	}
	var signingSecret string
	switch {
	case typ != "" && configID != "":
		if configID == meta.Name {
			return secretRotationResult{}, rotationInputError{"a secret can't hold its own rotator configuration"}
		}
		v, err := s.store.GetSecretValue(ctx, configID, "", store.CurrentVersionStage)
		if err != nil || v.SecretString == nil {
			return secretRotationResult{}, rotationInputError{"the configuration secret " + configID + " doesn't exist in this account"}
		}
		c, err := decodeRotatorConfig(*v.SecretString)
		if err != nil {
			return secretRotationResult{}, inputErr(err)
		}
		if err := c.validate(typ, false); err != nil {
			return secretRotationResult{}, inputErr(err)
		}
	case typ != "":
		raw := ""
		if req.Config != nil {
			raw = *req.Config
		} else if hasExisting && existing.RotatorType == typ && existing.ConfigSecret == "" {
			raw = existing.Config
		}
		c, err := decodeRotatorConfig(raw)
		if err != nil {
			return secretRotationResult{}, inputErr(err)
		}
		if err := c.validate(typ, true); err != nil {
			return secretRotationResult{}, inputErr(err)
		}
		b, _ := json.Marshal(c)
		cfg.Config = string(b)
		if typ == store.RotatorWebhook {
			if hasExisting && existing.RotatorType == store.RotatorWebhook && existing.ConfigSecret == "" && len(existing.SigningKeySealed) > 0 {
				cfg.ClearSigningKey = false // keep it
			} else {
				secret, sealed, err := s.newSigningSecret(account)
				if err != nil {
					return secretRotationResult{}, err
				}
				signingSecret, cfg.SigningKeySealed = secret, sealed
			}
		}
	}

	base := time.Now().UTC()
	if hasExisting && existing.LastRotatedAt != nil {
		base = *existing.LastRotatedAt
	}
	next, _ := sch.nextWindow(base)
	cfg.NextRotationDate = &next
	meta, err = s.store.ConfigureSecretRotation(ctx, cfg)
	if err != nil {
		return secretRotationResult{}, err
	}
	res := secretRotationResult{Meta: meta, Builtin: typ != "", SigningSecret: signingSecret}
	if req.RotateImmediately && typ != "" {
		token, err := s.startRotation(ctx, account, meta.Name, "immediate", strings.TrimSpace(req.Token), true)
		if err != nil {
			return res, err
		}
		res.Token = token
	}
	return res, nil
}

// regenerateSigningSecret replaces an inline webhook rotator's signing
// secret and returns the new one.
func (s *Server) regenerateSigningSecret(ctx context.Context, secretID string) (string, error) {
	meta, err := s.store.DescribeSecret(ctx, secretID)
	if err != nil {
		return "", err
	}
	rot, err := s.store.GetSecretRotation(ctx, meta.Name)
	if err != nil || rot.RotatorType != store.RotatorWebhook || rot.ConfigSecret != "" {
		return "", rotationInputError{"the secret has no inline webhook rotator"}
	}
	secret, sealed, err := s.newSigningSecret(s.callerAccount(ctx))
	if err != nil {
		return "", err
	}
	cfg := store.SecretRotationConfig{
		SecretID: meta.Name, LambdaARN: meta.RotationLambdaARN, AfterDays: meta.RotationDays, ScheduleExpression: rot.ScheduleExpression,
		Duration: rot.Duration, NextRotationDate: meta.NextRotationDate, RotatorType: rot.RotatorType, Config: rot.Config, SigningKeySealed: sealed,
	}
	if !meta.RotationEnabled {
		return "", rotationInputError{"turn rotation on first"}
	}
	if _, err := s.store.ConfigureSecretRotation(ctx, cfg); err != nil {
		return "", err
	}
	return secret, nil
}

// ---- AWS RotateSecret ---------------------------------------------------------

func (s *Server) handleRotateSecret(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.RotateSecret"
	var req rotateSecretRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	in := secretRotationRequest{SecretID: req.SecretID, LambdaARN: req.RotationLambdaARN, AfterDays: req.AutomaticallyAfterDays, Token: req.ClientRequestToken, RotateImmediately: true}
	if req.RotationRules != nil {
		if req.RotationRules.AutomaticallyAfterDays != 0 {
			in.AfterDays = req.RotationRules.AutomaticallyAfterDays
		}
		in.ScheduleExpression, in.Duration = req.RotationRules.ScheduleExpression, req.RotationRules.Duration
	}
	if req.RotateImmediately != nil {
		in.RotateImmediately = *req.RotateImmediately
	}
	if len(req.ClientRequestToken) > 64 {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", "ClientRequestToken must be at most 64 characters")
		return
	}
	meta, err := s.store.DescribeSecret(r.Context(), req.SecretID)
	if err != nil {
		secretError(w, err)
		return
	}
	if err := s.authorizeSecretAction(r.Context(), r, meta, "secretsmanager:RotateSecret"); err != nil {
		secretError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: classifySecretError(err), AuditOrigin: s.auditOrigin(r)})
		return
	}
	ctx := r.Context()
	if c, ok := awsCallerFromContext(ctx); ok {
		ctx = store.WithActor(ctx, c.Username)
	}
	in.checkApproval = func() error {
		if s.awsWriteNeedsApproval(ctx, meta.Name) {
			return errApprovalRequiredForRotation
		}
		return nil
	}
	res, err := s.configureRotation(ctx, in)
	if err != nil {
		errType := s.writeAWSRotationError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: meta.KMSKeyID, Result: "error", ErrorType: errType, AuditOrigin: s.auditOrigin(r)})
		return
	}
	writeJSON(w, http.StatusOK, rotateSecretResponse{ARN: res.Meta.ARN, Name: res.Meta.Name, VersionID: res.Token})
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: res.Meta.KMSKeyID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
}

var errApprovalRequiredForRotation = errors.New("approval required")

func (s *Server) writeAWSRotationError(w http.ResponseWriter, err error) string {
	var ie rotationInputError
	switch {
	case errors.As(err, &ie):
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", ie.msg)
		return "InvalidParameterException"
	case errors.Is(err, errRotationInProgress):
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidRequestException", "A previous rotation isn't complete. That rotation will be reattempted.")
		return "InvalidRequestException"
	case errors.Is(err, errApprovalRequiredForRotation):
		writeAWSJSONError(w, http.StatusBadRequest, "AccessDeniedException", awsApprovalRequiredMessage)
		return "AccessDeniedException"
	}
	secretError(w, err)
	return classifySecretError(err)
}

// ---- native API ---------------------------------------------------------------

type nativeRotatorJSON struct {
	Type             string          `json:"type"`
	Config           json.RawMessage `json:"config,omitempty"`
	ConfigSecret     string          `json:"configSecret,omitempty"`
	HasSigningSecret bool            `json:"hasSigningSecret,omitempty"`
}

type nativeRotationScheduleJSON struct {
	AfterDays  int    `json:"afterDays,omitempty"`
	Expression string `json:"expression,omitempty"`
	Duration   string `json:"duration,omitempty"`
}

type nativeRotationEventJSON struct {
	Token      string `json:"versionId"`
	Rotator    string `json:"rotator"`
	Trigger    string `json:"trigger"`
	Status     string `json:"status"`
	Step       string `json:"step"`
	Error      string `json:"error,omitempty"`
	StartedAt  string `json:"startedAt"`
	FinishedAt string `json:"finishedAt"`
}

// nativeRotationStatus is GET /v1/secrets/rotation.
type nativeRotationStatus struct {
	Enabled bool `json:"enabled"`
	// Mode is "builtin" (a Citadel rotator runs), "lambda" (a Lambda ARN is
	// recorded but nothing runs: schedule only) or "none".
	Mode             string                     `json:"mode"`
	LambdaARN        string                     `json:"lambdaArn,omitempty"`
	Rotator          *nativeRotatorJSON         `json:"rotator,omitempty"`
	Schedule         nativeRotationScheduleJSON `json:"schedule"`
	NextRotationDate string                     `json:"nextRotationDate,omitempty"`
	WindowEnd        string                     `json:"windowEnd,omitempty"`
	LastRotatedDate  string                     `json:"lastRotatedDate,omitempty"`
	Status           string                     `json:"status"`
	LastStep         string                     `json:"lastStep,omitempty"`
	LastError        string                     `json:"lastError,omitempty"`
	Attempts         int                        `json:"attempts,omitempty"`
	NextAttemptAt    string                     `json:"nextAttemptAt,omitempty"`
	PendingVersionID string                     `json:"pendingVersionId,omitempty"`
	Due              bool                       `json:"due"`
	History          []nativeRotationEventJSON  `json:"history"`
}

func fmtTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func (s *Server) secretRotationStatus(ctx context.Context, name string) (nativeRotationStatus, error) {
	meta, err := s.store.DescribeSecret(ctx, name)
	if err != nil {
		return nativeRotationStatus{}, err
	}
	out := nativeRotationStatus{Enabled: meta.RotationEnabled, Mode: "none", LambdaARN: meta.RotationLambdaARN, History: []nativeRotationEventJSON{}}
	out.Schedule.AfterDays = meta.RotationDays
	out.PendingVersionID = store.PendingRotationToken(meta)
	rot, err := s.store.GetSecretRotation(ctx, meta.Name)
	switch {
	case err == nil:
		out.Schedule.Expression, out.Schedule.Duration = rot.ScheduleExpression, rot.Duration
		if rot.RotatorType != "" {
			out.Rotator = &nativeRotatorJSON{Type: rot.RotatorType, ConfigSecret: rot.ConfigSecret, HasSigningSecret: len(rot.SigningKeySealed) > 0}
			if rot.Config != "" {
				out.Rotator.Config = json.RawMessage(rot.Config)
			}
		}
		out.Status, out.LastStep, out.LastError, out.Attempts = rot.Status, rot.LastStep, rot.LastError, rot.Attempts
		out.LastRotatedDate = fmtTimePtr(rot.LastRotatedAt)
		out.NextAttemptAt = fmtTimePtr(rot.NextAttemptAt)
	case !errors.Is(err, store.ErrRotationNotConfigured):
		return nativeRotationStatus{}, err
	}
	switch {
	case out.Rotator != nil:
		out.Mode = "builtin"
	case meta.RotationEnabled:
		out.Mode = "lambda"
	}
	if meta.RotationEnabled && meta.NextRotationDate != nil {
		out.NextRotationDate = fmtTimePtr(meta.NextRotationDate)
		if sch, err := parseRotationSchedule(meta.RotationDays, out.Schedule.Expression, out.Schedule.Duration); err == nil {
			out.WindowEnd = sch.windowEnd(*meta.NextRotationDate).Format(time.RFC3339)
		}
		out.Due = meta.DeletedDate == nil && !meta.NextRotationDate.After(time.Now())
	}
	hist, err := s.store.ListSecretRotationHistory(ctx, meta.Name, 20)
	if err != nil {
		return nativeRotationStatus{}, err
	}
	for _, e := range hist {
		out.History = append(out.History, nativeRotationEventJSON{
			Token: e.Token, Rotator: e.RotatorType, Trigger: e.Trigger, Status: e.Status, Step: e.Step, Error: e.Error,
			StartedAt: e.StartedAt.UTC().Format(time.RFC3339), FinishedAt: e.FinishedAt.UTC().Format(time.RFC3339),
		})
	}
	return out, nil
}

// writeRotationFailure reports a native rotation error.
func writeRotationFailure(w http.ResponseWriter, err error) {
	var ie rotationInputError
	switch {
	case errors.As(err, &ie):
		writeNativeError(w, http.StatusBadRequest, "invalid_request", ie.msg)
	case errors.Is(err, errRotationInProgress):
		writeNativeError(w, http.StatusConflict, "rotation_in_progress", errRotationInProgress.Error())
	case errors.Is(err, errNoBuiltinRotator):
		writeNativeError(w, http.StatusConflict, "no_rotator", "set up a built-in rotator first")
	case errors.Is(err, sql.ErrNoRows), errors.Is(err, errItemNotFound):
		writeNativeError(w, http.StatusNotFound, "not_found", "item not found")
	default:
		writeSecretsFailure(w, http.StatusBadRequest, "rotation_failed", err)
	}
}

// GET /v1/secrets/rotation?project&env&path&key — viewer.
func (s *Server) handleV1GetRotation(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "viewer")
	if !ok {
		return
	}
	coord, err := coordFromQuery(r.URL.Query())
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	st, err := s.secretRotationStatus(ctx, coord.backingName())
	if err != nil {
		writeRotationFailure(w, err)
		return
	}
	writeNativeJSON(w, http.StatusOK, st)
}

type nativeRotatorRequest struct {
	Type         string          `json:"type"`
	Config       json.RawMessage `json:"config"`
	ConfigSecret string          `json:"configSecret"`
}

type nativeRotationRequest struct {
	Project            string                `json:"project"`
	Env                string                `json:"env"`
	Path               string                `json:"path"`
	Key                string                `json:"key"`
	LambdaARN          string                `json:"lambdaArn"`
	AfterDays          int                   `json:"afterDays"`
	ScheduleExpression string                `json:"scheduleExpression"`
	Duration           string                `json:"duration"`
	Rotator            *nativeRotatorRequest `json:"rotator"`
	RotateImmediately  bool                  `json:"rotateImmediately"`
}

// POST /v1/secrets/rotation — editor. Configures a built-in rotator
// (rotator) or records a Lambda schedule (lambdaArn).
func (s *Server) handleV1ConfigureRotation(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeRotationRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	coord, err := coordFromParts(req.Project, req.Env, req.Path, req.Key)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	in := secretRotationRequest{SecretID: coord.backingName(), LambdaARN: req.LambdaARN, AfterDays: req.AfterDays, ScheduleExpression: req.ScheduleExpression, Duration: req.Duration, RotateImmediately: req.RotateImmediately}
	switch {
	case req.Rotator != nil:
		if strings.TrimSpace(req.Rotator.Type) == "" {
			writeNativeError(w, http.StatusBadRequest, "invalid_request", "rotator.type is required")
			return
		}
		in.RotatorType, in.ConfigSecret = req.Rotator.Type, req.Rotator.ConfigSecret
		if strings.HasPrefix(strings.TrimSpace(req.LambdaARN), rotatorARNPrefix) || strings.TrimSpace(req.LambdaARN) == "" {
			in.LambdaARN = ""
		} else {
			writeNativeError(w, http.StatusBadRequest, "invalid_request", "use either rotator or a Lambda ARN")
			return
		}
		raw := ""
		if len(req.Rotator.Config) > 0 && string(req.Rotator.Config) != "null" {
			raw = string(req.Rotator.Config)
		}
		in.Config = &raw
	case strings.TrimSpace(req.LambdaARN) == "":
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "choose a rotator or enter a Lambda ARN")
		return
	}
	approvalDenied := false
	in.checkApproval = func() error {
		if !s.requireNoApproval(w, r, ctx, coord.Project, coord.Env, "citadel.ConfigureItemRotation") {
			approvalDenied = true
			return errApprovalRequiredForRotation
		}
		return nil
	}
	res, err := s.configureRotation(ctx, in)
	if err != nil {
		if approvalDenied {
			return // requireNoApproval answered and audited
		}
		s.recordAudit(ctx, store.AuditEvent{Action: "citadel.ConfigureItemRotation", Result: "error", ErrorType: "RotationConfigFailed", AuditOrigin: s.auditOrigin(r)})
		writeRotationFailure(w, err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.ConfigureItemRotation", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	out := map[string]any{"configured": true, "builtin": res.Builtin}
	if res.Token != "" {
		out["versionId"] = res.Token
	}
	if res.SigningSecret != "" {
		out["signingSecret"] = res.SigningSecret
	}
	writeNativeJSON(w, http.StatusOK, out)
}

type nativeItemRequest struct {
	Project string `json:"project"`
	Env     string `json:"env"`
	Path    string `json:"path"`
	Key     string `json:"key"`
}

// POST /v1/secrets/rotation/rotate — editor. Starts a rotation now; it runs
// in the background (poll GET /v1/secrets/rotation).
func (s *Server) handleV1RotateNow(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeItemRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	coord, err := coordFromParts(req.Project, req.Env, req.Path, req.Key)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if !s.requireNoApproval(w, r, ctx, coord.Project, coord.Env, "citadel.RotateItemNow") {
		return
	}
	meta, err := s.store.DescribeSecret(ctx, coord.backingName())
	if err != nil {
		writeRotationFailure(w, err)
		return
	}
	rot, err := s.store.GetSecretRotation(ctx, meta.Name)
	if err != nil || rot.RotatorType == "" || !meta.RotationEnabled {
		writeRotationFailure(w, errNoBuiltinRotator)
		return
	}
	if meta.DeletedDate != nil {
		writeRotationFailure(w, store.ErrSecretPendingDeletion)
		return
	}
	token, err := s.startRotation(ctx, s.callerAccount(ctx), meta.Name, "immediate", "", true)
	if err != nil {
		s.recordAudit(ctx, store.AuditEvent{Action: "citadel.RotateItemNow", Result: "error", ErrorType: "RotationNotStarted", AuditOrigin: s.auditOrigin(r)})
		writeRotationFailure(w, err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.RotateItemNow", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusAccepted, map[string]any{"started": true, "versionId": token})
}

// POST /v1/secrets/rotation/signing-secret — editor. Replaces an inline
// webhook rotator's signing secret; the new one is returned once.
func (s *Server) handleV1RegenerateSigningSecret(w http.ResponseWriter, r *http.Request) {
	_, ctx, ok := s.secretsSession(w, r, "editor")
	if !ok {
		return
	}
	var req nativeItemRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	coord, err := coordFromParts(req.Project, req.Env, req.Path, req.Key)
	if err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if !s.requireNoApproval(w, r, ctx, coord.Project, coord.Env, "citadel.RegenerateRotationSigningSecret") {
		return
	}
	secret, err := s.regenerateSigningSecret(ctx, coord.backingName())
	if err != nil {
		s.recordAudit(ctx, store.AuditEvent{Action: "citadel.RegenerateRotationSigningSecret", Result: "error", ErrorType: "RotationConfigFailed", AuditOrigin: s.auditOrigin(r)})
		writeRotationFailure(w, err)
		return
	}
	s.recordAudit(ctx, store.AuditEvent{Action: "citadel.RegenerateRotationSigningSecret", Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeNativeJSON(w, http.StatusOK, map[string]any{"signingSecret": secret})
}

// rotationSummaries returns the account's rotation states for list views; a
// failure only loses the indicator.
func (s *Server) rotationSummaries(ctx context.Context) map[string]store.SecretRotationSummary {
	m, err := s.store.ListSecretRotationSummaries(ctx)
	if err != nil {
		log.Printf("rotation summaries: %v", err)
		return nil
	}
	return m
}

// awsRotationRules is DescribeSecret's RotationRules.
type awsRotationRules struct {
	AutomaticallyAfterDays int    `json:"AutomaticallyAfterDays,omitempty"`
	Duration               string `json:"Duration,omitempty"`
	ScheduleExpression     string `json:"ScheduleExpression,omitempty"`
}

// awsRotationFields returns DescribeSecret's RotationRules and
// LastRotatedDate for meta.
func (s *Server) awsRotationFields(ctx context.Context, meta store.SecretMetadataRecord) (*awsRotationRules, *store.AWSTimestamp) {
	var rules *awsRotationRules
	if meta.RotationDays > 0 {
		rules = &awsRotationRules{AutomaticallyAfterDays: meta.RotationDays}
	}
	rot, err := s.store.GetSecretRotation(ctx, meta.Name)
	if err != nil {
		return rules, nil
	}
	if rot.ScheduleExpression != "" || rot.Duration != "" {
		if rules == nil {
			rules = &awsRotationRules{}
		}
		rules.ScheduleExpression, rules.Duration = rot.ScheduleExpression, rot.Duration
	}
	return rules, awsTimePtr(rot.LastRotatedAt)
}
