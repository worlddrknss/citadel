package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// Built-in secret rotation.
//
// AWS rotates a secret by invoking a Lambda function four times, once per
// step: createSecret (store a new value as AWSPENDING), setSecret (apply it
// to the system that uses it), testSecret (check it works) and finishSecret
// (move AWSCURRENT to it; the old value becomes AWSPREVIOUS). Citadel can't
// run Lambda functions, so it ships rotators that implement the same four
// steps in-process: random, postgresql and webhook (rotators.go).
//
// A secret selects a rotator through RotationLambdaARN values of the form
//
//	arn:citadel:rotator:<region>:<account>:<type>[/<config-id>]
//
// where <config-id> names a secret in the same account whose JSON value is
// the rotator's configuration, or through the native API, which stores the
// configuration with the secret. A real Lambda ARN is still accepted and
// recorded, but nothing runs for it ("schedule only").
//
// The rotation job (every minute, on every replica) lists due rotations and
// runs each under a lease in the store, so two replicas never rotate the
// same secret at once. A failed attempt keeps its AWSPENDING version (as AWS
// does) and is retried with backoff using the same token, so a rotator that
// already changed a database password never loses it; after
// rotationMaxAttempts the rotation is marked failed and reattempted at the
// next window. Every step is audited.

const (
	rotatorARNPrefix    = "arn:citadel:rotator:"
	rotationActor       = "system:rotation"
	rotationLease       = 5 * time.Minute
	rotationTimeout     = 3 * time.Minute
	rotationJobInterval = time.Minute
	rotationMaxAttempts = 5
	rotationBatch       = 50
	rotationErrorMax    = 500
)

var rotationSteps = []string{"createSecret", "setSecret", "testSecret", "finishSecret"}

var (
	errRotationInProgress = errors.New("a previous rotation isn't complete; it is reattempted automatically")
	errNoBuiltinRotator   = errors.New("this secret has no built-in rotator")
)

// rotationRuntime holds test hooks for rotation. The zero value is ready.
type rotationRuntime struct {
	// webhookClient replaces the webhook rotator's HTTP client (tests).
	webhookClient *http.Client
	// allowLoopback lets the postgresql rotator reach loopback addresses
	// (tests against a local database).
	allowLoopback bool
	// done, when set, receives the secret name after every rotation run
	// (tests).
	done chan string
}

// rotatorConfig is a rotator's configuration: inline (native API, without
// signingSecret) or the JSON value of a config secret.
type rotatorConfig struct {
	// Password generation (random, postgresql, and webhook values the
	// webhook doesn't supply), with GetRandomPassword's options.
	Length                  *int64 `json:"length,omitempty"`
	ExcludeCharacters       string `json:"excludeCharacters,omitempty"`
	ExcludeNumbers          bool   `json:"excludeNumbers,omitempty"`
	ExcludePunctuation      bool   `json:"excludePunctuation,omitempty"`
	ExcludeUppercase        bool   `json:"excludeUppercase,omitempty"`
	ExcludeLowercase        bool   `json:"excludeLowercase,omitempty"`
	IncludeSpace            bool   `json:"includeSpace,omitempty"`
	RequireEachIncludedType *bool  `json:"requireEachIncludedType,omitempty"`
	// JSONKey (random) rotates one string field of a JSON object secret
	// instead of the whole value.
	JSONKey string `json:"jsonKey,omitempty"`
	// Strategy (postgresql): "single-user" or "alternating-users"; empty
	// picks alternating-users when an admin secret is known.
	Strategy string `json:"strategy,omitempty"`
	// AdminSecretARN (postgresql, alternating users): the secret whose
	// credentials create and alter the users; the secret's own "masterarn"
	// field is used when this is empty, as in AWS's templates.
	AdminSecretARN string `json:"adminSecretArn,omitempty"`
	// URL (webhook): the https endpoint called for each step.
	URL string `json:"url,omitempty"`
	// SigningSecret (webhook, config secrets only): the HMAC key.
	SigningSecret string `json:"signingSecret,omitempty"`
}

func (c rotatorConfig) passwordRequest() getRandomPasswordRequest {
	return getRandomPasswordRequest{
		PasswordLength: c.Length, ExcludeCharacters: c.ExcludeCharacters, ExcludeNumbers: c.ExcludeNumbers,
		ExcludePunctuation: c.ExcludePunctuation, ExcludeUppercase: c.ExcludeUppercase, ExcludeLowercase: c.ExcludeLowercase,
		IncludeSpace: c.IncludeSpace, RequireEachIncludedType: c.RequireEachIncludedType,
	}
}

// decodeRotatorConfig strictly decodes a configuration ("" is empty).
func decodeRotatorConfig(raw string) (rotatorConfig, error) {
	var c rotatorConfig
	if strings.TrimSpace(raw) == "" {
		return c, nil
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, errors.New("rotator configuration is not valid: " + jsonErrorMessage(err))
	}
	return c, nil
}

func jsonErrorMessage(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, "json: "); i >= 0 {
		msg = msg[i+len("json: "):]
	}
	return msg
}

// validate checks the configuration for rotator typ. inline configurations
// may not carry a signing secret (Citadel generates and seals one).
func (c rotatorConfig) validate(typ string, inline bool) error {
	if _, err := generatePassword(c.passwordRequest()); err != nil {
		return errors.New("rotator configuration: " + err.Error())
	}
	if inline && c.SigningSecret != "" {
		return errors.New("rotator configuration: signingSecret is generated by Citadel; leave it out")
	}
	switch typ {
	case store.RotatorRandom:
		if c.Strategy != "" || c.AdminSecretARN != "" || c.URL != "" || c.SigningSecret != "" {
			return errors.New("rotator configuration: the random rotator takes password options and jsonKey only")
		}
		if len(c.JSONKey) > 256 {
			return errors.New("rotator configuration: jsonKey must be at most 256 characters")
		}
	case store.RotatorPostgreSQL:
		if c.URL != "" || c.SigningSecret != "" || c.JSONKey != "" {
			return errors.New("rotator configuration: the postgresql rotator takes password options, strategy and adminSecretArn only")
		}
		switch c.Strategy {
		case "", pgSingleUser, pgAlternatingUsers:
		default:
			return errors.New("rotator configuration: strategy must be single-user or alternating-users")
		}
		if len(c.AdminSecretARN) > 2048 {
			return errors.New("rotator configuration: adminSecretArn is too long")
		}
	case store.RotatorWebhook:
		if c.Strategy != "" || c.AdminSecretARN != "" || c.JSONKey != "" {
			return errors.New("rotator configuration: the webhook rotator takes url and password options only")
		}
		if err := validateStreamURL(c.URL); err != nil {
			return errors.New("rotator configuration: " + err.Error())
		}
		if !inline && len(c.SigningSecret) < 32 {
			return errors.New("rotator configuration: signingSecret must be at least 32 characters")
		}
	default:
		return fmt.Errorf("unknown rotator type %q", typ)
	}
	return nil
}

// rotatorARN is a parsed arn:citadel:rotator ARN.
type rotatorARN struct {
	Type     string
	ConfigID string
}

// parseRotatorARN parses arn:citadel:rotator:<region>:<account>:<type>[/<config-id>].
// The region and account must be the deployment region and the caller's
// account; ok is false for any other ARN (a Lambda ARN).
func parseRotatorARN(raw, region, account string) (rotatorARN, bool, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, rotatorARNPrefix) {
		return rotatorARN{}, false, nil
	}
	parts := strings.SplitN(strings.TrimPrefix(raw, rotatorARNPrefix), ":", 3)
	if len(parts) != 3 {
		return rotatorARN{}, true, errors.New("RotationLambdaARN must be arn:citadel:rotator:<region>:<account>:<type>[/<config-id>]")
	}
	if parts[0] != region {
		return rotatorARN{}, true, fmt.Errorf("RotationLambdaARN region must be %s", region)
	}
	if parts[1] != account {
		return rotatorARN{}, true, errors.New("RotationLambdaARN must name the caller's account")
	}
	typ, cfg, _ := strings.Cut(parts[2], "/")
	switch typ {
	case store.RotatorRandom, store.RotatorPostgreSQL, store.RotatorWebhook:
	default:
		return rotatorARN{}, true, errors.New("RotationLambdaARN rotator type must be random, postgresql or webhook")
	}
	if strings.Contains(parts[2], "/") && strings.TrimSpace(cfg) == "" {
		return rotatorARN{}, true, errors.New("RotationLambdaARN config-id must not be empty")
	}
	if len(cfg) > 512 {
		return rotatorARN{}, true, errors.New("RotationLambdaARN config-id is too long")
	}
	return rotatorARN{Type: typ, ConfigID: cfg}, true, nil
}

func buildRotatorARN(region, account, typ, configID string) string {
	a := rotatorARNPrefix + region + ":" + account + ":" + typ
	if configID != "" {
		a += "/" + configID
	}
	return a
}

// ---- signing secrets --------------------------------------------------------

func (s *Server) rotationSealKey() ([]byte, error) {
	switch {
	case len(s.deploymentSecret()) > 0:
		return cryptoutil.DeriveRotationSigningKeySealKey(s.deploymentSecret()), nil
	case len(s.cfg.AuditHMACKey) > 0:
		return cryptoutil.DeriveRotationSigningKeySealKey(s.cfg.AuditHMACKey), nil
	}
	return nil, errors.New("no key is configured to seal the webhook signing secret")
}

func rotationSigningAAD(accountID string) []byte {
	return []byte("citadel/rotation-signing-key/v1|" + accountID)
}

// newSigningSecret returns a fresh webhook signing secret and its sealed form.
func (s *Server) newSigningSecret(accountID string) (string, []byte, error) {
	key, err := s.rotationSealKey()
	if err != nil {
		return "", nil, err
	}
	secret := "whsec_" + cryptoutil.RandomHex(32)
	sealed, err := cryptoutil.GCMSeal(key, []byte(secret), rotationSigningAAD(accountID))
	if err != nil {
		return "", nil, err
	}
	return secret, sealed, nil
}

func (s *Server) openSigningSecret(accountID string, sealed []byte) (string, error) {
	key, err := s.rotationSealKey()
	if err != nil {
		return "", err
	}
	pt, err := cryptoutil.GCMOpen(key, sealed, rotationSigningAAD(accountID))
	if err != nil {
		return "", errors.New("the webhook signing secret could not be decrypted")
	}
	return string(pt), nil
}

// ---- running a rotation -------------------------------------------------------

// rotationRun is one rotation of one secret: the context its steps share.
type rotationRun struct {
	s          *Server
	ctx        context.Context
	account    string
	name       string
	arn        string
	token      string
	typ        string
	cfg        rotatorConfig
	signingKey string
}

func (r *rotationRun) value(stage, versionID string) (store.SecretValueRecord, error) {
	return r.s.store.GetSecretValue(r.ctx, r.name, versionID, stage)
}

func (r *rotationRun) current() (store.SecretValueRecord, error) {
	return r.value(store.CurrentVersionStage, "")
}

// pending returns the AWSPENDING version for the run's token, if any.
func (r *rotationRun) pending() (store.SecretValueRecord, bool, error) {
	v, err := r.value("", r.token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return v, false, nil
		}
		return v, false, err
	}
	return v, store.ContainsString(v.VersionStages, store.PendingVersionStage), nil
}

func (r *rotationRun) putPending(value string) error {
	_, err := r.s.store.PutPendingSecretVersion(r.ctx, r.name, r.token, value, "")
	return err
}

// finish is the label move every rotator's finishSecret ends with.
func (r *rotationRun) finish() error {
	_, err := r.s.store.FinishSecretRotation(r.ctx, r.name, r.token)
	return err
}

// rotationContext scopes ctx to the secret's account with the rotation
// actor, so new versions are stamped as written by rotation.
func rotationContext(ctx context.Context, account string) context.Context {
	return store.WithActor(store.WithCallerAccount(ctx, account), rotationActor)
}

func (s *Server) rotationAudit(ctx context.Context, name, action, result, errType string) {
	s.recordAudit(ctx, store.AuditEvent{Action: action, Result: result, ErrorType: errType, AuditOrigin: store.AuditOrigin{
		Actor: rotationActor, ActorType: store.AuditActorSystem, Resource: name,
	}})
}

// rotationJob is the s.jobs entry point: it runs every due rotation.
func (s *Server) rotationJob(ctx context.Context) error {
	due, err := s.store.ListDueSecretRotations(ctx, time.Now().UTC(), rotationBatch)
	if err != nil {
		return err
	}
	for _, d := range due {
		if ctx.Err() != nil {
			return nil
		}
		rctx, cancel := context.WithTimeout(ctx, rotationTimeout)
		if _, err := s.startRotation(rctx, d.AccountID, d.SecretName, "schedule", "", false); err != nil && !errors.Is(err, errRotationInProgress) {
			log.Printf("secret rotation: a due rotation could not start: %v", err)
		}
		cancel()
	}
	return nil
}

// startRotation claims the secret's rotation lease and runs the rotation,
// in the background when async (returning once the lease is held). It
// returns the token (version ID) the rotation uses.
func (s *Server) startRotation(ctx context.Context, account, name, trigger, token string, async bool) (string, error) {
	ctx = rotationContext(ctx, account)
	owner := cryptoutil.RandomHex(12)
	ok, err := s.store.ClaimSecretRotation(ctx, name, owner, rotationLease)
	if errors.Is(err, store.ErrRotationNotConfigured) {
		return "", errNoBuiltinRotator
	}
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errRotationInProgress
	}
	meta, err := s.store.DescribeSecret(ctx, name)
	if err != nil {
		_ = s.store.ReleaseSecretRotation(ctx, name, owner)
		return "", err
	}
	if trigger == "schedule" {
		// The due list may be stale: another replica can have finished this
		// rotation between our listing and our claim. Re-check under the
		// lease.
		rot, err := s.store.GetSecretRotation(ctx, name)
		if err != nil {
			_ = s.store.ReleaseSecretRotation(ctx, name, owner)
			return "", err
		}
		rot.LeaseUntil = nil
		if !store.RotationIsDue(meta, &rot, time.Now().UTC()) {
			_ = s.store.ReleaseSecretRotation(ctx, name, owner)
			return "", errRotationInProgress
		}
	}
	if p := store.PendingRotationToken(meta); p != "" {
		token = p // resume the unfinished rotation, as AWS does
	}
	if token == "" {
		token = cryptoutil.RandomHex(16)
	}
	if async {
		s.jobs.Go("secret-rotation", ctx, rotationTimeout, func(bg context.Context) {
			s.executeRotation(bg, account, meta, owner, trigger, token)
		})
		return token, nil
	}
	s.executeRotation(ctx, account, meta, owner, trigger, token)
	return token, nil
}

// executeRotation runs the four steps while holding the lease and records
// the outcome.
func (s *Server) executeRotation(ctx context.Context, account string, meta store.SecretMetadataRecord, owner, trigger, token string) {
	name := meta.Name
	defer func() {
		if s.rot.done != nil {
			select {
			case s.rot.done <- name:
			default:
			}
		}
	}()
	// Write-ahead audit (audit_writeahead.go): a scheduled run records its
	// attempt before any step changes the secret; a run started by a request
	// is already covered by that request's attempt. If the attempt can't be
	// written nothing runs and the lease is released for a later retry.
	ctx, aerr := s.ensureAudit(ctx, store.AuditEvent{Action: "secretsmanager.RotateSecret", AuditOrigin: store.AuditOrigin{
		Actor: rotationActor, ActorType: store.AuditActorSystem, Resource: name,
	}})
	if aerr != nil {
		log.Printf("secret rotation: skipped, the audit log is unavailable")
		_ = s.store.ReleaseSecretRotation(ctx, name, owner)
		return
	}
	started := time.Now().UTC()
	rot, err := s.store.GetSecretRotation(ctx, name)
	if err != nil {
		log.Printf("secret rotation: could not load the rotation configuration: %v", err)
		s.finishAudit(ctx, store.AuditResultError, "InternalError")
		return
	}
	if rot.Attempts > 0 && trigger == "schedule" {
		trigger = "retry"
	}
	attempts := rot.Attempts
	if rot.Status == store.RotationStatusFailed {
		attempts = 0
	}
	save := func(upd store.SecretRotationStateUpdate) {
		if err := s.store.SaveSecretRotationState(ctx, name, owner, upd); err != nil {
			log.Printf("secret rotation: could not save the rotation state: %v", err)
		}
	}
	save(store.SecretRotationStateUpdate{Status: store.RotationStatusRunning, LastStep: rotationSteps[0], Attempts: attempts, LastAttemptAt: started, NextAttemptAt: rot.NextAttemptAt, KeepLease: true})

	run := &rotationRun{s: s, ctx: ctx, account: account, name: name, arn: meta.ARN, token: token, typ: rot.RotatorType}
	step := "configuration"
	impl, err := s.loadRotator(run, rot)
	if err == nil {
		for _, step = range rotationSteps {
			err = impl.step(step, run)
			result, errType := "ok", ""
			if err != nil {
				result, errType = "error", "RotationStepFailed"
			}
			s.rotationAudit(ctx, name, "secretsmanager.RotationStep."+step, result, errType)
			if err != nil {
				break
			}
			if step != "finishSecret" {
				save(store.SecretRotationStateUpdate{Status: store.RotationStatusRunning, LastStep: step, Attempts: attempts, LastAttemptAt: started, KeepLease: true})
			}
		}
	}
	finished := time.Now().UTC()
	event := store.SecretRotationEvent{Token: token, RotatorType: rot.RotatorType, Trigger: trigger, Step: step, StartedAt: started, FinishedAt: finished, Actor: rotationActor}
	if err == nil {
		sch, perr := parseRotationSchedule(meta.RotationDays, rot.ScheduleExpression, rot.Duration)
		upd := store.SecretRotationStateUpdate{Status: store.RotationStatusSucceeded, LastStep: "finishSecret", LastAttemptAt: started, LastRotatedAt: &finished}
		if perr == nil {
			next, _ := sch.nextWindow(finished)
			upd.NextRotationDate = &next
		}
		save(upd)
		event.Status = store.RotationStatusSucceeded
		_ = s.store.AppendSecretRotationHistory(ctx, name, event)
		s.rotationAudit(ctx, name, "secretsmanager.RotationSucceeded", "ok", "")
		return
	}
	msg := rotationErrorText(err)
	attempts++
	upd := store.SecretRotationStateUpdate{Status: store.RotationStatusRetrying, LastStep: step, LastError: msg, Attempts: attempts, LastAttemptAt: started}
	if attempts < rotationMaxAttempts {
		next := finished.Add(rotationBackoff(attempts))
		upd.NextAttemptAt = &next
	} else {
		// Out of retries: reattempt (with the same AWSPENDING version) at
		// the next window.
		upd.Status = store.RotationStatusFailed
		if sch, perr := parseRotationSchedule(meta.RotationDays, rot.ScheduleExpression, rot.Duration); perr == nil {
			next, _ := sch.nextWindow(finished)
			upd.NextAttemptAt = &next
		} else {
			next := finished.Add(24 * time.Hour)
			upd.NextAttemptAt = &next
		}
	}
	save(upd)
	event.Status = store.RotationStatusFailed
	event.Error = msg
	_ = s.store.AppendSecretRotationHistory(ctx, name, event)
	s.rotationAudit(ctx, name, "secretsmanager.RotationFailed", "error", "RotationStepFailed")
}

// rotationBackoff is the delay before retry n (1-based): 1, 2, 4, 8... minutes,
// at most an hour.
func rotationBackoff(n int) time.Duration {
	d := time.Minute << uint(n-1)
	if d > time.Hour || d <= 0 {
		d = time.Hour
	}
	return d
}

// rotationErrorText is the message stored and shown for a failed step. It is
// the rotator's own error text (never a secret value), bounded in length.
func rotationErrorText(err error) string {
	msg := err.Error()
	if errors.Is(err, context.DeadlineExceeded) {
		msg = "the step timed out"
	}
	if len(msg) > rotationErrorMax {
		msg = msg[:rotationErrorMax] + "…"
	}
	return msg
}

// loadRotator resolves the rotator and its configuration for a run.
func (s *Server) loadRotator(run *rotationRun, rot store.SecretRotation) (rotator, error) {
	if rot.RotatorType == "" {
		return nil, errNoBuiltinRotator
	}
	raw := rot.Config
	inline := true
	if rot.ConfigSecret != "" {
		v, err := s.store.GetSecretValue(run.ctx, rot.ConfigSecret, "", store.CurrentVersionStage)
		if err != nil || v.SecretString == nil {
			return nil, fmt.Errorf("the configuration secret %q could not be read", rot.ConfigSecret)
		}
		raw, inline = *v.SecretString, false
	}
	cfg, err := decodeRotatorConfig(raw)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(rot.RotatorType, inline); err != nil {
		return nil, err
	}
	run.cfg = cfg
	switch rot.RotatorType {
	case store.RotatorRandom:
		return randomRotator{}, nil
	case store.RotatorPostgreSQL:
		return postgresRotator{}, nil
	case store.RotatorWebhook:
		if inline {
			if len(rot.SigningKeySealed) == 0 {
				return nil, errors.New("the webhook rotator has no signing secret")
			}
			key, err := s.openSigningSecret(run.account, rot.SigningKeySealed)
			if err != nil {
				return nil, err
			}
			run.signingKey = key
		} else {
			run.signingKey = cfg.SigningSecret
		}
		return webhookRotator{}, nil
	}
	return nil, fmt.Errorf("unknown rotator type %q", rot.RotatorType)
}
