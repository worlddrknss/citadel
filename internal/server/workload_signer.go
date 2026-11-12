package server

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/worlddrknss/citadel/internal/jose"
	"github.com/worlddrknss/citadel/internal/store"
)

// Workload identity signing keys live in Citadel KMS (asymmetric
// SIGN_VERIFY keys in the deployment account). The issuer signs token
// digests with the current key; previous keys stay in the JWKS until their
// unpublishAt, so tokens signed before a rotation keep verifying.

const (
	defaultWorkloadAlg          = jose.ES256
	defaultWorkloadRotationDays = 90
	// workloadKeyOverlap is how long a retired key stays published: longer
	// than the longest token lifetime (1h) plus relying-party JWKS caching.
	workloadKeyOverlap = 24 * time.Hour
	signerCacheTTL     = 10 * time.Second
	// orphanKeyDeletionDays is the KMS deletion window for unused keys.
	orphanKeyDeletionDays = 7
)

// kmsSpecForAlg maps a JWS algorithm to the KMS key spec that signs it.
func kmsSpecForAlg(alg string) (string, bool) {
	switch alg {
	case jose.ES256:
		return store.KeySpecECCP256, true
	case jose.ES384:
		return store.KeySpecECCP384, true
	case jose.RS256, jose.PS256:
		return store.KeySpecRSA3072, true
	}
	return "", false
}

// deploymentCtx scopes store calls to the deployment account, where the
// issuer's KMS keys live.
func (s *Server) deploymentCtx(ctx context.Context) context.Context {
	_, acct := s.store.DeploymentIdentity()
	return store.WithCallerAccount(context.WithoutCancel(ctx), acct)
}

// kmsSigner is a jose.Signer backed by a Citadel KMS key: Sign receives the
// JWS digest and signs it with the KMS key material (MessageType DIGEST).
type kmsSigner struct {
	s        *Server
	kid      string
	alg      string
	kmsKeyID string
	pub      crypto.PublicKey
}

func (k *kmsSigner) Alg() string              { return k.alg }
func (k *kmsSigner) KeyID() string            { return k.kid }
func (k *kmsSigner) Public() crypto.PublicKey { return k.pub }

func (k *kmsSigner) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	key, err := k.s.store.ResolveByID(k.s.deploymentCtx(ctx), k.kmsKeyID)
	if err != nil {
		return nil, fmt.Errorf("resolve KMS key: %w", err)
	}
	if !key.Enabled {
		return nil, errors.New("KMS signing key is disabled")
	}
	if usage, _ := keyUsageAndSpecForMetadata(key); usage != store.KeyUsageSignVerify {
		return nil, errors.New("KMS key is not a signing key")
	}
	priv, _, err := parsePrivateKey(key.MasterKeyRaw)
	if err != nil {
		return nil, err
	}
	h, err := jose.HashFor(k.alg)
	if err != nil {
		return nil, err
	}
	var opts crypto.SignerOpts = h
	if k.alg == jose.PS256 {
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h}
	}
	return priv.Sign(rand.Reader, digest, opts)
}

// newKMSSigner builds the signer for a stored signing key.
func (s *Server) newKMSSigner(ctx context.Context, wk store.WorkloadSigningKey) (*kmsSigner, error) {
	key, err := s.store.ResolveByID(s.deploymentCtx(ctx), wk.KMSKeyID)
	if err != nil {
		return nil, fmt.Errorf("resolve KMS key %s: %w", wk.KMSKeyID, err)
	}
	var pub crypto.PublicKey
	if len(key.PublicKeyRaw) > 0 {
		pub, err = x509.ParsePKIXPublicKey(key.PublicKeyRaw)
	} else {
		_, pub, err = parsePrivateKey(key.MasterKeyRaw)
	}
	if err != nil {
		return nil, fmt.Errorf("KMS key %s public key: %w", wk.KMSKeyID, err)
	}
	if err := jose.CheckKey(wk.Algorithm, pub); err != nil {
		return nil, err
	}
	return &kmsSigner{s: s, kid: wk.KID, alg: wk.Algorithm, kmsKeyID: wk.KMSKeyID, pub: pub}, nil
}

// kmsSignerSet is the issuer's persistent workloadid.SignerSet: the current
// key and the retired keys still within their overlap window, read from the
// store (cached briefly so every replica sees rotations quickly).
type kmsSignerSet struct {
	s       *Server
	mu      sync.Mutex
	fetched time.Time
	current *kmsSigner
	all     []*kmsSigner
	signers map[string]*kmsSigner // kid -> signer
}

func (s *Server) workloadSigners() *kmsSignerSet {
	st := s.identity()
	st.rpMu.Lock()
	defer st.rpMu.Unlock()
	if st.signers == nil {
		st.signers = &kmsSignerSet{s: s, signers: map[string]*kmsSigner{}}
	}
	return st.signers
}

func (k *kmsSignerSet) invalidate() {
	k.mu.Lock()
	k.fetched = time.Time{}
	k.mu.Unlock()
}

func (k *kmsSignerSet) load(ctx context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.s.identity().now()
	if !k.fetched.IsZero() && now.Sub(k.fetched) < signerCacheTTL {
		return nil
	}
	keys, err := k.s.store.ListWorkloadSigningKeys(ctx)
	if err != nil {
		return err
	}
	k.current, k.all = nil, nil
	for _, wk := range keys {
		if !wk.RetiredAt.IsZero() && !now.Before(wk.UnpublishAt) {
			continue
		}
		sg, ok := k.signers[wk.KID]
		if !ok {
			if sg, err = k.s.newKMSSigner(ctx, wk); err != nil {
				slog.Error("workload identity: signing key unusable", "kid", wk.KID, "error", err)
				continue
			}
			k.signers[wk.KID] = sg
		}
		if wk.RetiredAt.IsZero() {
			k.current = sg
		}
		k.all = append(k.all, sg)
	}
	k.fetched = now
	return nil
}

// Current implements workloadid.SignerSet, creating the first key on
// first use.
func (k *kmsSignerSet) Current(ctx context.Context) (jose.Signer, error) {
	if err := k.load(ctx); err != nil {
		return nil, err
	}
	k.mu.Lock()
	cur := k.current
	k.mu.Unlock()
	if cur != nil {
		return cur, nil
	}
	if _, err := k.s.rotateWorkloadKey(ctx, ""); err != nil && !errors.Is(err, store.ErrWorkloadRotationConflict) {
		return nil, err
	}
	k.invalidate()
	if err := k.load(ctx); err != nil {
		return nil, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.current == nil {
		return nil, errors.New("no usable workload signing key")
	}
	return k.current, nil
}

// Published implements workloadid.SignerSet.
func (k *kmsSignerSet) Published(ctx context.Context) ([]jose.Signer, error) {
	if err := k.load(ctx); err != nil {
		return nil, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	out := make([]jose.Signer, 0, len(k.all))
	for _, sg := range k.all {
		out = append(out, sg)
	}
	return out, nil
}

// workloadIssuerSettings returns the settings with defaults applied.
func (s *Server) workloadIssuerSettings(ctx context.Context) store.WorkloadIssuerSettings {
	st, err := s.store.GetWorkloadIssuerSettings(ctx)
	if err != nil {
		slog.Error("workload identity: load settings", "error", err)
	}
	if !jose.IsSupported(st.Algorithm) {
		st.Algorithm = defaultWorkloadAlg
	}
	if st.RotationDays < 7 || st.RotationDays > 365 {
		st.RotationDays = defaultWorkloadRotationDays
	}
	return st
}

// rotateWorkloadKey creates a KMS key with the configured algorithm and
// makes it current, retiring the current key (expected kid expectKID; ""
// when there is none). On a lost race the new KMS key is scheduled for
// deletion and ErrWorkloadRotationConflict is returned.
func (s *Server) rotateWorkloadKey(ctx context.Context, expectKID string) (store.WorkloadSigningKey, error) {
	settings := s.workloadIssuerSettings(ctx)
	spec, _ := kmsSpecForAlg(settings.Algorithm)
	dctx := s.deploymentCtx(ctx)
	key, err := s.store.CreateKey(dctx, "Citadel workload identity signing key ("+settings.Algorithm+")", store.KeyUsageSignVerify, spec)
	if err != nil {
		return store.WorkloadSigningKey{}, fmt.Errorf("create KMS signing key: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(key.PublicKeyRaw)
	if err != nil {
		return store.WorkloadSigningKey{}, fmt.Errorf("KMS signing key public key: %w", err)
	}
	kid, err := jose.Thumbprint(pub)
	if err != nil {
		return store.WorkloadSigningKey{}, err
	}
	now := s.identity().now().UTC().Truncate(time.Second)
	next := store.WorkloadSigningKey{KID: kid, KMSKeyID: key.ID, Algorithm: settings.Algorithm, ActivatedAt: now}
	if err := s.store.RotateWorkloadSigningKey(ctx, next, expectKID, now, now.Add(workloadKeyOverlap)); err != nil {
		if _, derr := s.store.ScheduleKeyDeletion(dctx, key.ID, orphanKeyDeletionDays); derr != nil {
			slog.Error("workload identity: schedule deletion of unused key", "kmsKeyId", key.ID, "error", derr)
		}
		return store.WorkloadSigningKey{}, err
	}
	s.workloadSigners().invalidate()
	return next, nil
}

// currentWorkloadKey returns the current signing key record, if any.
func (s *Server) currentWorkloadKey(ctx context.Context) (store.WorkloadSigningKey, []store.WorkloadSigningKey, error) {
	keys, err := s.store.ListWorkloadSigningKeys(ctx)
	if err != nil {
		return store.WorkloadSigningKey{}, nil, err
	}
	for _, k := range keys {
		if k.RetiredAt.IsZero() {
			return k, keys, nil
		}
	}
	return store.WorkloadSigningKey{}, keys, nil
}

// workloadRotationJob rotates the current key when it is older than the
// rotation period and drops (and schedules KMS deletion of) keys past their
// publication window. Safe on every replica: rotation is conditional on the
// current key.
func (s *Server) workloadRotationJob(ctx context.Context) error {
	cur, _, err := s.currentWorkloadKey(ctx)
	if err != nil {
		return err
	}
	now := s.identity().now().UTC()
	if cur.KID != "" {
		days := s.workloadIssuerSettings(ctx).RotationDays
		if !now.Before(cur.ActivatedAt.Add(time.Duration(days) * 24 * time.Hour)) {
			next, err := s.rotateWorkloadKey(ctx, cur.KID)
			switch {
			case errors.Is(err, store.ErrWorkloadRotationConflict):
			case err != nil:
				return err
			default:
				s.recordAudit(s.deploymentCtx(ctx), store.AuditEvent{Action: "citadel.RotateWorkloadSigningKey", KeyID: next.KID, Result: "ok",
					AuditOrigin: store.AuditOrigin{Actor: "system:workload-key-rotation", ActorType: store.AuditActorSystem, Resource: next.KMSKeyID}})
			}
		}
	}
	gone, err := s.store.DeleteUnpublishedWorkloadSigningKeys(ctx, now)
	if err != nil {
		return err
	}
	for _, k := range gone {
		if _, err := s.store.ScheduleKeyDeletion(s.deploymentCtx(ctx), k.KMSKeyID, orphanKeyDeletionDays); err != nil {
			slog.Error("workload identity: schedule deletion of retired key", "kmsKeyId", k.KMSKeyID, "error", err)
		}
	}
	if len(gone) > 0 {
		s.workloadSigners().invalidate()
	}
	return nil
}
