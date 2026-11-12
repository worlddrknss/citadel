package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
)

// KMS key lifecycle: versioned key material and rotation, tags, usage counts,
// scheduled deletion and wrapping-key re-wrap.

const (
	RotationKindAutomatic = "automatic"
	RotationKindOnDemand  = "on-demand"

	// Automatic rotation periods AWS accepts, in days.
	MinRotationPeriodDays     = 90
	MaxRotationPeriodDays     = 2560
	DefaultRotationPeriodDays = 365
	// MaxOnDemandRotations is AWS's lifetime limit of on-demand rotations
	// per key.
	MaxOnDemandRotations = 10

	OriginAWSKMS   = "AWS_KMS"
	OriginExternal = "EXTERNAL"

	// Tag limits, as AWS KMS enforces them.
	MaxKeyTags        = 50
	MaxTagKeyLength   = 128
	MaxTagValueLength = 256
)

var (
	// ErrRotationUnsupported: rotation applies to symmetric keys only.
	ErrRotationUnsupported = errors.New("key rotation is supported for symmetric encryption keys only")
	// ErrRotationNotDue: an automatic rotation found the key no longer due
	// (another replica rotated it, or the schedule changed).
	ErrRotationNotDue = errors.New("key is not due for rotation")
	// ErrRotationLimit: the on-demand rotation limit was reached.
	ErrRotationLimit = errors.New("on-demand rotation limit reached for this key")
	// ErrInvalidRotationPeriod: period outside MinRotationPeriodDays..MaxRotationPeriodDays.
	ErrInvalidRotationPeriod = errors.New("rotation period must be between 90 and 2560 days")
	// ErrKeyNotUsable: the key is disabled or pending deletion.
	ErrKeyNotUsable = errors.New("key is disabled or pending deletion")
	// ErrInvalidTags wraps every tag validation failure; the wrapped message
	// is safe to show to clients.
	ErrInvalidTags = errors.New("invalid tags")
)

// KeyMaterial is one rotated version of a symmetric key's material.
type KeyMaterial struct {
	ID        string
	Raw       []byte
	Kind      string // RotationKindAutomatic or RotationKindOnDemand
	CreatedAt time.Time
}

// KeyRotation is one entry in a key's rotation history.
type KeyRotation struct {
	KeyID      string
	MaterialID string
	Kind       string
	RotatedAt  time.Time
}

// KeyRef names a key and the account owning it. Background jobs work across
// accounts and use it to scope each operation.
type KeyRef struct {
	KeyID     string
	AccountID string
}

// KMSTag is one key tag.
type KMSTag struct {
	Key   string
	Value string
}

// KeyUsageCounts counts the resources that reference a key.
type KeyUsageCounts struct {
	Secrets    int
	Parameters int
}

// RewrapReport summarises a wrapping-key re-wrap pass.
type RewrapReport struct {
	Scanned   int
	Rewrapped int
	Failed    int
	// Rewrapped counts by kind of secret.
	KeyMaterial       int // KMS key material (original and rotated versions)
	AccessKeySecrets  int // IAM access-key secrets
	STSSessionSecrets int // STS temporary-credential secrets
	ACMEKeys          int // ACME account and certificate private keys
	ServiceKeys       int // the deployment root secret derived keys come from
}

// KMSLifecycleStore is implemented by every backend. Methods taking a keyID
// are scoped to the caller account on ctx; the List*Due/Expired methods are
// deliberately account-wide (they feed the background job, which then acts
// per key under that key's account).
type KMSLifecycleStore interface {
	// SetKeyRotation turns automatic rotation on (scheduling the next
	// rotation periodDays from now) or off.
	SetKeyRotation(ctx context.Context, keyID string, enabled bool, periodDays int) (KMSKey, error)
	// RotateKeyMaterial adds a new material version and makes it current.
	// kind is RotationKindAutomatic (only when the key is due; reschedules)
	// or RotationKindOnDemand (limited to MaxOnDemandRotations).
	RotateKeyMaterial(ctx context.Context, keyID, kind string, now time.Time) (KeyRotation, error)
	ListKeyRotations(ctx context.Context, keyID string) ([]KeyRotation, error)
	ListKeysDueForRotation(ctx context.Context, now time.Time) ([]KeyRef, error)

	ListKeysPendingDeletion(ctx context.Context, now time.Time) ([]KeyRef, error)
	// DestroyKey destroys every version of a key's material and leaves a
	// tombstone: the key disappears from every read, and its aliases, grants,
	// policies, tags and rotation history are removed. Managed keys are
	// refused with ErrImmutableManagedKey.
	DestroyKey(ctx context.Context, keyID string) error

	TagKey(ctx context.Context, keyID string, tags []KMSTag) error
	UntagKey(ctx context.Context, keyID string, tagKeys []string) error
	ListKeyTags(ctx context.Context, keyID string) ([]KMSTag, error)

	CountKeyUsage(ctx context.Context, key KMSKey) (KeyUsageCounts, error)

	// FindGrant looks a grant up by ID or token within the caller account.
	FindGrant(ctx context.Context, grantID, grantToken string) (KMSGrant, error)

	// RewrapAll re-wraps every stored secret that is not yet wrapped with the
	// current wrapping key. Backends without wrapped state report zero.
	RewrapAll(ctx context.Context) (RewrapReport, error)
}

// IsSymmetric reports whether the key is a symmetric (AES-256-GCM) key.
func (k KMSKey) IsSymmetric() bool {
	usage := NormalizeKeyUsage(k.KeyUsage)
	spec := strings.ToUpper(strings.TrimSpace(k.KeySpec))
	return usage == KeyUsageEncryptDecrypt && (spec == "" || spec == KeySpecSymmetricDefault)
}

// material returns the raw material for a version ("" is the original).
func (k KMSKey) material(id string) ([]byte, bool) {
	if id == "" {
		return k.MasterKeyRaw, len(k.MasterKeyRaw) > 0
	}
	for _, m := range k.Materials {
		if m.ID == id {
			return m.Raw, true
		}
	}
	return nil, false
}

// EncryptBlob seals plaintext under the key's current material and returns a
// framed blob naming the key (and the material version, once rotated).
func (k KMSKey) EncryptBlob(plaintext, aad []byte) ([]byte, error) {
	raw, ok := k.material(k.CurrentMaterialID)
	if !ok {
		return nil, errors.New("current key material unavailable")
	}
	return cryptoutil.EncryptBlobWithMaterial(raw, k.ID, k.CurrentMaterialID, plaintext, aad)
}

// DecryptBlob opens a blob produced by EncryptBlob, by any earlier Citadel
// (v1 framing), or a headerless legacy blob. The material version is taken
// from the blob, so ciphertext sealed before any rotation still opens.
func (k KMSKey) DecryptBlob(blob, aad []byte) ([]byte, error) {
	p := cryptoutil.ParseCipherBlob(blob)
	if p.Header {
		if p.KeyID == k.ID {
			if raw, ok := k.material(p.MaterialID); ok {
				if out, err := cryptoutil.GCMOpen(raw, p.Sealed, aad); err == nil {
					return out, nil
				}
			}
		}
	}
	// No header, a header for another key, or a header that was really the
	// first bytes of a legacy blob's random nonce: open the whole blob with
	// the original material.
	if len(k.MasterKeyRaw) == 0 {
		return nil, errors.New("decrypt failed")
	}
	out, err := cryptoutil.GCMOpen(k.MasterKeyRaw, blob, aad)
	if err != nil {
		return nil, errors.New("decrypt failed")
	}
	return out, nil
}

// NormalizeTags validates tags for TagKey: non-empty keys within AWS length
// limits, no aws: prefix, no duplicates.
func NormalizeTags(tags []KMSTag) ([]KMSTag, error) {
	if len(tags) == 0 {
		return nil, fmt.Errorf("%w: at least one tag is required", ErrInvalidTags)
	}
	if len(tags) > MaxKeyTags {
		return nil, fmt.Errorf("%w: at most 50 tags per key", ErrInvalidTags)
	}
	seen := map[string]bool{}
	out := make([]KMSTag, 0, len(tags))
	for _, t := range tags {
		key := strings.TrimSpace(t.Key)
		if key == "" || len(key) > MaxTagKeyLength {
			return nil, fmt.Errorf("%w: tag keys must be 1-128 characters", ErrInvalidTags)
		}
		if len(t.Value) > MaxTagValueLength {
			return nil, fmt.Errorf("%w: tag values must be at most 256 characters", ErrInvalidTags)
		}
		if strings.HasPrefix(strings.ToLower(key), "aws:") {
			return nil, fmt.Errorf("%w: the aws: tag prefix is reserved", ErrInvalidTags)
		}
		if seen[key] {
			return nil, fmt.Errorf("%w: duplicate tag key", ErrInvalidTags)
		}
		seen[key] = true
		out = append(out, KMSTag{Key: key, Value: t.Value})
	}
	return out, nil
}
