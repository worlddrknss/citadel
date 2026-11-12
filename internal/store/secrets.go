package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
)

// AWSTimestamp marshals a time.Time as an AWS JSON 1.1 protocol epoch-seconds
// number (e.g. 1.50927752e9). AWS SDK clients (including External Secrets
// Operator) deserialize Secrets Manager timestamp fields as JSON numbers and
// reject the RFC3339 string that time.Time's default marshaler emits
// ("expected ... to be a JSON Number, got string instead").
type AWSTimestamp time.Time

const (
	CurrentVersionStage  = "AWSCURRENT"
	PreviousVersionStage = "AWSPREVIOUS"
)

type CreateSecretRequest struct {
	Name               string `json:"Name"`
	Description        string `json:"Description"`
	KMSKeyID           string `json:"KmsKeyId"`
	SecretString       string `json:"SecretString"`
	SecretBinary       string `json:"SecretBinary"`
	ClientRequestToken string `json:"ClientRequestToken"`
}

type PutSecretValueRequest struct {
	SecretID            string   `json:"SecretId"`
	ClientRequestToken  string   `json:"ClientRequestToken"`
	SecretString        string   `json:"SecretString"`
	SecretBinary        string   `json:"SecretBinary"`
	VersionStagesUnused []string `json:"VersionStages,omitempty"`
}

type UpdateSecretRequest struct {
	SecretID           string `json:"SecretId"`
	Description        string `json:"Description"`
	KMSKeyID           string `json:"KmsKeyId"`
	SecretString       string `json:"SecretString"`
	SecretBinary       string `json:"SecretBinary"`
	ClientRequestToken string `json:"ClientRequestToken"`
}

type SecretMetadataRecord struct {
	ARN               string
	Name              string
	Description       string
	KMSKeyID          string
	CurrentVersionID  string
	PreviousVersionID string
	VersionStages     map[string][]string
	CreatedAt         time.Time
	LastChangedDate   time.Time
	DeletedDate       *time.Time
	Tags              []SecretTag
	PolicyDocument    string
	RotationEnabled   bool
	RotationLambdaARN string
	RotationDays      int
	NextRotationDate  *time.Time
}

type SecretValueRecord struct {
	ARN           string
	Name          string
	VersionID     string
	SecretString  *string
	SecretBinary  string
	VersionStages []string
	CreatedAt     time.Time
	KMSKeyID      string
}

type SecretTag struct {
	Key   string
	Value string
}

type SecretVersionRow struct {
	VersionID           string
	EncryptedPayloadB64 string
	IsBinary            bool
	CreatedAt           time.Time
}

var (
	ErrSecretExists          = errors.New("secret already exists")
	ErrSecretPendingDeletion = errors.New("secret scheduled for deletion")
	ErrInvalidSecretVersion  = errors.New("invalid secret version")
)

func BuildSecretCiphertext(ctx context.Context, resolveByID func(context.Context, string) (KMSKey, error), resolveDefault func(context.Context) (KMSKey, error), kmsKeyID, secretString, secretBinary string) (string, string, bool, error) {
	var (
		key KMSKey
		err error
	)
	if strings.TrimSpace(kmsKeyID) != "" {
		key, err = resolveByID(ctx, strings.TrimSpace(kmsKeyID))
	} else {
		key, err = resolveDefault(ctx)
	}
	if err != nil {
		return "", "", false, err
	}
	var (
		raw      []byte
		isBinary bool
	)
	if secretBinary != "" {
		raw, err = base64.StdEncoding.DecodeString(secretBinary)
		if err != nil {
			return "", "", false, errors.New("SecretBinary must be base64")
		}
		isBinary = true
	} else {
		raw = []byte(secretString)
	}
	cipherBlob, err := cryptoutil.EncryptBlob(key.MasterKeyRaw, key.ID, raw, nil)
	if err != nil {
		return "", "", false, err
	}
	return key.ID, base64.StdEncoding.EncodeToString(cipherBlob), isBinary, nil
}

func BuildSecretValueRecord(ctx context.Context, resolveByID func(context.Context, string) (KMSKey, error), meta SecretMetadataRecord, version SecretVersionRow) (SecretValueRecord, error) {
	key, err := resolveByID(ctx, meta.KMSKeyID)
	if err != nil {
		return SecretValueRecord{}, err
	}
	encoded, err := base64.StdEncoding.DecodeString(version.EncryptedPayloadB64)
	if err != nil {
		return SecretValueRecord{}, err
	}
	_, rawBlob, err := cryptoutil.DecodeCipherBlob(encoded)
	if err != nil {
		return SecretValueRecord{}, err
	}
	raw, err := cryptoutil.DecryptBlob(key.MasterKeyRaw, rawBlob, nil)
	if err != nil {
		return SecretValueRecord{}, err
	}
	value := SecretValueRecord{
		ARN:           meta.ARN,
		Name:          meta.Name,
		VersionID:     version.VersionID,
		VersionStages: SecretStagesForVersion(meta, version.VersionID),
		CreatedAt:     version.CreatedAt,
		KMSKeyID:      meta.KMSKeyID,
	}
	if version.IsBinary {
		value.SecretBinary = base64.StdEncoding.EncodeToString(raw)
	} else {
		secretString := string(raw)
		value.SecretString = &secretString
	}
	return value, nil
}

func SecretStagesForVersion(meta SecretMetadataRecord, versionID string) []string {
	EnsureSecretStageMap(&meta)
	stages := append([]string(nil), meta.VersionStages[versionID]...)
	sort.Strings(stages)
	return stages
}

func ResolveSecretVersionID(meta SecretMetadataRecord, versionID, versionStage string) (string, error) {
	if versionID != "" {
		return versionID, nil
	}
	if versionStage == "" || versionStage == CurrentVersionStage {
		return meta.CurrentVersionID, nil
	}
	if versionStage == PreviousVersionStage && meta.PreviousVersionID != "" {
		return meta.PreviousVersionID, nil
	}
	EnsureSecretStageMap(&meta)
	for candidateVersionID, stages := range meta.VersionStages {
		if ContainsString(stages, versionStage) {
			return candidateVersionID, nil
		}
	}
	return "", ErrInvalidSecretVersion
}

func NormalizeSecretDeletion(forceDelete bool, recoveryWindowDays int) (time.Time, error) {
	if forceDelete {
		now := time.Now().UTC()
		return now, nil
	}
	if recoveryWindowDays == 0 {
		recoveryWindowDays = 30
	}
	if recoveryWindowDays < 7 || recoveryWindowDays > 30 {
		return time.Time{}, errors.New("RecoveryWindowInDays must be between 7 and 30")
	}
	return time.Now().UTC().Add(time.Duration(recoveryWindowDays) * 24 * time.Hour), nil
}

const PendingVersionStage = "AWSPENDING"

type SecretVersionListEntry struct {
	VersionID      string        `json:"VersionId"`
	VersionStages  []string      `json:"VersionStages"`
	CreatedDate    AWSTimestamp  `json:"CreatedDate"`
	KMSKeyIDs      []string      `json:"KmsKeyIds,omitempty"`
	LastAccessedAt *AWSTimestamp `json:"LastAccessedDate,omitempty"`
}

type SecretRotationResult struct {
	Metadata  SecretMetadataRecord
	VersionID string
}

func DefaultSecretResourcePolicy(meta SecretMetadataRecord) string {
	policy := map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{{
			"Sid":       "AllowAccountSecretAccess",
			"Effect":    "Allow",
			"Principal": "*",
			"Action":    "secretsmanager:*",
			"Resource":  meta.ARN,
		}},
	}
	b, _ := json.Marshal(policy)
	return string(b)
}

func EnsureSecretStageMap(meta *SecretMetadataRecord) {
	if meta.VersionStages == nil {
		meta.VersionStages = BuildFallbackSecretStageMap(meta.CurrentVersionID, meta.PreviousVersionID)
	}
}

func BuildFallbackSecretStageMap(currentVersionID, previousVersionID string) map[string][]string {
	out := map[string][]string{}
	if currentVersionID != "" {
		out[currentVersionID] = append(out[currentVersionID], CurrentVersionStage)
	}
	if previousVersionID != "" {
		out[previousVersionID] = append(out[previousVersionID], PreviousVersionStage)
	}
	return out
}

func MergeSecretStageMaps(dst, src map[string][]string) {
	for versionID, stages := range src {
		for _, stage := range stages {
			if !ContainsString(dst[versionID], stage) {
				dst[versionID] = append(dst[versionID], stage)
			}
		}
	}
}

func PromoteSecretVersion(meta *SecretMetadataRecord, newVersionID string) {
	EnsureSecretStageMap(meta)
	oldCurrent := meta.CurrentVersionID
	RemoveSecretStage(meta, PreviousVersionStage, "")
	if oldCurrent != "" && oldCurrent != newVersionID {
		AssignSecretStage(meta, PreviousVersionStage, oldCurrent)
	}
	AssignSecretStage(meta, CurrentVersionStage, newVersionID)
	SyncPrimarySecretVersionFields(meta)
}

func AssignSecretStage(meta *SecretMetadataRecord, stage, versionID string) {
	EnsureSecretStageMap(meta)
	RemoveSecretStage(meta, stage, "")
	if versionID == "" {
		return
	}
	if !ContainsString(meta.VersionStages[versionID], stage) {
		meta.VersionStages[versionID] = append(meta.VersionStages[versionID], stage)
	}
	stages := meta.VersionStages[versionID]
	sort.Strings(stages)
	meta.VersionStages[versionID] = stages
	SyncPrimarySecretVersionFields(meta)
}

func RemoveSecretStage(meta *SecretMetadataRecord, stage, versionID string) {
	EnsureSecretStageMap(meta)
	for currentVersionID, stages := range meta.VersionStages {
		if versionID != "" && currentVersionID != versionID {
			continue
		}
		filtered := stages[:0]
		for _, candidate := range stages {
			if candidate != stage {
				filtered = append(filtered, candidate)
			}
		}
		if len(filtered) == 0 {
			delete(meta.VersionStages, currentVersionID)
		} else {
			meta.VersionStages[currentVersionID] = filtered
		}
	}
	SyncPrimarySecretVersionFields(meta)
}

func SyncPrimarySecretVersionFields(meta *SecretMetadataRecord) {
	meta.CurrentVersionID = ""
	meta.PreviousVersionID = ""
	for versionID, stages := range meta.VersionStages {
		for _, stage := range stages {
			switch stage {
			case CurrentVersionStage:
				meta.CurrentVersionID = versionID
			case PreviousVersionStage:
				meta.PreviousVersionID = versionID
			}
		}
	}
}

func ContainsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func (t AWSTimestamp) MarshalJSON() ([]byte, error) {
	tt := time.Time(t)
	if tt.IsZero() {
		return []byte("null"), nil
	}
	secs := float64(tt.UnixNano()) / float64(time.Second)
	return []byte(strconv.FormatFloat(secs, 'f', -1, 64)), nil
}
