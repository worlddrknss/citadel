package server

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	"github.com/worlddrknss/citadel/internal/store"
)

// Secrets Manager compatibility: BatchGetSecretValue, GetRandomPassword and
// the store-paged, filtered secret scan shared with ListSecrets.

// scanSecrets returns up to limit secrets after the cursor that satisfy keep,
// paging through the store rather than loading every secret. next is the
// cursor for the following call ("" when the listing is exhausted).
func (s *Server) scanSecrets(ctx context.Context, after string, limit int, includeDeleted bool, keep func(store.SecretMetadataRecord) bool) (out []store.SecretMetadataRecord, next string, err error) {
	return s.scanSecretsOrdered(ctx, after, limit, includeDeleted, false, keep)
}

// scanSecretsOrdered is scanSecrets in ascending or descending name order.
func (s *Server) scanSecretsOrdered(ctx context.Context, after string, limit int, includeDeleted, descending bool, keep func(store.SecretMetadataRecord) bool) (out []store.SecretMetadataRecord, next string, err error) {
	cursor := after
	for {
		page, more, err := s.store.ListSecretsPage(ctx, store.SecretPageQuery{After: cursor, Limit: limit, IncludeDeleted: includeDeleted, Descending: descending})
		if err != nil {
			return nil, "", err
		}
		for i, item := range page {
			cursor = item.Name
			if !keep(item) {
				continue
			}
			out = append(out, item)
			if len(out) == limit {
				if i < len(page)-1 || more {
					return out, item.Name, nil
				}
				return out, "", nil
			}
		}
		if !more {
			return out, "", nil
		}
	}
}

// ---- BatchGetSecretValue ---------------------------------------------------

type batchGetSecretValueRequest struct {
	SecretIDList []string        `json:"SecretIdList"`
	Filters      []secretsFilter `json:"Filters"`
	MaxResults   int             `json:"MaxResults"`
	NextToken    string          `json:"NextToken"`
}

type batchSecretValueEntry struct {
	ARN           string             `json:"ARN"`
	Name          string             `json:"Name"`
	VersionID     string             `json:"VersionId"`
	SecretString  string             `json:"SecretString,omitempty"`
	SecretBinary  string             `json:"SecretBinary,omitempty"`
	VersionStages []string           `json:"VersionStages"`
	CreatedDate   store.AWSTimestamp `json:"CreatedDate"`
}

type batchSecretValueError struct {
	SecretID  string `json:"SecretId"`
	ErrorCode string `json:"ErrorCode"`
	Message   string `json:"Message"`
}

type batchGetSecretValueResponse struct {
	SecretValues []batchSecretValueEntry `json:"SecretValues"`
	Errors       []batchSecretValueError `json:"Errors"`
	NextToken    string                  `json:"NextToken,omitempty"`
}

const maxBatchSecretIDs = 20

func (s *Server) handleBatchGetSecretValue(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.BatchGetSecretValue"
	ctx := r.Context()
	fail := func(typ, msg string) {
		writeAWSJSONError(w, http.StatusBadRequest, typ, msg)
		s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
	}
	var req batchGetSecretValueRequest
	if err := decodeJSONBody(r, &req); err != nil {
		fail("InvalidParameterException", err.Error())
		return
	}
	switch {
	case len(req.SecretIDList) > 0 && len(req.Filters) > 0:
		fail("InvalidParameterException", "SecretIdList and Filters are mutually exclusive")
		return
	case len(req.SecretIDList) == 0 && len(req.Filters) == 0:
		fail("InvalidParameterException", "one of SecretIdList or Filters is required")
		return
	case len(req.SecretIDList) > maxBatchSecretIDs:
		fail("InvalidParameterException", fmt.Sprintf("SecretIdList can contain at most %d secrets", maxBatchSecretIDs))
		return
	case len(req.SecretIDList) > 0 && (req.MaxResults != 0 || req.NextToken != ""):
		fail("InvalidParameterException", "MaxResults and NextToken apply only with Filters")
		return
	}

	resp := batchGetSecretValueResponse{SecretValues: []batchSecretValueEntry{}, Errors: []batchSecretValueError{}}
	ids := req.SecretIDList
	if len(req.Filters) > 0 {
		if err := validateSecretsFilters(req.Filters); err != nil {
			fail("InvalidParameterException", err.Error())
			return
		}
		limit := req.MaxResults
		if limit == 0 {
			limit = maxBatchSecretIDs
		}
		if limit < 1 || limit > maxBatchSecretIDs {
			fail("InvalidParameterException", fmt.Sprintf("MaxResults must be between 1 and %d", maxBatchSecretIDs))
			return
		}
		after, err := decodeListMarker("s", req.NextToken)
		if err != nil {
			fail("InvalidNextTokenException", "NextToken is invalid")
			return
		}
		items, next, err := s.scanSecrets(ctx, after, limit, false, func(m store.SecretMetadataRecord) bool {
			return secretMatchesFilters(m, req.Filters)
		})
		if err != nil {
			writeAWSJSONError(w, http.StatusInternalServerError, "InternalServiceError", "list secrets: "+err.Error())
			return
		}
		ids = make([]string, 0, len(items))
		for _, m := range items {
			ids = append(ids, m.Name)
		}
		resp.NextToken = encodeListMarker("s", next)
	}

	for _, id := range ids {
		entry, typ, msg := s.batchGetOne(ctx, r, id)
		if typ != "" {
			resp.Errors = append(resp.Errors, batchSecretValueError{SecretID: id, ErrorCode: typ, Message: msg})
			s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
			continue
		}
		resp.SecretValues = append(resp.SecretValues, entry)
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, resp)
}

// batchGetOne reads the current value of one secret with the same checks as
// GetSecretValue, returning an error code instead of failing the batch.
func (s *Server) batchGetOne(ctx context.Context, r *http.Request, id string) (batchSecretValueEntry, string, string) {
	if strings.TrimSpace(id) == "" {
		return batchSecretValueEntry{}, "InvalidParameterException", "SecretId must not be empty"
	}
	meta, err := s.store.DescribeSecret(ctx, id)
	if err == nil {
		err = s.authorizeSecretAction(ctx, r, meta, "secretsmanager:GetSecretValue")
	}
	var value store.SecretValueRecord
	if err == nil {
		value, err = s.store.GetSecretValue(ctx, id, "", "")
	}
	if err != nil {
		typ, msg := secretErrorTypeAndMessage(err)
		if typ == "InternalServiceError" {
			msg = "An internal error occurred."
		}
		return batchSecretValueEntry{}, typ, msg
	}
	entry := batchSecretValueEntry{
		ARN:           value.ARN,
		Name:          value.Name,
		VersionID:     value.VersionID,
		VersionStages: value.VersionStages,
		CreatedDate:   store.AWSTimestamp(value.CreatedAt),
	}
	if value.SecretString != nil {
		entry.SecretString = *value.SecretString
	} else {
		entry.SecretBinary = value.SecretBinary
	}
	return entry, "", ""
}

// ---- GetRandomPassword -----------------------------------------------------

type getRandomPasswordRequest struct {
	PasswordLength          *int64 `json:"PasswordLength"`
	ExcludeCharacters       string `json:"ExcludeCharacters"`
	ExcludeNumbers          bool   `json:"ExcludeNumbers"`
	ExcludePunctuation      bool   `json:"ExcludePunctuation"`
	ExcludeUppercase        bool   `json:"ExcludeUppercase"`
	ExcludeLowercase        bool   `json:"ExcludeLowercase"`
	IncludeSpace            bool   `json:"IncludeSpace"`
	RequireEachIncludedType *bool  `json:"RequireEachIncludedType"`
}

// The character classes Secrets Manager draws from. Punctuation is the AWS
// set: every printable ASCII symbol.
const (
	pwLower       = "abcdefghijklmnopqrstuvwxyz"
	pwUpper       = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	pwDigits      = "0123456789"
	pwPunctuation = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
)

// generatePassword implements GetRandomPassword with crypto/rand: uniform
// choice from the allowed set, at least one character of each included type
// when requireEach, and a uniform shuffle so those are not positional.
func generatePassword(req getRandomPasswordRequest) (string, error) {
	length := int64(32)
	if req.PasswordLength != nil {
		length = *req.PasswordLength
	}
	if length < 1 || length > 4096 {
		return "", errors.New("PasswordLength must be between 1 and 4096")
	}
	requireEach := true
	if req.RequireEachIncludedType != nil {
		requireEach = *req.RequireEachIncludedType
	}
	exclude := func(set string) string {
		return strings.Map(func(c rune) rune {
			if strings.ContainsRune(req.ExcludeCharacters, c) {
				return -1
			}
			return c
		}, set)
	}
	var classes []string
	add := func(skip bool, set string) {
		if skip {
			return
		}
		if set = exclude(set); set != "" {
			classes = append(classes, set)
		}
	}
	add(req.ExcludeLowercase, pwLower)
	add(req.ExcludeUppercase, pwUpper)
	add(req.ExcludeNumbers, pwDigits)
	add(req.ExcludePunctuation, pwPunctuation)
	add(!req.IncludeSpace, " ")
	if len(classes) == 0 {
		return "", errors.New("the request excludes every character type")
	}
	if requireEach && int64(len(classes)) > length {
		return "", fmt.Errorf("PasswordLength must be at least %d to include each required character type", len(classes))
	}
	all := strings.Join(classes, "")
	out := make([]byte, 0, length)
	if requireEach {
		for _, set := range classes {
			c, err := randomChar(set)
			if err != nil {
				return "", err
			}
			out = append(out, c)
		}
	}
	for int64(len(out)) < length {
		c, err := randomChar(all)
		if err != nil {
			return "", err
		}
		out = append(out, c)
	}
	for i := len(out) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", err
		}
		out[i], out[j.Int64()] = out[j.Int64()], out[i]
	}
	return string(out), nil
}

func randomChar(set string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		return 0, err
	}
	return set[n.Int64()], nil
}

func (s *Server) handleGetRandomPassword(w http.ResponseWriter, r *http.Request) {
	const action = "secretsmanager.GetRandomPassword"
	var req getRandomPasswordRequest
	if err := decodeOptionalJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	password, err := generatePassword(req)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidParameterException", AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, map[string]string{"RandomPassword": password})
}
