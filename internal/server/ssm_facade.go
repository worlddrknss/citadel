package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/worlddrknss/citadel/internal/arn"
	"github.com/worlddrknss/citadel/internal/store"
)

// AWS Systems Manager (SSM) Parameter Store compatibility facade. These
// handlers are dispatched from handleKMS on the X-Amz-Target header
// (AmazonSSM.*) after SigV4 authentication, mirroring the KMS and Secrets
// Manager facades. They translate the AWS JSON wire shapes to and from the
// shared parameter store so existing AWS SDKs and tooling (e.g. the
// External Secrets Operator) work unchanged.

func (s *Server) parameterARN(ctx context.Context, name string) string {
	region, acct := s.store.DeploymentIdentity()
	if a, ok := store.CallerAccountFromContext(ctx); ok {
		acct = a
	}
	return arn.Build("ssm", region, acct, "parameter"+name)
}

// ssmParamStore resolves the parameter persistence layer or writes an AWS error.
func (s *Server) ssmParamStore(w http.ResponseWriter) (store.ParameterStore, bool) {
	ps, ok := s.paramStore()
	if !ok {
		writeAWSJSONError(w, http.StatusInternalServerError, "InternalServerError", "parameter store is not available")
		return nil, false
	}
	return ps, true
}

// errParameterVersionNotFound is a selector or label naming no version.
var errParameterVersionNotFound = errors.New("parameter version not found")

// ssmErrorType maps an error to its SSM error code.
func ssmErrorType(err error) string {
	switch {
	case errors.Is(err, store.ErrParameterNotFound):
		return "ParameterNotFound"
	case errors.Is(err, store.ErrParameterExists):
		return "ParameterAlreadyExists"
	case errors.Is(err, errParameterVersionNotFound):
		return "ParameterVersionNotFound"
	case errors.Is(err, errSSMKeyNotFound):
		return "InvalidKeyId"
	}
	return "InternalServerError"
}

func ssmParameterError(w http.ResponseWriter, err error) string {
	typ := ssmErrorType(err)
	switch typ {
	case "ParameterNotFound":
		writeAWSJSONError(w, http.StatusBadRequest, typ, "Parameter not found.")
	case "ParameterAlreadyExists":
		writeAWSJSONError(w, http.StatusBadRequest, typ, "The parameter already exists. To overwrite this value, set the overwrite option in the request to true.")
	case "ParameterVersionNotFound":
		writeAWSJSONError(w, http.StatusBadRequest, typ, "The specified parameter version was not found.")
	case "InvalidKeyId":
		writeAWSJSONError(w, http.StatusBadRequest, typ, "The KMS key ID is not valid or not accessible to this account.")
	default:
		writeAWSJSONError(w, http.StatusInternalServerError, typ, err.Error())
	}
	return typ
}

func (s *Server) ssmValidation(w http.ResponseWriter, r *http.Request, action, msg string) {
	writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", msg)
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "ValidationException", AuditOrigin: s.auditOrigin(r)})
}

// ---- wire shapes -----------------------------------------------------------

type ssmTag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

type ssmParameter struct {
	Name             string              `json:"Name"`
	Type             string              `json:"Type"`
	Value            string              `json:"Value"`
	Version          int64               `json:"Version"`
	Selector         string              `json:"Selector,omitempty"`
	LastModifiedDate *store.AWSTimestamp `json:"LastModifiedDate,omitempty"`
	ARN              string              `json:"ARN"`
	DataType         string              `json:"DataType"`
}

type ssmParameterMetadata struct {
	Name             string              `json:"Name"`
	ARN              string              `json:"ARN"`
	Type             string              `json:"Type"`
	Tier             string              `json:"Tier"`
	Version          int64               `json:"Version"`
	Description      string              `json:"Description,omitempty"`
	KeyId            string              `json:"KeyId,omitempty"`
	LastModifiedDate *store.AWSTimestamp `json:"LastModifiedDate,omitempty"`
	DataType         string              `json:"DataType"`
	Policies         []any               `json:"Policies"`
}

// errSSMKeyNotFound marks a SecureString whose KMS key cannot be resolved.
var errSSMKeyNotFound = errors.New("kms key not found")

// ssmValue returns the value to surface for a record, decrypting
// SecureString only when requested.
func (s *Server) ssmValue(ctx context.Context, isEncrypted bool, keyID, value string, withDecryption bool) (string, error) {
	if !isEncrypted || !withDecryption {
		return value, nil
	}
	plain, err := s.decryptParameterValue(ctx, keyID, value)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", errSSMKeyNotFound
		}
		return "", fmt.Errorf("decrypt %s: %w", keyID, err)
	}
	return plain, nil
}

func (s *Server) ssmParameterFrom(ctx context.Context, rec store.ParameterRecord, withDecryption bool) (ssmParameter, error) {
	value, err := s.ssmValue(ctx, rec.IsEncrypted, rec.KMSKeyID, rec.Value, withDecryption)
	if err != nil {
		return ssmParameter{}, err
	}
	ts := store.AWSTimestamp(rec.UpdatedAt)
	return ssmParameter{
		Name:             rec.Name,
		Type:             rec.Type,
		Value:            value,
		Version:          rec.Version,
		LastModifiedDate: &ts,
		ARN:              s.parameterARN(ctx, rec.Name),
		DataType:         "text",
	}, nil
}

// ssmNameFromInput accepts a parameter name or its ARN.
func ssmNameFromInput(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "arn:") {
		parts := strings.SplitN(raw, ":", 6)
		if len(parts) == 6 && strings.HasPrefix(parts[5], "parameter") {
			return strings.TrimPrefix(parts[5], "parameter")
		}
	}
	return raw
}

// splitParameterSelector splits "name:3" or "name:label" (the GetParameter
// selector forms) into name and selector.
func splitParameterSelector(raw string) (name, selector string) {
	raw = ssmNameFromInput(raw)
	slash := strings.LastIndex(raw, "/")
	if i := strings.LastIndex(raw, ":"); i > slash {
		return raw[:i], raw[i+1:]
	}
	return raw, ""
}

// ssmGetSelected fetches a parameter, honouring a version or label selector.
func (s *Server) ssmGetSelected(ctx context.Context, ps store.ParameterStore, raw string) (store.ParameterRecord, string, error) {
	name, selector := splitParameterSelector(raw)
	canonical, err := normalizeParameterName(name)
	if err != nil {
		return store.ParameterRecord{}, "", err
	}
	rec, err := ps.GetParameter(ctx, canonical)
	if err != nil || selector == "" {
		return rec, "", err
	}
	history, err := ps.GetParameterHistory(ctx, canonical)
	if err != nil {
		return store.ParameterRecord{}, "", err
	}
	version, verr := strconv.ParseInt(selector, 10, 64)
	for _, h := range history {
		if (verr == nil && h.Version == version) || (verr != nil && containsString(h.Labels, selector)) {
			return store.ParameterRecord{
				Name: h.Name, Type: h.Type, Value: h.Value, IsEncrypted: h.IsEncrypted, KMSKeyID: h.KMSKeyID,
				Tier: h.Tier, Version: h.Version, Description: h.Description, UpdatedAt: h.ModifiedAt,
			}, ":" + selector, nil
		}
	}
	return store.ParameterRecord{}, "", errParameterVersionNotFound
}

// normalizeParameterPath validates a hierarchy path. "/" is the root.
func normalizeParameterPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "/" {
		return "/", nil
	}
	if !strings.HasPrefix(path, "/") {
		return "", errors.New("Path must begin with /")
	}
	return normalizeParameterName(path)
}

// ---- PutParameter ----------------------------------------------------------

type ssmPutParameterRequest struct {
	Name           string   `json:"Name"`
	Value          string   `json:"Value"`
	Type           string   `json:"Type"`
	KeyId          string   `json:"KeyId"`
	Tier           string   `json:"Tier"`
	Description    string   `json:"Description"`
	Overwrite      bool     `json:"Overwrite"`
	Tags           []ssmTag `json:"Tags"`
	AllowedPattern string   `json:"AllowedPattern"`
	DataType       string   `json:"DataType"`
	Policies       string   `json:"Policies"`
}

type ssmPutParameterResponse struct {
	Version int64  `json:"Version"`
	Tier    string `json:"Tier"`
}

const maxSSMValueBytes = 8192

func (s *Server) handleSSMPutParameter(w http.ResponseWriter, r *http.Request) {
	const action = "AmazonSSM.PutParameter"
	ps, ok := s.ssmParamStore(w)
	if !ok {
		return
	}
	var req ssmPutParameterRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.ssmValidation(w, r, action, err.Error())
		return
	}
	name, err := normalizeParameterName(ssmNameFromInput(req.Name))
	if err == nil {
		err = s.validateNewParameterName(r.Context(), name)
	}
	if err != nil {
		typ, msg := ssmNameErrorParts(err)
		writeAWSJSONError(w, http.StatusBadRequest, typ, msg)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: typ, AuditOrigin: s.auditOrigin(r)})
		return
	}
	typ := req.Type
	if typ == "" && req.Overwrite {
		// Overwrite without Type keeps the existing type, as in AWS.
		if existing, gerr := ps.GetParameter(r.Context(), name); gerr == nil {
			typ = existing.Type
		}
	}
	if _, err := normalizeParameterType(typ); err != nil {
		s.ssmValidation(w, r, action, err.Error())
		return
	}
	switch {
	case req.Value == "":
		s.ssmValidation(w, r, action, "Value is required")
		return
	case len(req.Value) > maxSSMValueBytes:
		s.ssmValidation(w, r, action, "Value exceeds the 8 KB limit")
		return
	case req.DataType != "" && req.DataType != "text":
		s.ssmValidation(w, r, action, "DataType "+req.DataType+" is not supported; only text is")
		return
	case req.Overwrite && len(req.Tags) > 0:
		s.ssmValidation(w, r, action, "Tags and Overwrite can't be used together. To create a parameter with tags, don't set Overwrite; to change tags, use AddTagsToResource or RemoveTagsFromResource.")
		return
	case strings.TrimSpace(req.Policies) != "":
		s.ssmValidation(w, r, action, "parameter policies are not supported")
		return
	}
	if req.AllowedPattern != "" {
		re, err := regexp.Compile(req.AllowedPattern)
		if err != nil {
			s.ssmValidation(w, r, action, "AllowedPattern is not a valid regular expression")
			return
		}
		if !re.MatchString(req.Value) {
			writeAWSJSONError(w, http.StatusBadRequest, "ParameterPatternMismatchException", "Parameter value does not match the AllowedPattern")
			return
		}
	}
	rec, err := s.buildParameterRecord(r.Context(), name, typ, req.Value, kmsKeyIDFromInput(req.KeyId), req.Tier, req.Description)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = errSSMKeyNotFound
		}
		errType := ssmParameterError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: errType, AuditOrigin: s.auditOrigin(r)})
		return
	}
	saved, err := ps.PutParameter(r.Context(), rec, req.Overwrite)
	if err != nil {
		errType := ssmParameterError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: rec.KMSKeyID, Result: "error", ErrorType: errType, AuditOrigin: s.auditOrigin(r)})
		return
	}
	if len(req.Tags) > 0 {
		tags := make([]store.ParamTag, 0, len(req.Tags))
		for _, t := range req.Tags {
			tags = append(tags, store.ParamTag{Key: t.Key, Value: t.Value})
		}
		if err := ps.TagParameter(r.Context(), saved.Name, tags); err != nil {
			errType := ssmParameterError(w, err)
			s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: saved.KMSKeyID, Result: "error", ErrorType: errType, AuditOrigin: s.auditOrigin(r)})
			return
		}
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: saved.KMSKeyID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, ssmPutParameterResponse{Version: saved.Version, Tier: saved.Tier})
}

// ---- GetParameter ----------------------------------------------------------

type ssmGetParameterRequest struct {
	Name           string `json:"Name"`
	WithDecryption bool   `json:"WithDecryption"`
}

type ssmGetParameterResponse struct {
	Parameter ssmParameter `json:"Parameter"`
}

func (s *Server) handleSSMGetParameter(w http.ResponseWriter, r *http.Request) {
	const action = "AmazonSSM.GetParameter"
	ps, ok := s.ssmParamStore(w)
	if !ok {
		return
	}
	var req ssmGetParameterRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.ssmValidation(w, r, action, err.Error())
		return
	}
	rec, selector, err := s.ssmGetSelected(r.Context(), ps, req.Name)
	if err != nil {
		if isParameterNameError(err) {
			s.ssmValidation(w, r, action, err.Error())
			return
		}
		errType := ssmParameterError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: errType, AuditOrigin: s.auditOrigin(r)})
		return
	}
	param, err := s.ssmParameterFrom(r.Context(), rec, req.WithDecryption)
	if err != nil {
		errType := ssmParameterError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: rec.KMSKeyID, Result: "error", ErrorType: errType, AuditOrigin: s.auditOrigin(r)})
		return
	}
	param.Selector = selector
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: rec.KMSKeyID, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, ssmGetParameterResponse{Parameter: param})
}

// isParameterNameError reports a name validation failure from
// normalizeParameterName.
func isParameterNameError(err error) bool {
	msg := err.Error()
	return strings.HasPrefix(msg, "parameter name") || strings.HasPrefix(msg, "Path ")
}

// ---- GetParameters ---------------------------------------------------------

type ssmGetParametersRequest struct {
	Names          []string `json:"Names"`
	WithDecryption bool     `json:"WithDecryption"`
}

type ssmGetParametersResponse struct {
	Parameters        []ssmParameter `json:"Parameters"`
	InvalidParameters []string       `json:"InvalidParameters"`
}

const maxSSMBatchNames = 10

func (s *Server) handleSSMGetParameters(w http.ResponseWriter, r *http.Request) {
	const action = "AmazonSSM.GetParameters"
	ps, ok := s.ssmParamStore(w)
	if !ok {
		return
	}
	var req ssmGetParametersRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.ssmValidation(w, r, action, err.Error())
		return
	}
	if len(req.Names) == 0 || len(req.Names) > maxSSMBatchNames {
		s.ssmValidation(w, r, action, "Names must contain between 1 and 10 names")
		return
	}
	resp := ssmGetParametersResponse{Parameters: []ssmParameter{}, InvalidParameters: []string{}}
	for _, raw := range req.Names {
		rec, selector, err := s.ssmGetSelected(r.Context(), ps, raw)
		if err != nil {
			if ssmErrorType(err) == "InternalServerError" && !isParameterNameError(err) {
				// A store failure fails the call; only bad or missing names
				// are reported in InvalidParameters.
				ssmParameterError(w, err)
				return
			}
			resp.InvalidParameters = append(resp.InvalidParameters, raw)
			continue
		}
		param, err := s.ssmParameterFrom(r.Context(), rec, req.WithDecryption)
		if err != nil {
			errType := ssmParameterError(w, err)
			s.recordAudit(r.Context(), store.AuditEvent{Action: action, KeyID: rec.KMSKeyID, Result: "error", ErrorType: errType, AuditOrigin: s.auditOrigin(r)})
			return
		}
		param.Selector = selector
		resp.Parameters = append(resp.Parameters, param)
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, resp)
}

// ---- filters ---------------------------------------------------------------

// ssmParameterStringFilter is ParameterStringFilter.
type ssmParameterStringFilter struct {
	Key    string   `json:"Key"`
	Option string   `json:"Option"`
	Values []string `json:"Values"`
}

// ssmLegacyFilter is the deprecated ParametersFilter of DescribeParameters.
type ssmLegacyFilter struct {
	Key    string   `json:"Key"`
	Values []string `json:"Values"`
}

// ssmFilterSet is a validated set of filters plus the path restriction
// that is pushed down to the store.
type ssmFilterSet struct {
	filters   []ssmParameterStringFilter
	path      string
	recursive bool
	needTags  bool
	label     string
}

// compileSSMFilters validates filters. forPath selects the subset allowed by
// GetParametersByPath (Type, KeyId, Label); otherwise the DescribeParameters
// keys (Name, Type, KeyId, Path, Tier, DataType, tag:*) apply.
func compileSSMFilters(filters []ssmParameterStringFilter, forPath bool) (ssmFilterSet, error) {
	set := ssmFilterSet{path: "/", recursive: true}
	seen := map[string]bool{}
	for _, f := range filters {
		key := strings.TrimSpace(f.Key)
		opt := f.Option
		if opt == "" {
			opt = "Equals"
		}
		if seen[key] {
			return set, fmt.Errorf("filter key %s is specified more than once", key)
		}
		seen[key] = true
		isTag := strings.HasPrefix(key, "tag:") && len(key) > len("tag:")
		switch {
		case forPath && (key == "Type" || key == "KeyId" || key == "Label"):
		case !forPath && (key == "Name" || key == "Type" || key == "KeyId" || key == "Path" || key == "Tier" || key == "DataType" || isTag):
		default:
			return set, fmt.Errorf("filter key %q is not valid for this operation", key)
		}
		switch key {
		case "Name":
			if opt != "Equals" && opt != "BeginsWith" && opt != "Contains" {
				return set, fmt.Errorf("option %s is not valid for the Name filter", opt)
			}
		case "Path":
			if opt != "Recursive" && opt != "OneLevel" {
				return set, fmt.Errorf("option %s is not valid for the Path filter", opt)
			}
			if len(f.Values) != 1 {
				return set, errors.New("the Path filter takes exactly one value")
			}
			p, err := normalizeParameterPath(f.Values[0])
			if err != nil {
				return set, err
			}
			set.path, set.recursive = p, opt == "Recursive"
			continue
		case "Label":
			if opt != "Equals" || len(f.Values) != 1 {
				return set, errors.New("the Label filter takes Equals and exactly one value")
			}
			set.label = f.Values[0]
			continue
		default:
			if opt != "Equals" && !(isTag && opt == "BeginsWith") {
				return set, fmt.Errorf("option %s is not valid for the %s filter", opt, key)
			}
		}
		if len(f.Values) == 0 && !isTag {
			return set, fmt.Errorf("filter %s requires at least one value", key)
		}
		set.needTags = set.needTags || isTag
		set.filters = append(set.filters, ssmParameterStringFilter{Key: key, Option: opt, Values: f.Values})
	}
	return set, nil
}

// legacySSMFilters converts the deprecated Filters member.
func legacySSMFilters(filters []ssmLegacyFilter) ([]ssmParameterStringFilter, error) {
	out := make([]ssmParameterStringFilter, 0, len(filters))
	for _, f := range filters {
		switch f.Key {
		case "Name", "Type", "KeyId":
			opt := "Equals"
			if f.Key == "Name" {
				opt = "BeginsWith"
			}
			out = append(out, ssmParameterStringFilter{Key: f.Key, Option: opt, Values: f.Values})
		default:
			return nil, fmt.Errorf("filter key %q is not valid", f.Key)
		}
	}
	return out, nil
}

func ssmFilterMatches(f ssmParameterStringFilter, rec store.ParameterRecord, tags []store.ParamTag) bool {
	field := ""
	switch f.Key {
	case "Name":
		field = rec.Name
	case "Type":
		field = rec.Type
	case "KeyId":
		field = rec.KMSKeyID
	case "Tier":
		field = rec.Tier
	case "DataType":
		field = "text"
	default: // tag:<key>
		want := strings.TrimPrefix(f.Key, "tag:")
		for _, t := range tags {
			if t.Key != want {
				continue
			}
			if len(f.Values) == 0 {
				return true
			}
			for _, v := range f.Values {
				if (f.Option == "BeginsWith" && strings.HasPrefix(t.Value, v)) || t.Value == v {
					return true
				}
			}
		}
		return false
	}
	for _, v := range f.Values {
		switch f.Option {
		case "BeginsWith":
			if f.Key == "Name" && !strings.HasPrefix(v, "/") {
				v = "/" + v
			}
			if strings.HasPrefix(field, v) {
				return true
			}
		case "Contains":
			if strings.Contains(field, v) {
				return true
			}
		default:
			if f.Key == "KeyId" && kmsKeyIDFromInput(v) == field {
				return true
			}
			if f.Key == "Name" && !strings.HasPrefix(v, "/") {
				v = "/" + v
			}
			if field == v {
				return true
			}
		}
	}
	return false
}

// scanParameters pages through the store (not loading every parameter)
// until limit records satisfy keep. next is the cursor for the following
// call, "" when exhausted.
func (s *Server) scanParameters(ctx context.Context, path string, recursive bool, after string, limit int, keep func(store.ParameterRecord) (bool, error)) ([]store.ParameterRecord, string, error) {
	var out []store.ParameterRecord
	cursor := after
	for {
		page, more, err := s.store.ListParametersPage(ctx, store.ParameterPageQuery{Path: path, Recursive: recursive, After: cursor, Limit: limit})
		if err != nil {
			return nil, "", err
		}
		for i, rec := range page {
			cursor = rec.Name
			ok, err := keep(rec)
			if err != nil {
				return nil, "", err
			}
			if !ok {
				continue
			}
			out = append(out, rec)
			if len(out) == limit {
				if i < len(page)-1 || more {
					return out, rec.Name, nil
				}
				return out, "", nil
			}
		}
		if !more {
			return out, "", nil
		}
	}
}

// keepFunc builds the per-record predicate for a filter set.
func (s *Server) ssmKeepFunc(ctx context.Context, ps store.ParameterStore, set ssmFilterSet) func(store.ParameterRecord) (bool, error) {
	return func(rec store.ParameterRecord) (bool, error) {
		var tags []store.ParamTag
		if set.needTags {
			t, err := ps.ListParameterTags(ctx, rec.Name)
			if err != nil && !errors.Is(err, store.ErrParameterNotFound) {
				return false, err
			}
			tags = t
		}
		for _, f := range set.filters {
			if !ssmFilterMatches(f, rec, tags) {
				return false, nil
			}
		}
		return true, nil
	}
}

func ssmPageLimit(maxResults, def, max int) (int, error) {
	if maxResults == 0 {
		return def, nil
	}
	if maxResults < 1 || maxResults > max {
		return 0, fmt.Errorf("MaxResults must be between 1 and %d", max)
	}
	return maxResults, nil
}

// ---- GetParametersByPath ---------------------------------------------------

type ssmGetParametersByPathRequest struct {
	Path             string                     `json:"Path"`
	Recursive        bool                       `json:"Recursive"`
	WithDecryption   bool                       `json:"WithDecryption"`
	MaxResults       int                        `json:"MaxResults"`
	NextToken        string                     `json:"NextToken"`
	ParameterFilters []ssmParameterStringFilter `json:"ParameterFilters"`
}

type ssmGetParametersByPathResponse struct {
	Parameters []ssmParameter `json:"Parameters"`
	NextToken  string         `json:"NextToken,omitempty"`
}

func (s *Server) handleSSMGetParametersByPath(w http.ResponseWriter, r *http.Request) {
	const action = "AmazonSSM.GetParametersByPath"
	ctx := r.Context()
	ps, ok := s.ssmParamStore(w)
	if !ok {
		return
	}
	var req ssmGetParametersByPathRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.ssmValidation(w, r, action, err.Error())
		return
	}
	path, err := normalizeParameterPath(req.Path)
	if err != nil {
		s.ssmValidation(w, r, action, err.Error())
		return
	}
	limit, err := ssmPageLimit(req.MaxResults, 10, 10)
	if err != nil {
		s.ssmValidation(w, r, action, err.Error())
		return
	}
	set, err := compileSSMFilters(req.ParameterFilters, true)
	if err != nil {
		s.ssmValidation(w, r, action, err.Error())
		return
	}
	after, err := decodeListMarker("p", req.NextToken)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidNextToken", "The specified token is not valid.")
		return
	}
	keep := s.ssmKeepFunc(ctx, ps, set)
	labeled := map[string]store.ParameterRecord{}
	if set.label != "" {
		inner := keep
		keep = func(rec store.ParameterRecord) (bool, error) {
			if ok, err := inner(rec); !ok || err != nil {
				return ok, err
			}
			history, err := ps.GetParameterHistory(ctx, rec.Name)
			if err != nil {
				return false, err
			}
			for _, h := range history {
				if containsString(h.Labels, set.label) {
					labeled[rec.Name] = store.ParameterRecord{Name: h.Name, Type: h.Type, Value: h.Value, IsEncrypted: h.IsEncrypted, KMSKeyID: h.KMSKeyID, Tier: h.Tier, Version: h.Version, UpdatedAt: h.ModifiedAt}
					return true, nil
				}
			}
			return false, nil
		}
	}
	recs, next, err := s.scanParameters(ctx, path, req.Recursive, after, limit, keep)
	if err != nil {
		ssmParameterError(w, err)
		return
	}
	out := make([]ssmParameter, 0, len(recs))
	for _, rec := range recs {
		if l, ok := labeled[rec.Name]; ok {
			rec = l
		}
		param, err := s.ssmParameterFrom(ctx, rec, req.WithDecryption)
		if err != nil {
			errType := ssmParameterError(w, err)
			s.recordAudit(ctx, store.AuditEvent{Action: action, KeyID: rec.KMSKeyID, Result: "error", ErrorType: errType, AuditOrigin: s.auditOrigin(r)})
			return
		}
		if set.label != "" {
			param.Selector = ":" + set.label
		}
		out = append(out, param)
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, ssmGetParametersByPathResponse{Parameters: out, NextToken: encodeListMarker("p", next)})
}

// ---- DeleteParameter / DeleteParameters ------------------------------------

type ssmDeleteParameterRequest struct {
	Name string `json:"Name"`
}

func (s *Server) handleSSMDeleteParameter(w http.ResponseWriter, r *http.Request) {
	const action = "AmazonSSM.DeleteParameter"
	ps, ok := s.ssmParamStore(w)
	if !ok {
		return
	}
	var req ssmDeleteParameterRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.ssmValidation(w, r, action, err.Error())
		return
	}
	name, err := normalizeParameterName(ssmNameFromInput(req.Name))
	if err != nil {
		s.ssmValidation(w, r, action, err.Error())
		return
	}
	if err := ps.DeleteParameter(r.Context(), name); err != nil {
		errType := ssmParameterError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: errType, AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, map[string]any{})
}

type ssmDeleteParametersRequest struct {
	Names []string `json:"Names"`
}

type ssmDeleteParametersResponse struct {
	DeletedParameters []string `json:"DeletedParameters"`
	InvalidParameters []string `json:"InvalidParameters"`
}

func (s *Server) handleSSMDeleteParameters(w http.ResponseWriter, r *http.Request) {
	const action = "AmazonSSM.DeleteParameters"
	ps, ok := s.ssmParamStore(w)
	if !ok {
		return
	}
	var req ssmDeleteParametersRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.ssmValidation(w, r, action, err.Error())
		return
	}
	if len(req.Names) == 0 || len(req.Names) > maxSSMBatchNames {
		s.ssmValidation(w, r, action, "Names must contain between 1 and 10 names")
		return
	}
	resp := ssmDeleteParametersResponse{DeletedParameters: []string{}, InvalidParameters: []string{}}
	for _, raw := range req.Names {
		name, err := normalizeParameterName(ssmNameFromInput(raw))
		if err != nil {
			resp.InvalidParameters = append(resp.InvalidParameters, raw)
			continue
		}
		if err := ps.DeleteParameter(r.Context(), name); err != nil {
			if !errors.Is(err, store.ErrParameterNotFound) {
				ssmParameterError(w, err)
				return
			}
			resp.InvalidParameters = append(resp.InvalidParameters, raw)
			continue
		}
		resp.DeletedParameters = append(resp.DeletedParameters, raw)
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, resp)
}

// ---- DescribeParameters ----------------------------------------------------

type ssmDescribeParametersRequest struct {
	Filters          []ssmLegacyFilter          `json:"Filters"`
	ParameterFilters []ssmParameterStringFilter `json:"ParameterFilters"`
	MaxResults       int                        `json:"MaxResults"`
	NextToken        string                     `json:"NextToken"`
	Shared           bool                       `json:"Shared"`
}

type ssmDescribeParametersResponse struct {
	Parameters []ssmParameterMetadata `json:"Parameters"`
	NextToken  string                 `json:"NextToken,omitempty"`
}

func (s *Server) handleSSMDescribeParameters(w http.ResponseWriter, r *http.Request) {
	const action = "AmazonSSM.DescribeParameters"
	ctx := r.Context()
	ps, ok := s.ssmParamStore(w)
	if !ok {
		return
	}
	var req ssmDescribeParametersRequest
	if err := decodeOptionalJSONBody(r, &req); err != nil {
		s.ssmValidation(w, r, action, err.Error())
		return
	}
	if len(req.Filters) > 0 && len(req.ParameterFilters) > 0 {
		s.ssmValidation(w, r, action, "Filters and ParameterFilters can't be used together")
		return
	}
	filters := req.ParameterFilters
	if len(req.Filters) > 0 {
		legacy, err := legacySSMFilters(req.Filters)
		if err != nil {
			s.ssmValidation(w, r, action, err.Error())
			return
		}
		filters = legacy
	}
	set, err := compileSSMFilters(filters, false)
	if err != nil {
		s.ssmValidation(w, r, action, err.Error())
		return
	}
	limit, err := ssmPageLimit(req.MaxResults, 50, 50)
	if err != nil {
		s.ssmValidation(w, r, action, err.Error())
		return
	}
	after, err := decodeListMarker("p", req.NextToken)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidNextToken", "The specified token is not valid.")
		return
	}
	out := make([]ssmParameterMetadata, 0)
	next := ""
	if !req.Shared { // nothing is shared from other accounts
		recs, n, err := s.scanParameters(ctx, set.path, set.recursive, after, limit, s.ssmKeepFunc(ctx, ps, set))
		if err != nil {
			ssmParameterError(w, err)
			return
		}
		next = n
		for _, rec := range recs {
			ts := store.AWSTimestamp(rec.UpdatedAt)
			out = append(out, ssmParameterMetadata{
				Name:             rec.Name,
				ARN:              s.parameterARN(ctx, rec.Name),
				Type:             rec.Type,
				Tier:             rec.Tier,
				Version:          rec.Version,
				Description:      rec.Description,
				KeyId:            rec.KMSKeyID,
				LastModifiedDate: &ts,
				DataType:         "text",
				Policies:         []any{},
			})
		}
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, ssmDescribeParametersResponse{Parameters: out, NextToken: encodeListMarker("p", next)})
}

// ---- GetParameterHistory ---------------------------------------------------

type ssmGetParameterHistoryRequest struct {
	Name           string `json:"Name"`
	WithDecryption bool   `json:"WithDecryption"`
	MaxResults     int    `json:"MaxResults"`
	NextToken      string `json:"NextToken"`
}

type ssmParameterHistoryEntry struct {
	Name             string              `json:"Name"`
	Type             string              `json:"Type"`
	Value            string              `json:"Value"`
	Version          int64               `json:"Version"`
	Tier             string              `json:"Tier"`
	Description      string              `json:"Description,omitempty"`
	KeyId            string              `json:"KeyId,omitempty"`
	Labels           []string            `json:"Labels"`
	LastModifiedDate *store.AWSTimestamp `json:"LastModifiedDate,omitempty"`
	DataType         string              `json:"DataType"`
	Policies         []any               `json:"Policies"`
}

type ssmGetParameterHistoryResponse struct {
	Parameters []ssmParameterHistoryEntry `json:"Parameters"`
	NextToken  string                     `json:"NextToken,omitempty"`
}

func (s *Server) handleSSMGetParameterHistory(w http.ResponseWriter, r *http.Request) {
	const action = "AmazonSSM.GetParameterHistory"
	ctx := r.Context()
	ps, ok := s.ssmParamStore(w)
	if !ok {
		return
	}
	var req ssmGetParameterHistoryRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.ssmValidation(w, r, action, err.Error())
		return
	}
	name, err := normalizeParameterName(ssmNameFromInput(req.Name))
	if err != nil {
		s.ssmValidation(w, r, action, err.Error())
		return
	}
	limit, err := ssmPageLimit(req.MaxResults, 50, 50)
	if err != nil {
		s.ssmValidation(w, r, action, err.Error())
		return
	}
	history, err := ps.GetParameterHistory(ctx, name)
	if err != nil {
		errType := ssmParameterError(w, err)
		s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "error", ErrorType: errType, AuditOrigin: s.auditOrigin(r)})
		return
	}
	sort.Slice(history, func(i, j int) bool { return history[i].Version < history[j].Version })
	// History is bounded (AWS keeps 100 versions), so it pages in memory; the
	// token is the last version returned.
	start := 0
	if req.NextToken != "" {
		cursor, err := decodeListMarker("h", req.NextToken)
		v, perr := strconv.ParseInt(cursor, 10, 64)
		if err != nil || perr != nil {
			writeAWSJSONError(w, http.StatusBadRequest, "InvalidNextToken", "The specified token is not valid.")
			return
		}
		for start < len(history) && history[start].Version <= v {
			start++
		}
	}
	end := min(start+limit, len(history))
	out := make([]ssmParameterHistoryEntry, 0, end-start)
	for _, h := range history[start:end] {
		value, err := s.ssmValue(ctx, h.IsEncrypted, h.KMSKeyID, h.Value, req.WithDecryption)
		if err != nil {
			ssmParameterError(w, err)
			return
		}
		labels := h.Labels
		if labels == nil {
			labels = []string{}
		}
		ts := store.AWSTimestamp(h.ModifiedAt)
		out = append(out, ssmParameterHistoryEntry{
			Name:             h.Name,
			Type:             h.Type,
			Value:            value,
			Version:          h.Version,
			Tier:             h.Tier,
			Description:      h.Description,
			KeyId:            h.KMSKeyID,
			Labels:           labels,
			LastModifiedDate: &ts,
			DataType:         "text",
			Policies:         []any{},
		})
	}
	resp := ssmGetParameterHistoryResponse{Parameters: out}
	if end < len(history) && end > start {
		resp.NextToken = encodeListMarker("h", strconv.FormatInt(history[end-1].Version, 10))
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, resp)
}

// ---- LabelParameterVersion -------------------------------------------------

type ssmLabelParameterVersionRequest struct {
	Name             string   `json:"Name"`
	ParameterVersion int64    `json:"ParameterVersion"`
	Labels           []string `json:"Labels"`
}

type ssmLabelParameterVersionResponse struct {
	InvalidLabels    []string `json:"InvalidLabels"`
	ParameterVersion int64    `json:"ParameterVersion"`
}

var ssmLabelRe = regexp.MustCompile(`^[A-Za-z_.\-][A-Za-z0-9_.\-]{0,99}$`)

// validSSMLabel applies the AWS label rules: letters, digits, period, dash
// and underscore; not starting with a digit, "aws" or "ssm".
func validSSMLabel(label string) bool {
	lower := strings.ToLower(label)
	return ssmLabelRe.MatchString(label) && !strings.HasPrefix(lower, "aws") && !strings.HasPrefix(lower, "ssm")
}

func (s *Server) handleSSMLabelParameterVersion(w http.ResponseWriter, r *http.Request) {
	const action = "AmazonSSM.LabelParameterVersion"
	ctx := r.Context()
	ps, ok := s.ssmParamStore(w)
	if !ok {
		return
	}
	var req ssmLabelParameterVersionRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.ssmValidation(w, r, action, err.Error())
		return
	}
	name, err := normalizeParameterName(ssmNameFromInput(req.Name))
	if err != nil {
		s.ssmValidation(w, r, action, err.Error())
		return
	}
	if len(req.Labels) == 0 || len(req.Labels) > 10 {
		s.ssmValidation(w, r, action, "Labels must contain between 1 and 10 labels")
		return
	}
	rec, err := ps.GetParameter(ctx, name)
	if err != nil {
		errType := ssmParameterError(w, err)
		s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "error", ErrorType: errType, AuditOrigin: s.auditOrigin(r)})
		return
	}
	version := req.ParameterVersion
	if version == 0 {
		version = rec.Version
	}
	valid, invalid := []string{}, []string{}
	for _, l := range req.Labels {
		if validSSMLabel(l) {
			valid = append(valid, l)
		} else {
			invalid = append(invalid, l)
		}
	}
	if len(valid) > 0 {
		if _, err := ps.LabelParameterVersion(ctx, name, version, valid); err != nil {
			if errors.Is(err, store.ErrParameterNotFound) {
				err = errParameterVersionNotFound
			}
			errType := ssmParameterError(w, err)
			s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "error", ErrorType: errType, AuditOrigin: s.auditOrigin(r)})
			return
		}
	}
	s.recordAudit(ctx, store.AuditEvent{Action: action, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, ssmLabelParameterVersionResponse{InvalidLabels: invalid, ParameterVersion: version})
}

// ---- Tags ------------------------------------------------------------------

// ssmTagTarget validates ResourceType/ResourceId; only parameters are
// taggable here.
func (s *Server) ssmTagTarget(w http.ResponseWriter, r *http.Request, action, resourceType, resourceID string) (string, bool) {
	if resourceType != "Parameter" {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidResourceType", "only the Parameter resource type is supported")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidResourceType", AuditOrigin: s.auditOrigin(r)})
		return "", false
	}
	name, err := normalizeParameterName(ssmNameFromInput(resourceID))
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidResourceId", "ResourceId is not a valid parameter name")
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: "InvalidResourceId", AuditOrigin: s.auditOrigin(r)})
		return "", false
	}
	return name, true
}

// ssmTagError reports a missing parameter as InvalidResourceId, the code
// the tagging APIs use.
func ssmTagError(w http.ResponseWriter, err error) string {
	if errors.Is(err, store.ErrParameterNotFound) {
		writeAWSJSONError(w, http.StatusBadRequest, "InvalidResourceId", "The resource ID is not valid. Verify that you entered the correct ID and try again.")
		return "InvalidResourceId"
	}
	return ssmParameterError(w, err)
}

type ssmAddTagsRequest struct {
	ResourceType string   `json:"ResourceType"`
	ResourceId   string   `json:"ResourceId"`
	Tags         []ssmTag `json:"Tags"`
}

func (s *Server) handleSSMAddTagsToResource(w http.ResponseWriter, r *http.Request) {
	const action = "AmazonSSM.AddTagsToResource"
	ps, ok := s.ssmParamStore(w)
	if !ok {
		return
	}
	var req ssmAddTagsRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.ssmValidation(w, r, action, err.Error())
		return
	}
	name, ok := s.ssmTagTarget(w, r, action, req.ResourceType, req.ResourceId)
	if !ok {
		return
	}
	if len(req.Tags) == 0 {
		s.ssmValidation(w, r, action, "Tags is required")
		return
	}
	tags := make([]store.ParamTag, 0, len(req.Tags))
	for _, t := range req.Tags {
		if k := strings.TrimSpace(t.Key); k == "" || len(k) > 128 || len(t.Value) > 256 {
			s.ssmValidation(w, r, action, "tag keys must be 1-128 characters and values at most 256")
			return
		}
		tags = append(tags, store.ParamTag{Key: t.Key, Value: t.Value})
	}
	if err := ps.TagParameter(r.Context(), name, tags); err != nil {
		errType := ssmTagError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: errType, AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, map[string]any{})
}

type ssmRemoveTagsRequest struct {
	ResourceType string   `json:"ResourceType"`
	ResourceId   string   `json:"ResourceId"`
	TagKeys      []string `json:"TagKeys"`
}

func (s *Server) handleSSMRemoveTagsFromResource(w http.ResponseWriter, r *http.Request) {
	const action = "AmazonSSM.RemoveTagsFromResource"
	ps, ok := s.ssmParamStore(w)
	if !ok {
		return
	}
	var req ssmRemoveTagsRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.ssmValidation(w, r, action, err.Error())
		return
	}
	name, ok := s.ssmTagTarget(w, r, action, req.ResourceType, req.ResourceId)
	if !ok {
		return
	}
	if err := ps.UntagParameter(r.Context(), name, req.TagKeys); err != nil {
		errType := ssmTagError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: errType, AuditOrigin: s.auditOrigin(r)})
		return
	}
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, map[string]any{})
}

type ssmListTagsRequest struct {
	ResourceType string `json:"ResourceType"`
	ResourceId   string `json:"ResourceId"`
}

type ssmListTagsResponse struct {
	TagList []ssmTag `json:"TagList"`
}

func (s *Server) handleSSMListTagsForResource(w http.ResponseWriter, r *http.Request) {
	const action = "AmazonSSM.ListTagsForResource"
	ps, ok := s.ssmParamStore(w)
	if !ok {
		return
	}
	var req ssmListTagsRequest
	if err := decodeJSONBody(r, &req); err != nil {
		s.ssmValidation(w, r, action, err.Error())
		return
	}
	name, ok := s.ssmTagTarget(w, r, action, req.ResourceType, req.ResourceId)
	if !ok {
		return
	}
	tags, err := ps.ListParameterTags(r.Context(), name)
	if err != nil {
		errType := ssmTagError(w, err)
		s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "error", ErrorType: errType, AuditOrigin: s.auditOrigin(r)})
		return
	}
	out := make([]ssmTag, 0, len(tags))
	for _, t := range tags {
		out = append(out, ssmTag{Key: t.Key, Value: t.Value})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	s.recordAudit(r.Context(), store.AuditEvent{Action: action, Result: "ok", AuditOrigin: s.auditOrigin(r)})
	writeJSON(w, http.StatusOK, ssmListTagsResponse{TagList: out})
}
