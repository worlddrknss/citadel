package main

import (
	"context"
	"net/http"
	"sort"
	"strings"
)

// AWS Systems Manager (SSM) Parameter Store compatibility facade. These
// handlers are dispatched from handleKMS on the X-Amz-Target header
// (AmazonSSM.*) after SigV4 authentication, mirroring the KMS and Secrets
// Manager facades. They translate the AWS JSON wire shapes to and from the
// shared parameterStore layer so existing AWS SDKs and tooling (e.g. the
// External Secrets Operator) work unchanged.

func (s *server) parameterARN(ctx context.Context, name string) string {
	region, acct := s.store.DeploymentIdentity()
	if a, ok := callerAccountFromContext(ctx); ok {
		acct = a
	}
	return arnFor("ssm", region, acct, "parameter"+name)
}

// ssmParamStore resolves the parameter persistence layer or writes an AWS error.
func (s *server) ssmParamStore(w http.ResponseWriter) (parameterStore, bool) {
	ps, ok := s.paramStore()
	if !ok {
		writeAWSJSONError(w, http.StatusInternalServerError, "InternalServerError", "parameter store is not available")
		return nil, false
	}
	return ps, true
}

func ssmParameterError(w http.ResponseWriter, err error) {
	switch classifyParameterError(err) {
	case "ParameterNotFound":
		writeAWSJSONError(w, http.StatusBadRequest, "ParameterNotFound", "parameter not found")
	case "ParameterAlreadyExists":
		writeAWSJSONError(w, http.StatusBadRequest, "ParameterAlreadyExists", "the parameter already exists; use Overwrite to update")
	default:
		writeAWSJSONError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
	}
}

// ---- wire shapes -----------------------------------------------------------

type ssmTag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

type ssmParameter struct {
	Name             string        `json:"Name"`
	Type             string        `json:"Type"`
	Value            string        `json:"Value"`
	Version          int64         `json:"Version"`
	LastModifiedDate *awsTimestamp `json:"LastModifiedDate,omitempty"`
	ARN              string        `json:"ARN"`
	DataType         string        `json:"DataType"`
}

type ssmParameterMetadata struct {
	Name             string        `json:"Name"`
	Type             string        `json:"Type"`
	Tier             string        `json:"Tier"`
	Version          int64         `json:"Version"`
	Description      string        `json:"Description,omitempty"`
	KeyId            string        `json:"KeyId,omitempty"`
	LastModifiedDate *awsTimestamp `json:"LastModifiedDate,omitempty"`
	DataType         string        `json:"DataType"`
}

// ssmValueForResponse returns the value to surface for a record, decrypting
// SecureString only when requested.
func (s *server) ssmValueForResponse(ctx context.Context, rec parameterRecord, withDecryption bool) string {
	if !rec.IsEncrypted {
		return rec.Value
	}
	if !withDecryption {
		return rec.Value
	}
	plain, err := s.decryptParameterValue(ctx, rec.KMSKeyID, rec.Value)
	if err != nil {
		return ""
	}
	return plain
}

func (s *server) ssmParameterFrom(ctx context.Context, rec parameterRecord, withDecryption bool) ssmParameter {
	ts := awsTimestamp(rec.UpdatedAt)
	return ssmParameter{
		Name:             rec.Name,
		Type:             rec.Type,
		Value:            s.ssmValueForResponse(ctx, rec, withDecryption),
		Version:          rec.Version,
		LastModifiedDate: &ts,
		ARN:              s.parameterARN(ctx, rec.Name),
		DataType:         "text",
	}
}

// ---- PutParameter ----------------------------------------------------------

type ssmPutParameterRequest struct {
	Name        string   `json:"Name"`
	Value       string   `json:"Value"`
	Type        string   `json:"Type"`
	KeyId       string   `json:"KeyId"`
	Tier        string   `json:"Tier"`
	Description string   `json:"Description"`
	Overwrite   bool     `json:"Overwrite"`
	Tags        []ssmTag `json:"Tags"`
}

type ssmPutParameterResponse struct {
	Version int64  `json:"Version"`
	Tier    string `json:"Tier"`
}

func (s *server) handleSSMPutParameter(w http.ResponseWriter, r *http.Request) {
	const action = "AmazonSSM.PutParameter"
	ps, ok := s.ssmParamStore(w)
	if !ok {
		return
	}
	var req ssmPutParameterRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		return
	}
	rec, err := s.buildParameterRecord(r.Context(), req.Name, req.Type, req.Value, req.KeyId, req.Tier, req.Description)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: "ValidationException", Actor: r.RemoteAddr})
		return
	}
	saved, err := ps.PutParameter(r.Context(), rec, req.Overwrite)
	if err != nil {
		ssmParameterError(w, err)
		s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: rec.KMSKeyID, Result: "error", ErrorType: classifyParameterError(err), Actor: r.RemoteAddr})
		return
	}
	if len(req.Tags) > 0 {
		tags := make([]paramTag, 0, len(req.Tags))
		for _, t := range req.Tags {
			tags = append(tags, paramTag{Key: t.Key, Value: t.Value})
		}
		_ = ps.TagParameter(r.Context(), saved.Name, tags)
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: saved.KMSKeyID, Result: "ok", Actor: r.RemoteAddr})
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

func (s *server) handleSSMGetParameter(w http.ResponseWriter, r *http.Request) {
	const action = "AmazonSSM.GetParameter"
	ps, ok := s.ssmParamStore(w)
	if !ok {
		return
	}
	var req ssmGetParameterRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	name, err := normalizeParameterName(req.Name)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	rec, err := ps.GetParameter(r.Context(), name)
	if err != nil {
		ssmParameterError(w, err)
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: classifyParameterError(err), Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, KeyID: rec.KMSKeyID, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, ssmGetParameterResponse{Parameter: s.ssmParameterFrom(r.Context(), rec, req.WithDecryption)})
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

func (s *server) handleSSMGetParameters(w http.ResponseWriter, r *http.Request) {
	const action = "AmazonSSM.GetParameters"
	ps, ok := s.ssmParamStore(w)
	if !ok {
		return
	}
	var req ssmGetParametersRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	resp := ssmGetParametersResponse{Parameters: []ssmParameter{}, InvalidParameters: []string{}}
	for _, raw := range req.Names {
		name, err := normalizeParameterName(raw)
		if err != nil {
			resp.InvalidParameters = append(resp.InvalidParameters, raw)
			continue
		}
		rec, err := ps.GetParameter(r.Context(), name)
		if err != nil {
			resp.InvalidParameters = append(resp.InvalidParameters, raw)
			continue
		}
		resp.Parameters = append(resp.Parameters, s.ssmParameterFrom(r.Context(), rec, req.WithDecryption))
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, resp)
}

// ---- GetParametersByPath ---------------------------------------------------

type ssmGetParametersByPathRequest struct {
	Path           string `json:"Path"`
	Recursive      bool   `json:"Recursive"`
	WithDecryption bool   `json:"WithDecryption"`
	MaxResults     int    `json:"MaxResults"`
	NextToken      string `json:"NextToken"`
}

type ssmGetParametersByPathResponse struct {
	Parameters []ssmParameter `json:"Parameters"`
	NextToken  string         `json:"NextToken,omitempty"`
}

func (s *server) handleSSMGetParametersByPath(w http.ResponseWriter, r *http.Request) {
	const action = "AmazonSSM.GetParametersByPath"
	ps, ok := s.ssmParamStore(w)
	if !ok {
		return
	}
	var req ssmGetParametersByPathRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	path, err := normalizeParameterName(req.Path)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	recs, err := ps.ListParameters(r.Context())
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	prefix := strings.TrimSuffix(path, "/") + "/"
	out := []ssmParameter{}
	for _, rec := range recs {
		if !strings.HasPrefix(rec.Name, prefix) {
			continue
		}
		rest := strings.TrimPrefix(rec.Name, prefix)
		if !req.Recursive && strings.Contains(rest, "/") {
			continue
		}
		out = append(out, s.ssmParameterFrom(r.Context(), rec, req.WithDecryption))
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, ssmGetParametersByPathResponse{Parameters: out})
}

// ---- DeleteParameter / DeleteParameters ------------------------------------

type ssmDeleteParameterRequest struct {
	Name string `json:"Name"`
}

func (s *server) handleSSMDeleteParameter(w http.ResponseWriter, r *http.Request) {
	const action = "AmazonSSM.DeleteParameter"
	ps, ok := s.ssmParamStore(w)
	if !ok {
		return
	}
	var req ssmDeleteParameterRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	name, err := normalizeParameterName(req.Name)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if err := ps.DeleteParameter(r.Context(), name); err != nil {
		ssmParameterError(w, err)
		s.recordAudit(r.Context(), auditEvent{Action: action, Result: "error", ErrorType: classifyParameterError(err), Actor: r.RemoteAddr})
		return
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, map[string]any{})
}

type ssmDeleteParametersRequest struct {
	Names []string `json:"Names"`
}

type ssmDeleteParametersResponse struct {
	DeletedParameters []string `json:"DeletedParameters"`
	InvalidParameters []string `json:"InvalidParameters"`
}

func (s *server) handleSSMDeleteParameters(w http.ResponseWriter, r *http.Request) {
	const action = "AmazonSSM.DeleteParameters"
	ps, ok := s.ssmParamStore(w)
	if !ok {
		return
	}
	var req ssmDeleteParametersRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	resp := ssmDeleteParametersResponse{DeletedParameters: []string{}, InvalidParameters: []string{}}
	for _, raw := range req.Names {
		name, err := normalizeParameterName(raw)
		if err != nil {
			resp.InvalidParameters = append(resp.InvalidParameters, raw)
			continue
		}
		if err := ps.DeleteParameter(r.Context(), name); err != nil {
			resp.InvalidParameters = append(resp.InvalidParameters, raw)
			continue
		}
		resp.DeletedParameters = append(resp.DeletedParameters, name)
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, resp)
}

// ---- DescribeParameters ----------------------------------------------------

type ssmDescribeParametersResponse struct {
	Parameters []ssmParameterMetadata `json:"Parameters"`
	NextToken  string                 `json:"NextToken,omitempty"`
}

func (s *server) handleSSMDescribeParameters(w http.ResponseWriter, r *http.Request) {
	const action = "AmazonSSM.DescribeParameters"
	ps, ok := s.ssmParamStore(w)
	if !ok {
		return
	}
	recs, err := ps.ListParameters(r.Context())
	if err != nil {
		writeAWSJSONError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	out := make([]ssmParameterMetadata, 0, len(recs))
	for _, rec := range recs {
		ts := awsTimestamp(rec.UpdatedAt)
		out = append(out, ssmParameterMetadata{
			Name:             rec.Name,
			Type:             rec.Type,
			Tier:             rec.Tier,
			Version:          rec.Version,
			Description:      rec.Description,
			KeyId:            rec.KMSKeyID,
			LastModifiedDate: &ts,
			DataType:         "text",
		})
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, ssmDescribeParametersResponse{Parameters: out})
}

// ---- GetParameterHistory ---------------------------------------------------

type ssmGetParameterHistoryRequest struct {
	Name           string `json:"Name"`
	WithDecryption bool   `json:"WithDecryption"`
}

type ssmParameterHistoryEntry struct {
	Name             string        `json:"Name"`
	Type             string        `json:"Type"`
	Value            string        `json:"Value"`
	Version          int64         `json:"Version"`
	Tier             string        `json:"Tier"`
	Description      string        `json:"Description,omitempty"`
	KeyId            string        `json:"KeyId,omitempty"`
	Labels           []string      `json:"Labels"`
	LastModifiedDate *awsTimestamp `json:"LastModifiedDate,omitempty"`
	DataType         string        `json:"DataType"`
}

type ssmGetParameterHistoryResponse struct {
	Parameters []ssmParameterHistoryEntry `json:"Parameters"`
	NextToken  string                     `json:"NextToken,omitempty"`
}

func (s *server) handleSSMGetParameterHistory(w http.ResponseWriter, r *http.Request) {
	const action = "AmazonSSM.GetParameterHistory"
	ps, ok := s.ssmParamStore(w)
	if !ok {
		return
	}
	var req ssmGetParameterHistoryRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	name, err := normalizeParameterName(req.Name)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	history, err := ps.GetParameterHistory(r.Context(), name)
	if err != nil {
		ssmParameterError(w, err)
		return
	}
	out := make([]ssmParameterHistoryEntry, 0, len(history))
	for _, h := range history {
		value := h.Value
		if h.IsEncrypted && req.WithDecryption {
			if plain, derr := s.decryptParameterValue(r.Context(), h.KMSKeyID, h.Value); derr == nil {
				value = plain
			}
		}
		labels := h.Labels
		if labels == nil {
			labels = []string{}
		}
		ts := awsTimestamp(h.ModifiedAt)
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
		})
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, ssmGetParameterHistoryResponse{Parameters: out})
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

func (s *server) handleSSMLabelParameterVersion(w http.ResponseWriter, r *http.Request) {
	const action = "AmazonSSM.LabelParameterVersion"
	ps, ok := s.ssmParamStore(w)
	if !ok {
		return
	}
	var req ssmLabelParameterVersionRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	name, err := normalizeParameterName(req.Name)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if _, err := ps.LabelParameterVersion(r.Context(), name, req.ParameterVersion, req.Labels); err != nil {
		ssmParameterError(w, err)
		return
	}
	version := req.ParameterVersion
	if version == 0 {
		if rec, gerr := ps.GetParameter(r.Context(), name); gerr == nil {
			version = rec.Version
		}
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, ssmLabelParameterVersionResponse{InvalidLabels: []string{}, ParameterVersion: version})
}

// ---- Tags ------------------------------------------------------------------

type ssmAddTagsRequest struct {
	ResourceType string   `json:"ResourceType"`
	ResourceId   string   `json:"ResourceId"`
	Tags         []ssmTag `json:"Tags"`
}

func (s *server) handleSSMAddTagsToResource(w http.ResponseWriter, r *http.Request) {
	const action = "AmazonSSM.AddTagsToResource"
	ps, ok := s.ssmParamStore(w)
	if !ok {
		return
	}
	var req ssmAddTagsRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	name, err := normalizeParameterName(req.ResourceId)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	tags := make([]paramTag, 0, len(req.Tags))
	for _, t := range req.Tags {
		tags = append(tags, paramTag{Key: t.Key, Value: t.Value})
	}
	if err := ps.TagParameter(r.Context(), name, tags); err != nil {
		ssmParameterError(w, err)
		return
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, map[string]any{})
}

type ssmRemoveTagsRequest struct {
	ResourceType string   `json:"ResourceType"`
	ResourceId   string   `json:"ResourceId"`
	TagKeys      []string `json:"TagKeys"`
}

func (s *server) handleSSMRemoveTagsFromResource(w http.ResponseWriter, r *http.Request) {
	const action = "AmazonSSM.RemoveTagsFromResource"
	ps, ok := s.ssmParamStore(w)
	if !ok {
		return
	}
	var req ssmRemoveTagsRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	name, err := normalizeParameterName(req.ResourceId)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	if err := ps.UntagParameter(r.Context(), name, req.TagKeys); err != nil {
		ssmParameterError(w, err)
		return
	}
	s.recordAudit(r.Context(), auditEvent{Action: action, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, map[string]any{})
}

type ssmListTagsRequest struct {
	ResourceType string `json:"ResourceType"`
	ResourceId   string `json:"ResourceId"`
}

type ssmListTagsResponse struct {
	TagList []ssmTag `json:"TagList"`
}

func (s *server) handleSSMListTagsForResource(w http.ResponseWriter, r *http.Request) {
	const action = "AmazonSSM.ListTagsForResource"
	ps, ok := s.ssmParamStore(w)
	if !ok {
		return
	}
	var req ssmListTagsRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	name, err := normalizeParameterName(req.ResourceId)
	if err != nil {
		writeAWSJSONError(w, http.StatusBadRequest, "ValidationException", err.Error())
		return
	}
	tags, err := ps.ListParameterTags(r.Context(), name)
	if err != nil {
		ssmParameterError(w, err)
		return
	}
	out := make([]ssmTag, 0, len(tags))
	for _, t := range tags {
		out = append(out, ssmTag{Key: t.Key, Value: t.Value})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	s.recordAudit(r.Context(), auditEvent{Action: action, Result: "ok", Actor: r.RemoteAddr})
	writeJSON(w, http.StatusOK, ssmListTagsResponse{TagList: out})
}
