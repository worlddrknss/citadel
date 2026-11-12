package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
)

// awsError is the AWS JSON 1.1 error body. SDKs read the code from __type
// (or the X-Amzn-ErrorType header) and the message from "message".
type awsError struct {
	Type      string `json:"__type"`
	Message   string `json:"message"`
	RequestID string `json:"RequestId,omitempty"`
}

// awsProtocolCtxKey marks a request as AWS-protocol traffic (as opposed to
// the native /v1 API). Request decoding is lenient for AWS traffic: real SDKs,
// Terraform and the AWS CLI send members Citadel does not model, and AWS
// itself ignores unknown members. The native API stays strict.
type awsProtocolCtxKey struct{}

func withAWSProtocol(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), awsProtocolCtxKey{}, true))
}

func isAWSProtocol(r *http.Request) bool {
	v, _ := r.Context().Value(awsProtocolCtxKey{}).(bool)
	return v
}

// awsResponseWriter carries the request ID and service of an AWS-protocol
// request so that every response (success or error) gets x-amzn-RequestId and
// errors can be normalized per service without threading the request through
// every writeAWSJSONError call.
type awsResponseWriter struct {
	http.ResponseWriter
	requestID string
	service   string
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *awsResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// awsServiceFromTarget maps an X-Amz-Target prefix to a service name.
func awsServiceFromTarget(target string) string {
	prefix, _, _ := strings.Cut(target, ".")
	switch prefix {
	case "TrentService":
		return "kms"
	case "secretsmanager":
		return "secretsmanager"
	case "AmazonSSM":
		return "ssm"
	case "acm-pca", "ACMPrivateCA":
		return "acm-pca"
	case "acm", "CertificateManager":
		return "acm"
	}
	return ""
}

// newAWSRequestID returns a UUID-shaped request id like AWS's.
func newAWSRequestID() string {
	h := cryptoutil.RandomHex(16)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// beginAWSResponse stamps the response with a fresh x-amzn-RequestId and
// returns a writer that remembers it (and the service, for error mapping).
func beginAWSResponse(w http.ResponseWriter, service string) *awsResponseWriter {
	if aw, ok := w.(*awsResponseWriter); ok {
		if service != "" {
			aw.service = service
		}
		return aw
	}
	id := newAWSRequestID()
	w.Header().Set("x-amzn-RequestId", id)
	return &awsResponseWriter{ResponseWriter: w, requestID: id, service: service}
}

// awsRequestID returns the request id stamped by beginAWSResponse, if any.
func awsRequestID(w http.ResponseWriter) string {
	if aw, ok := w.(*awsResponseWriter); ok {
		return aw.requestID
	}
	return ""
}

// internalErrorCode is the per-service code for a server-side failure.
func internalErrorCode(service string) string {
	switch service {
	case "kms":
		return "KMSInternalException"
	case "secretsmanager":
		return "InternalServiceError"
	case "ssm":
		return "InternalServerError"
	default:
		return "InternalFailure"
	}
}

func decodeJSONBody(r *http.Request, target any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if !isAWSProtocol(r) {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(target); err != nil {
		if isAWSProtocol(r) && errors.Is(err, io.EOF) {
			// An absent body is an empty input structure; the handler's
			// required-member checks report what is actually missing.
			return nil
		}
		return fmt.Errorf("invalid JSON body: %w", sanitizeJSONError(err))
	}
	return nil
}

func decodeOptionalJSONBody(r *http.Request, target any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if !isAWSProtocol(r) {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(target); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("invalid JSON body: %w", sanitizeJSONError(err))
	}
	return nil
}

// sanitizeJSONError keeps decoder errors useful (which member had the wrong
// type) without echoing request content back.
func sanitizeJSONError(err error) error {
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		return fmt.Errorf("member %s has the wrong type", typeErr.Field)
	}
	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		return errors.New("malformed JSON")
	}
	return err
}

func normalizeListLimit(limit int) (int, error) {
	if limit == 0 {
		return 100, nil
	}
	if limit < 0 || limit > 1000 {
		return 0, errors.New("Limit must be between 1 and 1000")
	}
	return limit, nil
}

func paginateList[T any](items []T, marker string, limit int, idOf func(T) string) ([]T, string, bool, error) {
	start := 0
	if marker != "" {
		found := false
		for i, item := range items {
			if idOf(item) == marker {
				start = i + 1
				found = true
				break
			}
		}
		if !found {
			return nil, "", false, errors.New("Marker is invalid")
		}
	}
	if start >= len(items) {
		return []T{}, "", false, nil
	}
	end := start + limit
	if end >= len(items) {
		return items[start:], "", false, nil
	}
	nextMarker := idOf(items[end-1])
	return items[start:end], nextMarker, true, nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// writeAWSJSONError writes an AWS JSON error. For AWS-protocol requests the
// body carries the request id, and any 5xx is normalized to the service's
// internal-error code with a fixed message: the original text is logged, never
// sent, because it may carry driver or SQL detail.
func writeAWSJSONError(w http.ResponseWriter, status int, typ, msg string) {
	body := awsError{Type: typ, Message: msg}
	if aw, ok := w.(*awsResponseWriter); ok {
		body.RequestID = aw.requestID
		if status >= 500 {
			log.Printf("aws internal error request_id=%s service=%s type=%s: %s", aw.requestID, aw.service, typ, msg)
			body.Type = internalErrorCode(aw.service)
			body.Message = "An internal error occurred. Request ID: " + aw.requestID
		}
	} else if status >= 500 {
		log.Printf("internal error type=%s: %s", typ, msg)
		body.Message = "an internal error occurred"
	}
	w.Header().Set("X-Amzn-ErrorType", body.Type)
	writeJSON(w, status, body)
}
