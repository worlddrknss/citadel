package main

import (
	"encoding/json"
	"testing"
	"time"
)

// TestAWSTimestampMarshalsAsNumber guards against regressing the Secrets Manager
// wire format: AWS SDK clients (including External Secrets Operator) deserialize
// timestamp fields as JSON numbers (epoch seconds) and reject the RFC3339 string
// that time.Time's default marshaler emits.
func TestAWSTimestampMarshalsAsNumber(t *testing.T) {
	ts := time.Date(2017, 11, 1, 0, 0, 0, 0, time.UTC) // 1.5092352e9

	b, err := json.Marshal(awsTimestamp(ts))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var num float64
	if err := json.Unmarshal(b, &num); err != nil {
		t.Fatalf("expected a JSON number, got %q: %v", b, err)
	}
	if want := float64(ts.Unix()); num != want {
		t.Fatalf("epoch mismatch: got %v want %v", num, want)
	}
}

// TestGetSecretValueResponseTimestampIsNumber verifies the full response struct
// (the field that broke ESO) serializes CreatedDate as a number, not a string.
func TestGetSecretValueResponseTimestampIsNumber(t *testing.T) {
	resp := getSecretValueResponse{
		ARN:         "arn:aws:secretsmanager:us-west-2:348107687147:secret:eso-kms-test/demo",
		Name:        "eso-kms-test/demo",
		VersionID:   "v1",
		CreatedDate: awsTimestamp(time.Now().UTC()),
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	raw, ok := generic["CreatedDate"]
	if !ok {
		t.Fatalf("CreatedDate missing from response: %s", b)
	}
	if len(raw) > 0 && raw[0] == '"' {
		t.Fatalf("CreatedDate serialized as a string, want number: %s", raw)
	}
	var num float64
	if err := json.Unmarshal(raw, &num); err != nil {
		t.Fatalf("CreatedDate is not a JSON number (%s): %v", raw, err)
	}
}

// TestAWSTimestampZeroMarshalsNull ensures a zero time renders as null rather
// than a misleading negative epoch number.
func TestAWSTimestampZeroMarshalsNull(t *testing.T) {
	b, err := json.Marshal(awsTimestamp(time.Time{}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != "null" {
		t.Fatalf("zero timestamp: got %s want null", b)
	}
}
