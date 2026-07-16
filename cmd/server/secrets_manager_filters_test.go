package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestListSecretsAcceptsFiltersBody guards the Secrets Manager wire contract:
// every AWS SDK sends Filters on ListSecrets, and the request decoder rejects
// unknown fields. Without a Filters field, ListSecrets answered
//
//	InvalidParameterException: invalid JSON body: json: unknown field "Filters"
//
// which made External Secrets Operator's dataFrom.find unusable, so each app
// extracted a hand-seeded aggregate blob instead. Those blobs went stale
// silently — d76riders ran five days without EMERGENCY_MASTER_KEY on a green
// Ready=True.
func TestListSecretsAcceptsFiltersBody(t *testing.T) {
	// The shape External Secrets Operator actually sends.
	body := `{"Filters":[{"Key":"name","Values":["d76riders/prod/"]}],"MaxResults":100}`
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))

	var req listSecretsRequest
	if err := decodeOptionalJSONBody(r, &req); err != nil {
		t.Fatalf("decode rejected a valid ListSecrets body: %v", err)
	}
	if len(req.Filters) != 1 {
		t.Fatalf("got %d filters, want 1", len(req.Filters))
	}
	if req.Filters[0].Key != "name" {
		t.Fatalf("filter key = %q, want name", req.Filters[0].Key)
	}
	if got := req.Filters[0].Values; len(got) != 1 || got[0] != "d76riders/prod/" {
		t.Fatalf("filter values = %v", got)
	}
}

func TestListSecretsEmptyBodyStillDecodes(t *testing.T) {
	r := httptest.NewRequest("POST", "/", strings.NewReader(""))
	var req listSecretsRequest
	if err := decodeOptionalJSONBody(r, &req); err != nil {
		t.Fatalf("empty body should decode: %v", err)
	}
	if len(req.Filters) != 0 {
		t.Fatalf("expected no filters, got %v", req.Filters)
	}
}

func TestSecretMatchesFilters(t *testing.T) {
	secret := func(name string) secretMetadataRecord {
		return secretMetadataRecord{Name: name, Description: "rider stuff"}
	}

	cases := []struct {
		desc    string
		item    secretMetadataRecord
		filters []secretsFilter
		want    bool
	}{
		{
			desc:    "no filters matches everything",
			item:    secret("d76riders/prod/MAPBOX_TOKEN"),
			filters: nil,
			want:    true,
		},
		{
			desc:    "name is a prefix match, not exact",
			item:    secret("d76riders/prod/MAPBOX_TOKEN"),
			filters: []secretsFilter{{Key: "name", Values: []string{"d76riders/prod/"}}},
			want:    true,
		},
		{
			desc:    "a different project is excluded",
			item:    secret("varaperformance/prod/DATABASE_URL"),
			filters: []secretsFilter{{Key: "name", Values: []string{"d76riders/prod/"}}},
			want:    false,
		},
		{
			// The whole point of the trailing slash: the legacy blob sits at the
			// folder's own path and must not come back with its children.
			desc:    "the aggregate blob is not a child",
			item:    secret("d76riders/prod"),
			filters: []secretsFilter{{Key: "name", Values: []string{"d76riders/prod/"}}},
			want:    false,
		},
		{
			desc:    "prefix match is case-insensitive, as AWS does it",
			item:    secret("D76Riders/Prod/MAPBOX_TOKEN"),
			filters: []secretsFilter{{Key: "name", Values: []string{"d76riders/prod/"}}},
			want:    true,
		},
		{
			desc:    "values within one filter are OR'd",
			item:    secret("93rdavenue/prod/X"),
			filters: []secretsFilter{{Key: "name", Values: []string{"d76riders/", "93rdavenue/"}}},
			want:    true,
		},
		{
			desc: "separate filters are AND'd",
			item: secret("d76riders/prod/MAPBOX_TOKEN"),
			filters: []secretsFilter{
				{Key: "name", Values: []string{"d76riders/"}},
				{Key: "description", Values: []string{"nothing-like-this"}},
			},
			want: false,
		},
		{
			desc:    "a negated value excludes",
			item:    secret("d76riders/prod/MAPBOX_TOKEN"),
			filters: []secretsFilter{{Key: "name", Values: []string{"!d76riders/prod/MAPBOX"}}},
			want:    false,
		},
		{
			desc:    "negation leaves non-matches alone",
			item:    secret("d76riders/prod/DATABASE_URL"),
			filters: []secretsFilter{{Key: "name", Values: []string{"!d76riders/prod/MAPBOX"}}},
			want:    true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			if got := secretMatchesFilters(tc.item, tc.filters); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestValidateSecretsFilters(t *testing.T) {
	cases := []struct {
		desc    string
		filters []secretsFilter
		wantErr bool
	}{
		{"none is fine", nil, false},
		{"name is valid", []secretsFilter{{Key: "name", Values: []string{"x"}}}, false},
		// Rejected rather than ignored: dropping a filter would return secrets the
		// caller explicitly asked to exclude.
		{"unknown key is rejected", []secretsFilter{{Key: "primary-region", Values: []string{"us-east-1"}}}, true},
		{"empty key is rejected", []secretsFilter{{Key: "", Values: []string{"x"}}}, true},
		{"no values is rejected", []secretsFilter{{Key: "name"}}, true},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			err := validateSecretsFilters(tc.filters)
			if tc.wantErr && err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
