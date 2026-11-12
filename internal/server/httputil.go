package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
)

type awsError struct {
	Type    string `json:"__type"`
	Message string `json:"message"`
}

func withRequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s target=%s", r.Method, r.URL.Path, r.Header.Get("X-Amz-Target"))
		next.ServeHTTP(w, r)
	})
}

func decodeJSONBody(r *http.Request, target any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

func decodeOptionalJSONBody(r *http.Request, target any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
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

func writeAWSJSONError(w http.ResponseWriter, status int, typ, msg string) {
	writeJSON(w, status, awsError{Type: typ, Message: msg})
}
