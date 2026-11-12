package config

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// parsePreviousWrappingKeys decodes KMS_PREVIOUS_WRAPPING_KEYS_B64: a
// comma-separated list of base64 32-byte keys that used to be the wrapping
// key. Empty entries are ignored. Errors never echo key material.
func parsePreviousWrappingKeys(raw string) ([][]byte, error) {
	var out [][]byte
	for i, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, err := base64.StdEncoding.DecodeString(part)
		if err != nil {
			return nil, fmt.Errorf("decode KMS_PREVIOUS_WRAPPING_KEYS_B64 entry %d: invalid base64", i+1)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("KMS_PREVIOUS_WRAPPING_KEYS_B64 entry %d must decode to exactly 32 bytes", i+1)
		}
		out = append(out, key)
	}
	return out, nil
}
