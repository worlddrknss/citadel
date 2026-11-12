package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"

	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/store"
)

// Wrapping-key rotation.
//
// Everything Citadel stores encrypted at rest under the deployment wrapping
// key (KMS key material, access-key secrets, STS session secrets, ACME
// private keys) is unwrapped by trying, in order: the current wrapping key,
// each previous wrapping key (KMS_PREVIOUS_WRAPPING_KEYS_B64), then the
// pre-HKDF legacy derivation; each with the row ID bound as AAD and then
// without (material wrapped before AAD binding). New material is always
// wrapped with the current key. RewrapAll moves every row that is not yet
// "current key + AAD" onto it, after which the previous keys can be dropped.

type wrapCandidate struct {
	key []byte
	aad bool
}

func (s *Store) wrapCandidates() []wrapCandidate {
	out := []wrapCandidate{{s.wrappingKey, true}, {s.wrappingKey, false}}
	for _, k := range s.previousWrappingKeys {
		if len(k) == 32 {
			out = append(out, wrapCandidate{k, true}, wrapCandidate{k, false})
		}
	}
	if len(s.legacyWrappingKey) == 32 {
		out = append(out, wrapCandidate{s.legacyWrappingKey, true}, wrapCandidate{s.legacyWrappingKey, false})
	}
	return out
}

func (s *Store) unwrapKeyMaterial(keyID, wrappedB64, nonceB64 string) ([]byte, error) {
	out, _, err := s.unwrapWithStatus(keyID, wrappedB64, nonceB64)
	return out, err
}

// unwrapWithStatus unwraps and reports whether the blob is already in the
// canonical form (current wrapping key, ID bound as AAD).
func (s *Store) unwrapWithStatus(keyID, wrappedB64, nonceB64 string) ([]byte, bool, error) {
	if len(s.wrappingKey) != 32 {
		return nil, false, errors.New("wrapping key is not configured")
	}
	wrapped, err := base64.StdEncoding.DecodeString(wrappedB64)
	if err != nil {
		return nil, false, err
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, false, err
	}
	blob := append(append(make([]byte, 0, len(nonce)+len(wrapped)), nonce...), wrapped...)
	for i, c := range s.wrapCandidates() {
		var aad []byte
		if c.aad {
			aad = []byte(keyID)
		}
		if out, err := cryptoutil.GCMOpen(c.key, blob, aad); err == nil {
			return out, i == 0, nil
		}
	}
	return nil, false, errors.New("unwrap failed: no configured wrapping key opens this material")
}

// rewrapTarget describes one table of wrapped values.
type rewrapTarget struct {
	table      string
	idCol      string // primary key column
	secondCol  string // second primary key column ("" when single)
	aadExpr    string // SQL expression for the AAD the value is bound to
	wrappedCol string
	nonceCol   string
}

var rewrapTargets = []rewrapTarget{
	{table: "kms_keys", idCol: "id", aadExpr: "id", wrappedCol: "wrapped_key_b64", nonceCol: "key_nonce_b64"},
	{table: "kms_key_materials", idCol: "key_id", secondCol: "material_id", aadExpr: "key_id || '#' || material_id", wrappedCol: "wrapped_b64", nonceCol: "nonce_b64"},
	{table: "iam_access_keys", idCol: "access_key_id", aadExpr: "access_key_id", wrappedCol: "secret_wrapped_b64", nonceCol: "secret_nonce_b64"},
	{table: "sts_sessions", idCol: "access_key_id", aadExpr: "access_key_id", wrappedCol: "secret_wrapped_b64", nonceCol: "secret_nonce_b64"},
	{table: "acme_le_accounts", idCol: "id", aadExpr: "id", wrappedCol: "account_key_wrapped_b64", nonceCol: "account_key_nonce_b64"},
	{table: "acme_le_certificates", idCol: "cert_id", aadExpr: "cert_id", wrappedCol: "key_wrapped_b64", nonceCol: "key_nonce_b64"},
}

// RewrapAll re-wraps every stored value that is not yet wrapped with the
// current wrapping key (with its ID as AAD). Each update is conditional on
// the ciphertext being unchanged, so it is safe to run alongside normal
// traffic and on several replicas at once. Values no configured key can open
// are counted as failed and left untouched.
func (s *Store) RewrapAll(ctx context.Context) (store.RewrapReport, error) {
	var report store.RewrapReport
	for _, t := range rewrapTargets {
		if err := s.rewrapTable(ctx, t, &report); err != nil {
			return report, fmt.Errorf("rewrap %s: %w", t.table, err)
		}
	}
	return report, nil
}

func (s *Store) rewrapTable(ctx context.Context, t rewrapTarget, report *store.RewrapReport) error {
	second := "''"
	if t.secondCol != "" {
		second = t.secondCol
	}
	// Identifiers here come from the fixed rewrapTargets table, never from input.
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(
		`SELECT %s, %s, %s, %s, %s FROM %s WHERE %s <> '' AND %s <> ''`,
		t.idCol, second, t.aadExpr, t.wrappedCol, t.nonceCol, t.table, t.wrappedCol, t.nonceCol))
	if err != nil {
		return err
	}
	type row struct{ id, second, aad, wrapped, nonce string }
	var pending []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.second, &r.aad, &r.wrapped, &r.nonce); err != nil {
			rows.Close()
			return err
		}
		pending = append(pending, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	secondCond := "$4 = ''"
	if t.secondCol != "" {
		secondCond = t.secondCol + " = $4"
	}
	update := fmt.Sprintf(`UPDATE %s SET %s = $2, %s = $3 WHERE %s = $1 AND %s AND %s = $5 AND %s = $6`,
		t.table, t.wrappedCol, t.nonceCol, t.idCol, secondCond, t.wrappedCol, t.nonceCol)
	for _, r := range pending {
		report.Scanned++
		raw, current, err := s.unwrapWithStatus(r.aad, r.wrapped, r.nonce)
		if err != nil {
			report.Failed++
			slog.Warn("rewrap: cannot unwrap with any configured wrapping key", "table", t.table, "row", r.id)
			continue
		}
		if current {
			continue
		}
		wrapped, nonce, err := s.wrapKeyMaterial(r.aad, raw)
		if err != nil {
			return err
		}
		res, err := s.db.ExecContext(ctx, update, r.id, wrapped, nonce, r.second, r.wrapped, r.nonce)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			// Changed underneath us (another replica re-wrapped it, or the
			// row was rewritten); the next pass will see the new value.
			continue
		}
		report.Rewrapped++
		switch t.table {
		case "kms_keys", "kms_key_materials":
			report.KeyMaterial++
		case "iam_access_keys":
			report.AccessKeySecrets++
		case "sts_sessions":
			report.STSSessionSecrets++
		default:
			report.ACMEKeys++
		}
	}
	return nil
}
