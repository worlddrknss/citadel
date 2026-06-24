package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
)

// Parameter Store provides an AWS Systems Manager (SSM) Parameter Store
// compatible configuration surface. Parameters are hierarchical, slash-style
// paths (e.g. "/app/prod/db/password") and may be of type String, StringList,
// or SecureString. SecureString values are encrypted at rest with a KMS key
// (defaulting to the deployment's default key when none is supplied), mirroring
// the Secrets Manager ciphertext format so the existing crypto helpers can be
// reused.

var (
	errParameterNotFound = errors.New("parameter not found")
	errParameterExists   = errors.New("parameter already exists")
)

const (
	parameterTypeString       = "String"
	parameterTypeStringList   = "StringList"
	parameterTypeSecureString = "SecureString"
	parameterTierStandard     = "Standard"
	parameterTierAdvanced     = "Advanced"
)

// parameterRecord is the persisted form of a parameter. For SecureString the
// Value field holds the base64 ciphertext blob; for String/StringList it holds
// the plaintext value.
type parameterRecord struct {
	Name        string
	Type        string
	Value       string
	IsEncrypted bool
	KMSKeyID    string
	Tier        string
	Version     int64
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// parameterHistoryEntry captures a single historical version of a parameter.
type parameterHistoryEntry struct {
	Name        string
	Version     int64
	Type        string
	Value       string
	IsEncrypted bool
	KMSKeyID    string
	Tier        string
	Description string
	Labels      []string
	ModifiedAt  time.Time
}

type paramTag struct {
	Key   string
	Value string
}

// memParameter is the in-memory representation including history and tags.
type memParameter struct {
	rec     parameterRecord
	history []parameterHistoryEntry
	tags    []paramTag
}

// parameterStore is the persistence contract for Parameter Store. It is
// implemented by both dbStore and inMemoryStore and consumed via a type
// assertion (s.store.(parameterStore)) so the large keyStore interface stays
// unchanged.
type parameterStore interface {
	PutParameter(ctx context.Context, rec parameterRecord, overwrite bool) (parameterRecord, error)
	GetParameter(ctx context.Context, name string) (parameterRecord, error)
	ListParameters(ctx context.Context) ([]parameterRecord, error)
	DeleteParameter(ctx context.Context, name string) error
	GetParameterHistory(ctx context.Context, name string) ([]parameterHistoryEntry, error)
	LabelParameterVersion(ctx context.Context, name string, version int64, labels []string) ([]string, error)
	TagParameter(ctx context.Context, name string, tags []paramTag) error
	UntagParameter(ctx context.Context, name string, keys []string) error
	ListParameterTags(ctx context.Context, name string) ([]paramTag, error)
}

// normalizeParameterName canonicalizes an SSM-style parameter name to a single
// leading slash with validated path segments and no trailing slash.
func normalizeParameterName(name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", errors.New("parameter name is required")
	}
	// SSM allows a bare relative name (no leading slash) for a top-level
	// parameter; canonicalize everything to a leading slash.
	parts := strings.Split(strings.Trim(trimmed, "/"), "/")
	if len(parts) == 0 {
		return "", errors.New("parameter name is required")
	}
	for _, p := range parts {
		if !nativeSegmentRe.MatchString(p) {
			return "", errors.New("parameter name segments must match [A-Za-z0-9_.-]+")
		}
	}
	if len(parts) > 15 {
		return "", errors.New("parameter name hierarchy is too deep")
	}
	return "/" + strings.Join(parts, "/"), nil
}

func normalizeParameterType(t string) (string, error) {
	switch strings.TrimSpace(t) {
	case "", parameterTypeString:
		return parameterTypeString, nil
	case parameterTypeStringList:
		return parameterTypeStringList, nil
	case parameterTypeSecureString:
		return parameterTypeSecureString, nil
	default:
		return "", errors.New("Type must be String, StringList, or SecureString")
	}
}

func normalizeParameterTier(t string) string {
	if strings.TrimSpace(t) == parameterTierAdvanced {
		return parameterTierAdvanced
	}
	return parameterTierStandard
}

// ---- dbStore implementation -----------------------------------------------

func (s *dbStore) PutParameter(ctx context.Context, rec parameterRecord, overwrite bool) (parameterRecord, error) {
	acct := s.accountForContext(ctx)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return parameterRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var existingVersion int64
	err = tx.QueryRowContext(ctx,
		`SELECT version FROM ps_parameters WHERE account_id=$1 AND name=$2`,
		acct, rec.Name).Scan(&existingVersion)
	switch {
	case err == sql.ErrNoRows:
		existingVersion = 0
	case err != nil:
		return parameterRecord{}, err
	default:
		if !overwrite {
			return parameterRecord{}, errParameterExists
		}
	}

	now := time.Now().UTC()
	rec.Version = existingVersion + 1
	rec.UpdatedAt = now
	if existingVersion == 0 {
		rec.CreatedAt = now
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO ps_parameters (account_id, name, param_type, param_value, is_encrypted, kms_key_id, tier, version, description, created_at, updated_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
			acct, rec.Name, rec.Type, rec.Value, rec.IsEncrypted, rec.KMSKeyID, rec.Tier, rec.Version, rec.Description, now, now); err != nil {
			return parameterRecord{}, err
		}
	} else {
		if _, err := tx.ExecContext(ctx,
			`UPDATE ps_parameters SET param_type=$3, param_value=$4, is_encrypted=$5, kms_key_id=$6, tier=$7, version=$8, description=$9, updated_at=$10
			 WHERE account_id=$1 AND name=$2`,
			acct, rec.Name, rec.Type, rec.Value, rec.IsEncrypted, rec.KMSKeyID, rec.Tier, rec.Version, rec.Description, now); err != nil {
			return parameterRecord{}, err
		}
		// Preserve CreatedAt from the existing row for the returned record.
		_ = tx.QueryRowContext(ctx, `SELECT created_at FROM ps_parameters WHERE account_id=$1 AND name=$2`, acct, rec.Name).Scan(&rec.CreatedAt)
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO ps_parameter_history (account_id, name, version, param_type, param_value, is_encrypted, kms_key_id, tier, description, labels_json, modified_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'[]',$10)`,
		acct, rec.Name, rec.Version, rec.Type, rec.Value, rec.IsEncrypted, rec.KMSKeyID, rec.Tier, rec.Description, now); err != nil {
		return parameterRecord{}, err
	}

	if err := tx.Commit(); err != nil {
		return parameterRecord{}, err
	}
	return rec, nil
}

func (s *dbStore) GetParameter(ctx context.Context, name string) (parameterRecord, error) {
	acct := s.accountForContext(ctx)
	var rec parameterRecord
	err := s.db.QueryRowContext(ctx,
		`SELECT name, param_type, param_value, is_encrypted, kms_key_id, tier, version, description, created_at, updated_at
		 FROM ps_parameters WHERE account_id=$1 AND name=$2`,
		acct, name).Scan(&rec.Name, &rec.Type, &rec.Value, &rec.IsEncrypted, &rec.KMSKeyID, &rec.Tier, &rec.Version, &rec.Description, &rec.CreatedAt, &rec.UpdatedAt)
	if err == sql.ErrNoRows {
		return parameterRecord{}, errParameterNotFound
	}
	if err != nil {
		return parameterRecord{}, err
	}
	return rec, nil
}

func (s *dbStore) ListParameters(ctx context.Context) ([]parameterRecord, error) {
	cond, args := accountFilter(ctx, "account_id", 1)
	query := `SELECT name, param_type, param_value, is_encrypted, kms_key_id, tier, version, description, created_at, updated_at FROM ps_parameters`
	if cond != "" {
		query += " WHERE " + cond
	}
	query += " ORDER BY name"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []parameterRecord
	for rows.Next() {
		var rec parameterRecord
		if err := rows.Scan(&rec.Name, &rec.Type, &rec.Value, &rec.IsEncrypted, &rec.KMSKeyID, &rec.Tier, &rec.Version, &rec.Description, &rec.CreatedAt, &rec.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *dbStore) DeleteParameter(ctx context.Context, name string) error {
	acct := s.accountForContext(ctx)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `DELETE FROM ps_parameters WHERE account_id=$1 AND name=$2`, acct, name)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errParameterNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM ps_parameter_history WHERE account_id=$1 AND name=$2`, acct, name); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM ps_parameter_tags WHERE account_id=$1 AND name=$2`, acct, name); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *dbStore) GetParameterHistory(ctx context.Context, name string) ([]parameterHistoryEntry, error) {
	acct := s.accountForContext(ctx)
	rows, err := s.db.QueryContext(ctx,
		`SELECT name, version, param_type, param_value, is_encrypted, kms_key_id, tier, description, labels_json, modified_at
		 FROM ps_parameter_history WHERE account_id=$1 AND name=$2 ORDER BY version`,
		acct, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []parameterHistoryEntry
	for rows.Next() {
		var (
			e         parameterHistoryEntry
			labelsRaw string
		)
		if err := rows.Scan(&e.Name, &e.Version, &e.Type, &e.Value, &e.IsEncrypted, &e.KMSKeyID, &e.Tier, &e.Description, &labelsRaw, &e.ModifiedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(labelsRaw), &e.Labels)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		// Distinguish "no such parameter" from "no history".
		if _, err := s.GetParameter(ctx, name); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *dbStore) LabelParameterVersion(ctx context.Context, name string, version int64, labels []string) ([]string, error) {
	acct := s.accountForContext(ctx)
	if version == 0 {
		// Default to the latest version.
		if err := s.db.QueryRowContext(ctx, `SELECT version FROM ps_parameters WHERE account_id=$1 AND name=$2`, acct, name).Scan(&version); err != nil {
			if err == sql.ErrNoRows {
				return nil, errParameterNotFound
			}
			return nil, err
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	// Labels are unique per parameter; moving a label detaches it from any
	// other version first.
	for _, lbl := range labels {
		rows, err := tx.QueryContext(ctx, `SELECT version, labels_json FROM ps_parameter_history WHERE account_id=$1 AND name=$2`, acct, name)
		if err != nil {
			return nil, err
		}
		type verLabels struct {
			ver    int64
			labels []string
		}
		var all []verLabels
		for rows.Next() {
			var v int64
			var raw string
			if err := rows.Scan(&v, &raw); err != nil {
				rows.Close()
				return nil, err
			}
			var ls []string
			_ = json.Unmarshal([]byte(raw), &ls)
			all = append(all, verLabels{ver: v, labels: ls})
		}
		rows.Close()
		for _, vl := range all {
			if vl.ver == version {
				continue
			}
			filtered := removeLabel(vl.labels, lbl)
			if len(filtered) != len(vl.labels) {
				raw, _ := json.Marshal(filtered)
				if _, err := tx.ExecContext(ctx, `UPDATE ps_parameter_history SET labels_json=$3 WHERE account_id=$1 AND name=$2 AND version=$4`, acct, name, string(raw), vl.ver); err != nil {
					return nil, err
				}
			}
		}
	}

	var raw string
	err = tx.QueryRowContext(ctx, `SELECT labels_json FROM ps_parameter_history WHERE account_id=$1 AND name=$2 AND version=$3`, acct, name, version).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, errParameterNotFound
	}
	if err != nil {
		return nil, err
	}
	var current []string
	_ = json.Unmarshal([]byte(raw), &current)
	current = mergeLabels(current, labels)
	merged, _ := json.Marshal(current)
	if _, err := tx.ExecContext(ctx, `UPDATE ps_parameter_history SET labels_json=$3 WHERE account_id=$1 AND name=$2 AND version=$4`, acct, name, string(merged), version); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return current, nil
}

func (s *dbStore) TagParameter(ctx context.Context, name string, tags []paramTag) error {
	acct := s.accountForContext(ctx)
	if _, err := s.GetParameter(ctx, name); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, t := range tags {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO ps_parameter_tags (account_id, name, tag_key, tag_value) VALUES ($1,$2,$3,$4)
			 ON CONFLICT (account_id, name, tag_key) DO UPDATE SET tag_value=EXCLUDED.tag_value`,
			acct, name, t.Key, t.Value); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *dbStore) UntagParameter(ctx context.Context, name string, keys []string) error {
	acct := s.accountForContext(ctx)
	if _, err := s.GetParameter(ctx, name); err != nil {
		return err
	}
	for _, k := range keys {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM ps_parameter_tags WHERE account_id=$1 AND name=$2 AND tag_key=$3`, acct, name, k); err != nil {
			return err
		}
	}
	return nil
}

func (s *dbStore) ListParameterTags(ctx context.Context, name string) ([]paramTag, error) {
	acct := s.accountForContext(ctx)
	rows, err := s.db.QueryContext(ctx, `SELECT tag_key, tag_value FROM ps_parameter_tags WHERE account_id=$1 AND name=$2 ORDER BY tag_key`, acct, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []paramTag
	for rows.Next() {
		var t paramTag
		if err := rows.Scan(&t.Key, &t.Value); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ---- inMemoryStore implementation -----------------------------------------

func (s *inMemoryStore) PutParameter(ctx context.Context, rec parameterRecord, overwrite bool) (parameterRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.params == nil {
		s.params = map[string]*memParameter{}
	}
	now := time.Now().UTC()
	existing, ok := s.params[rec.Name]
	if ok {
		if !overwrite {
			return parameterRecord{}, errParameterExists
		}
		rec.Version = existing.rec.Version + 1
		rec.CreatedAt = existing.rec.CreatedAt
	} else {
		rec.Version = 1
		rec.CreatedAt = now
		existing = &memParameter{}
		s.params[rec.Name] = existing
	}
	rec.UpdatedAt = now
	existing.rec = rec
	existing.history = append(existing.history, parameterHistoryEntry{
		Name:        rec.Name,
		Version:     rec.Version,
		Type:        rec.Type,
		Value:       rec.Value,
		IsEncrypted: rec.IsEncrypted,
		KMSKeyID:    rec.KMSKeyID,
		Tier:        rec.Tier,
		Description: rec.Description,
		ModifiedAt:  now,
	})
	return rec, nil
}

func (s *inMemoryStore) GetParameter(ctx context.Context, name string) (parameterRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.params[name]
	if !ok {
		return parameterRecord{}, errParameterNotFound
	}
	return p.rec, nil
}

func (s *inMemoryStore) ListParameters(ctx context.Context) ([]parameterRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []parameterRecord
	for _, p := range s.params {
		out = append(out, p.rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *inMemoryStore) DeleteParameter(ctx context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.params[name]; !ok {
		return errParameterNotFound
	}
	delete(s.params, name)
	return nil
}

func (s *inMemoryStore) GetParameterHistory(ctx context.Context, name string) ([]parameterHistoryEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.params[name]
	if !ok {
		return nil, errParameterNotFound
	}
	out := make([]parameterHistoryEntry, len(p.history))
	copy(out, p.history)
	return out, nil
}

func (s *inMemoryStore) LabelParameterVersion(ctx context.Context, name string, version int64, labels []string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.params[name]
	if !ok {
		return nil, errParameterNotFound
	}
	if version == 0 {
		version = p.rec.Version
	}
	var target *parameterHistoryEntry
	for i := range p.history {
		if p.history[i].Version == version {
			target = &p.history[i]
			break
		}
	}
	if target == nil {
		return nil, errParameterNotFound
	}
	for _, lbl := range labels {
		for i := range p.history {
			if p.history[i].Version != version {
				p.history[i].Labels = removeLabel(p.history[i].Labels, lbl)
			}
		}
	}
	target.Labels = mergeLabels(target.Labels, labels)
	return target.Labels, nil
}

func (s *inMemoryStore) TagParameter(ctx context.Context, name string, tags []paramTag) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.params[name]
	if !ok {
		return errParameterNotFound
	}
	for _, t := range tags {
		replaced := false
		for i := range p.tags {
			if p.tags[i].Key == t.Key {
				p.tags[i].Value = t.Value
				replaced = true
				break
			}
		}
		if !replaced {
			p.tags = append(p.tags, t)
		}
	}
	return nil
}

func (s *inMemoryStore) UntagParameter(ctx context.Context, name string, keys []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.params[name]
	if !ok {
		return errParameterNotFound
	}
	for _, k := range keys {
		filtered := p.tags[:0]
		for _, t := range p.tags {
			if t.Key != k {
				filtered = append(filtered, t)
			}
		}
		p.tags = filtered
	}
	return nil
}

func (s *inMemoryStore) ListParameterTags(ctx context.Context, name string) ([]paramTag, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.params[name]
	if !ok {
		return nil, errParameterNotFound
	}
	out := make([]paramTag, len(p.tags))
	copy(out, p.tags)
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// ---- label helpers ---------------------------------------------------------

func mergeLabels(existing, add []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(existing)+len(add))
	for _, l := range existing {
		if _, ok := seen[l]; !ok {
			seen[l] = struct{}{}
			out = append(out, l)
		}
	}
	for _, l := range add {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if _, ok := seen[l]; !ok {
			seen[l] = struct{}{}
			out = append(out, l)
		}
	}
	return out
}

func removeLabel(labels []string, target string) []string {
	out := make([]string, 0, len(labels))
	for _, l := range labels {
		if l != target {
			out = append(out, l)
		}
	}
	return out
}
