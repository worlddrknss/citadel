package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/worlddrknss/citadel/internal/store"
)

// ---- approval policies -------------------------------------------------------

func (s *Store) ListApprovalPolicies(ctx context.Context) ([]store.ApprovalPolicy, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT project, env, approvals_required, approver_roles_json, updated_at, updated_by
		 FROM sm_approval_policies WHERE account_id = $1 ORDER BY project, env`,
		s.accountForContext(ctx))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.ApprovalPolicy{}
	for rows.Next() {
		p, err := scanApprovalPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetApprovalPolicy(ctx context.Context, project, env string) (store.ApprovalPolicy, bool, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT project, env, approvals_required, approver_roles_json, updated_at, updated_by
		 FROM sm_approval_policies WHERE account_id = $1 AND project = $2 AND env = $3`,
		s.accountForContext(ctx), project, env)
	p, err := scanApprovalPolicy(row)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ApprovalPolicy{}, false, nil
	}
	if err != nil {
		return store.ApprovalPolicy{}, false, err
	}
	return p, true, nil
}

func (s *Store) PutApprovalPolicy(ctx context.Context, p store.ApprovalPolicy) error {
	acct := s.accountForContext(ctx)
	if p.ApprovalsRequired <= 0 {
		_, err := s.db.ExecContext(ctx, `DELETE FROM sm_approval_policies WHERE account_id = $1 AND project = $2 AND env = $3`, acct, p.Project, p.Env)
		return err
	}
	roles, err := json.Marshal(p.ApproverRoles)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO sm_approval_policies (account_id, project, env, approvals_required, approver_roles_json, updated_at, updated_by)
		 VALUES ($1, $2, $3, $4, $5, NOW(), $6)
		 ON CONFLICT (account_id, project, env) DO UPDATE SET approvals_required = EXCLUDED.approvals_required,
		   approver_roles_json = EXCLUDED.approver_roles_json, updated_at = NOW(), updated_by = EXCLUDED.updated_by`,
		acct, p.Project, p.Env, p.ApprovalsRequired, string(roles), p.UpdatedBy)
	return err
}

func scanApprovalPolicy(r rowScanner) (store.ApprovalPolicy, error) {
	var (
		p     store.ApprovalPolicy
		roles string
	)
	if err := r.Scan(&p.Project, &p.Env, &p.ApprovalsRequired, &roles, &p.UpdatedAt, &p.UpdatedBy); err != nil {
		return store.ApprovalPolicy{}, err
	}
	_ = json.Unmarshal([]byte(roles), &p.ApproverRoles)
	return p, nil
}

// ---- change requests ---------------------------------------------------------

const changeRequestColumns = `id, project, env, folder_path, item_key, requester, requester_role, title, comment, status,
	proposed_ciphertext, proposed_kms_key_id, proposed_length, target_kms_key_id, base_version_id,
	created_at, decided_by, decided_at, decision_comment`

func scanChangeRequest(r rowScanner) (store.ChangeRequestRecord, error) {
	var (
		cr        store.ChangeRequestRecord
		decidedAt sql.NullTime
	)
	if err := r.Scan(&cr.ID, &cr.Project, &cr.Env, &cr.Path, &cr.Key, &cr.Requester, &cr.RequesterRole, &cr.Title, &cr.Comment, &cr.Status,
		&cr.ProposedCiphertext, &cr.ProposedKMSKeyID, &cr.ProposedLength, &cr.TargetKMSKeyID, &cr.BaseVersionID,
		&cr.CreatedAt, &cr.DecidedBy, &decidedAt, &cr.DecisionComment); err != nil {
		return store.ChangeRequestRecord{}, err
	}
	if decidedAt.Valid {
		t := decidedAt.Time
		cr.DecidedAt = &t
	}
	return cr, nil
}

func (s *Store) CreateChangeRequest(ctx context.Context, cr store.ChangeRequestRecord) (store.ChangeRequestRecord, error) {
	if strings.TrimSpace(cr.ID) == "" {
		return store.ChangeRequestRecord{}, errors.New("change request id is required")
	}
	if cr.CreatedAt.IsZero() {
		cr.CreatedAt = time.Now().UTC()
	}
	cr.Status = store.ChangeRequestPending
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sm_change_requests (account_id, id, project, env, folder_path, item_key, requester, requester_role, title, comment, status,
			proposed_ciphertext, proposed_kms_key_id, proposed_length, target_kms_key_id, base_version_id, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
		s.accountForContext(ctx), cr.ID, cr.Project, cr.Env, cr.Path, cr.Key, cr.Requester, cr.RequesterRole, cr.Title, cr.Comment, cr.Status,
		cr.ProposedCiphertext, cr.ProposedKMSKeyID, cr.ProposedLength, cr.TargetKMSKeyID, cr.BaseVersionID, cr.CreatedAt)
	if err != nil {
		return store.ChangeRequestRecord{}, err
	}
	cr.Approvals = []store.ChangeRequestApproval{}
	return cr, nil
}

func (s *Store) GetChangeRequest(ctx context.Context, id string) (store.ChangeRequestRecord, error) {
	return s.getChangeRequest(ctx, s.db, s.accountForContext(ctx), id, false)
}

type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func (s *Store) getChangeRequest(ctx context.Context, q queryer, acct, id string, forUpdate bool) (store.ChangeRequestRecord, error) {
	query := `SELECT ` + changeRequestColumns + ` FROM sm_change_requests WHERE account_id = $1 AND id = $2`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	cr, err := scanChangeRequest(q.QueryRowContext(ctx, query, acct, id))
	if errors.Is(err, sql.ErrNoRows) {
		return store.ChangeRequestRecord{}, store.ErrChangeRequestNotFound
	}
	if err != nil {
		return store.ChangeRequestRecord{}, err
	}
	approvals, err := loadApprovals(ctx, q, acct, []string{id})
	if err != nil {
		return store.ChangeRequestRecord{}, err
	}
	cr.Approvals = approvals[id]
	if cr.Approvals == nil {
		cr.Approvals = []store.ChangeRequestApproval{}
	}
	return cr, nil
}

func loadApprovals(ctx context.Context, q queryer, acct string, ids []string) (map[string][]store.ChangeRequestApproval, error) {
	out := map[string][]store.ChangeRequestApproval{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := q.QueryContext(ctx,
		`SELECT request_id, username, comment, decided_at FROM sm_change_request_approvals
		 WHERE account_id = $1 AND request_id = ANY($2) ORDER BY decided_at ASC`,
		acct, pq.Array(ids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id string
			a  store.ChangeRequestApproval
		)
		if err := rows.Scan(&id, &a.Username, &a.Comment, &a.DecidedAt); err != nil {
			return nil, err
		}
		out[id] = append(out[id], a)
	}
	return out, rows.Err()
}

func (s *Store) ListChangeRequests(ctx context.Context) ([]store.ChangeRequestRecord, error) {
	acct := s.accountForContext(ctx)
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+changeRequestColumns+` FROM sm_change_requests WHERE account_id = $1 ORDER BY created_at DESC, id DESC`, acct)
	if err != nil {
		return nil, err
	}
	out := []store.ChangeRequestRecord{}
	ids := []string{}
	for rows.Next() {
		cr, err := scanChangeRequest(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, cr)
		ids = append(ids, cr.ID)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	approvals, err := loadApprovals(ctx, s.db, acct, ids)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Approvals = approvals[out[i].ID]
		if out[i].Approvals == nil {
			out[i].Approvals = []store.ChangeRequestApproval{}
		}
	}
	return out, nil
}

func (s *Store) AddChangeRequestApproval(ctx context.Context, id string, a store.ChangeRequestApproval) (store.ChangeRequestRecord, error) {
	acct := s.accountForContext(ctx)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return store.ChangeRequestRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()
	cr, err := s.getChangeRequest(ctx, tx, acct, id, true)
	if err != nil {
		return store.ChangeRequestRecord{}, err
	}
	if cr.Status != store.ChangeRequestPending {
		return store.ChangeRequestRecord{}, store.ErrChangeRequestDecided
	}
	for _, existing := range cr.Approvals {
		if existing.Username == a.Username {
			return store.ChangeRequestRecord{}, store.ErrAlreadyApproved
		}
	}
	if a.DecidedAt.IsZero() {
		a.DecidedAt = time.Now().UTC()
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO sm_change_request_approvals (account_id, request_id, username, comment, decided_at) VALUES ($1,$2,$3,$4,$5)`,
		acct, id, a.Username, a.Comment, a.DecidedAt); err != nil {
		return store.ChangeRequestRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return store.ChangeRequestRecord{}, err
	}
	cr.Approvals = append(cr.Approvals, a)
	return cr, nil
}

func (s *Store) TransitionChangeRequest(ctx context.Context, id, from, to, decidedBy, comment string) (store.ChangeRequestRecord, error) {
	acct := s.accountForContext(ctx)
	var (
		res sql.Result
		err error
	)
	if to == store.ChangeRequestPending {
		res, err = s.db.ExecContext(ctx,
			`UPDATE sm_change_requests SET status = $4, decided_by = '', decided_at = NULL, decision_comment = ''
			 WHERE account_id = $1 AND id = $2 AND status = $3`, acct, id, from, to)
	} else {
		res, err = s.db.ExecContext(ctx,
			`UPDATE sm_change_requests SET status = $4, decided_by = $5, decided_at = NOW(), decision_comment = $6
			 WHERE account_id = $1 AND id = $2 AND status = $3`, acct, id, from, to, decidedBy, comment)
	}
	if err != nil {
		return store.ChangeRequestRecord{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, gerr := s.GetChangeRequest(ctx, id); gerr != nil {
			return store.ChangeRequestRecord{}, gerr
		}
		return store.ChangeRequestRecord{}, store.ErrChangeRequestDecided
	}
	return s.GetChangeRequest(ctx, id)
}

// ---- settings ----------------------------------------------------------------

func (s *Store) GetSecretSettings(ctx context.Context) (store.SecretSettings, error) {
	var out store.SecretSettings
	err := s.db.QueryRowContext(ctx,
		`SELECT viewers_can_reveal, updated_at, updated_by FROM sm_account_settings WHERE account_id = $1`,
		s.accountForContext(ctx)).Scan(&out.ViewersCanReveal, &out.UpdatedAt, &out.UpdatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return store.SecretSettings{}, nil
	}
	return out, err
}

func (s *Store) PutSecretSettings(ctx context.Context, in store.SecretSettings) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sm_account_settings (account_id, viewers_can_reveal, updated_at, updated_by) VALUES ($1, $2, NOW(), $3)
		 ON CONFLICT (account_id) DO UPDATE SET viewers_can_reveal = EXCLUDED.viewers_can_reveal, updated_at = NOW(), updated_by = EXCLUDED.updated_by`,
		s.accountForContext(ctx), in.ViewersCanReveal, in.UpdatedBy)
	return err
}

// ---- lifecycle ---------------------------------------------------------------

func (s *Store) RenameSecret(ctx context.Context, oldName, newName string) (store.SecretMetadataRecord, error) {
	acct := s.accountForContext(ctx)
	meta, err := s.loadSecretMetadata(ctx, oldName)
	if err != nil {
		return store.SecretMetadataRecord{}, err
	}
	newName = strings.TrimSpace(newName)
	// The child tables' foreign keys cascade the new name (migration 0300).
	if _, err := s.db.ExecContext(ctx,
		`UPDATE sm_secrets SET name = $3, arn = $4, updated_at = NOW() WHERE account_id = $1 AND name = $2`,
		acct, meta.Name, newName, s.SecretARNForCtx(ctx, newName)); err != nil {
		return store.SecretMetadataRecord{}, mapSecretDBError(err)
	}
	return s.loadSecretMetadata(ctx, newName)
}

func (s *Store) PurgeExpiredSecrets(ctx context.Context, now time.Time) ([]store.PurgedSecret, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT account_id, name, kms_key_id FROM sm_secrets WHERE deleted_date IS NOT NULL AND deleted_date <= $1 ORDER BY deleted_date LIMIT 500`, now)
	if err != nil {
		return nil, err
	}
	var due []store.PurgedSecret
	for rows.Next() {
		var p store.PurgedSecret
		if err := rows.Scan(&p.AccountID, &p.Name, &p.KMSKeyID); err != nil {
			rows.Close()
			return nil, err
		}
		due = append(due, p)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	out := make([]store.PurgedSecret, 0, len(due))
	for _, p := range due {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return out, err
		}
		// Re-check under lock: a restore may have raced the scan.
		var still bool
		err = tx.QueryRowContext(ctx,
			`SELECT TRUE FROM sm_secrets WHERE account_id = $1 AND name = $2 AND deleted_date IS NOT NULL AND deleted_date <= $3 FOR UPDATE`,
			p.AccountID, p.Name, now).Scan(&still)
		if errors.Is(err, sql.ErrNoRows) {
			_ = tx.Rollback()
			continue
		}
		if err == nil {
			err = purgeSecretTx(ctx, tx, p.AccountID, p.Name)
		}
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			_ = tx.Rollback()
			return out, err
		}
		out = append(out, p)
	}
	return out, nil
}
