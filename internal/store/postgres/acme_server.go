package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/lib/pq"

	"github.com/worlddrknss/citadel/internal/acme"
)

// ACMEServerStore returns a PostgreSQL implementation of acme.Store for
// Citadel's own ACME server, shared by every replica using this database.
func (s *Store) ACMEServerStore() acme.Store {
	return &acmeServerStore{db: s.db}
}

// acmeServerStore implements acme.Store. Each object is stored as JSON next
// to the columns used for lookups; updates compare-and-swap on version.
type acmeServerStore struct {
	db *sql.DB

	pruneMu   sync.Mutex
	lastPrune time.Time
}

var _ acme.Store = (*acmeServerStore)(nil)

func isUniqueViolation(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "23505"
}

func (a *acmeServerStore) AddNonce(ctx context.Context, nonce string, expires time.Time) error {
	if _, err := a.db.ExecContext(ctx, `INSERT INTO acme_srv_nonces (nonce, expires_at) VALUES ($1, $2)`, nonce, expires); err != nil {
		return fmt.Errorf("insert nonce: %w", err)
	}
	a.pruneMu.Lock()
	due := time.Since(a.lastPrune) > time.Minute
	if due {
		a.lastPrune = time.Now()
	}
	a.pruneMu.Unlock()
	if due {
		if _, err := a.db.ExecContext(ctx, `DELETE FROM acme_srv_nonces WHERE expires_at < NOW()`); err != nil {
			return fmt.Errorf("prune nonces: %w", err)
		}
	}
	return nil
}

func (a *acmeServerStore) ConsumeNonce(ctx context.Context, nonce string, now time.Time) (bool, error) {
	var expires time.Time
	err := a.db.QueryRowContext(ctx, `DELETE FROM acme_srv_nonces WHERE nonce = $1 RETURNING expires_at`, nonce).Scan(&expires)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("consume nonce: %w", err)
	}
	return !now.After(expires), nil
}

// casUpdate runs an UPDATE guarded by "version = $old" and maps zero rows to
// ErrNotFound or ErrStale.
func (a *acmeServerStore) casUpdate(ctx context.Context, table, id string, res sql.Result, err error) error {
	if err != nil {
		if isUniqueViolation(err) {
			return acme.ErrDuplicate
		}
		return fmt.Errorf("update %s: %w", table, err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return nil
	}
	var one int
	switch err := a.db.QueryRowContext(ctx, `SELECT 1 FROM `+table+` WHERE id = $1`, id).Scan(&one); {
	case errors.Is(err, sql.ErrNoRows):
		return acme.ErrNotFound
	case err != nil:
		return fmt.Errorf("check %s: %w", table, err)
	}
	return acme.ErrStale
}

func decodeRow[T any](data []byte, version int64, err error) (*T, error) {
	if errors.Is(err, sql.ErrNoRows) {
		return nil, acme.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("decode acme object: %w", err)
	}
	setVersion(&v, version)
	return &v, nil
}

func setVersion(v any, version int64) {
	switch o := v.(type) {
	case *acme.Account:
		o.Version = version
	case *acme.Order:
		o.Version = version
	case *acme.Authorization:
		o.Version = version
	case *acme.Certificate:
		o.Version = version
	}
}

func (a *acmeServerStore) CreateAccount(ctx context.Context, acct *acme.Account) error {
	data, err := json.Marshal(acct)
	if err != nil {
		return err
	}
	_, err = a.db.ExecContext(ctx, `
INSERT INTO acme_srv_accounts (id, thumbprint, account_ref, data, version, created_at) VALUES ($1, $2, $3, $4, 1, $5)`,
		acct.ID, acct.KeyThumbprint, acct.AccountRef, data, acct.CreatedAt)
	if isUniqueViolation(err) {
		return acme.ErrDuplicate
	}
	if err != nil {
		return fmt.Errorf("insert acme account: %w", err)
	}
	acct.Version = 1
	return nil
}

func (a *acmeServerStore) GetAccount(ctx context.Context, id string) (*acme.Account, error) {
	var data []byte
	var version int64
	err := a.db.QueryRowContext(ctx, `SELECT data, version FROM acme_srv_accounts WHERE id = $1`, id).Scan(&data, &version)
	return decodeRow[acme.Account](data, version, err)
}

func (a *acmeServerStore) GetAccountByThumbprint(ctx context.Context, thumbprint string) (*acme.Account, error) {
	var data []byte
	var version int64
	err := a.db.QueryRowContext(ctx, `SELECT data, version FROM acme_srv_accounts WHERE thumbprint = $1`, thumbprint).Scan(&data, &version)
	return decodeRow[acme.Account](data, version, err)
}

func (a *acmeServerStore) UpdateAccount(ctx context.Context, acct *acme.Account) error {
	data, err := json.Marshal(acct)
	if err != nil {
		return err
	}
	res, err := a.db.ExecContext(ctx, `
UPDATE acme_srv_accounts SET data = $2, thumbprint = $3, account_ref = $4, version = version + 1
WHERE id = $1 AND version = $5`, acct.ID, data, acct.KeyThumbprint, acct.AccountRef, acct.Version)
	if err := a.casUpdate(ctx, "acme_srv_accounts", acct.ID, res, err); err != nil {
		return err
	}
	acct.Version++
	return nil
}

func (a *acmeServerStore) CreateOrder(ctx context.Context, o *acme.Order, authzs []*acme.Authorization) error {
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit
	for _, az := range authzs {
		data, err := json.Marshal(az)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO acme_srv_authzs (id, account_id, ident_type, ident_value, status, expires_at, data, version)
VALUES ($1, $2, $3, $4, $5, $6, $7, 1)`,
			az.ID, az.AccountID, az.Identifier.Type, az.Identifier.Value, az.Status, az.Expires, data)
		if isUniqueViolation(err) {
			return acme.ErrDuplicate
		}
		if err != nil {
			return fmt.Errorf("insert acme authz: %w", err)
		}
	}
	data, err := json.Marshal(o)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO acme_srv_orders (id, account_id, status, expires_at, data, version) VALUES ($1, $2, $3, $4, $5, 1)`,
		o.ID, o.AccountID, o.Status, o.Expires, data)
	if isUniqueViolation(err) {
		return acme.ErrDuplicate
	}
	if err != nil {
		return fmt.Errorf("insert acme order: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	for _, az := range authzs {
		az.Version = 1
	}
	o.Version = 1
	return nil
}

func (a *acmeServerStore) GetOrder(ctx context.Context, id string) (*acme.Order, error) {
	var data []byte
	var version int64
	err := a.db.QueryRowContext(ctx, `SELECT data, version FROM acme_srv_orders WHERE id = $1`, id).Scan(&data, &version)
	return decodeRow[acme.Order](data, version, err)
}

func (a *acmeServerStore) UpdateOrder(ctx context.Context, o *acme.Order) error {
	data, err := json.Marshal(o)
	if err != nil {
		return err
	}
	res, err := a.db.ExecContext(ctx, `
UPDATE acme_srv_orders SET data = $2, status = $3, expires_at = $4, version = version + 1
WHERE id = $1 AND version = $5`, o.ID, data, o.Status, o.Expires, o.Version)
	if err := a.casUpdate(ctx, "acme_srv_orders", o.ID, res, err); err != nil {
		return err
	}
	o.Version++
	return nil
}

func (a *acmeServerStore) ListOrderIDs(ctx context.Context, accountID string) ([]string, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT id FROM acme_srv_orders WHERE account_id = $1 ORDER BY seq`, accountID)
	if err != nil {
		return nil, fmt.Errorf("list acme orders: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (a *acmeServerStore) CountPendingOrders(ctx context.Context, accountID string, now time.Time) (int, error) {
	var n int
	err := a.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM acme_srv_orders
WHERE account_id = $1 AND status IN ('pending', 'ready') AND expires_at > $2`, accountID, now).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count acme orders: %w", err)
	}
	return n, nil
}

func (a *acmeServerStore) GetAuthorization(ctx context.Context, id string) (*acme.Authorization, error) {
	var data []byte
	var version int64
	err := a.db.QueryRowContext(ctx, `SELECT data, version FROM acme_srv_authzs WHERE id = $1`, id).Scan(&data, &version)
	return decodeRow[acme.Authorization](data, version, err)
}

func (a *acmeServerStore) UpdateAuthorization(ctx context.Context, az *acme.Authorization) error {
	data, err := json.Marshal(az)
	if err != nil {
		return err
	}
	res, err := a.db.ExecContext(ctx, `
UPDATE acme_srv_authzs SET data = $2, status = $3, expires_at = $4, version = version + 1
WHERE id = $1 AND version = $5`, az.ID, data, az.Status, az.Expires, az.Version)
	if err := a.casUpdate(ctx, "acme_srv_authzs", az.ID, res, err); err != nil {
		return err
	}
	az.Version++
	return nil
}

func (a *acmeServerStore) FindValidAuthorization(ctx context.Context, accountID string, id acme.Identifier, now time.Time) (*acme.Authorization, error) {
	var data []byte
	var version int64
	err := a.db.QueryRowContext(ctx, `
SELECT data, version FROM acme_srv_authzs
WHERE account_id = $1 AND ident_type = $2 AND ident_value = $3 AND status = 'valid' AND expires_at > $4
ORDER BY expires_at DESC LIMIT 1`, accountID, id.Type, id.Value, now).Scan(&data, &version)
	return decodeRow[acme.Authorization](data, version, err)
}

func (a *acmeServerStore) CreateCertificate(ctx context.Context, c *acme.Certificate) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	_, err = a.db.ExecContext(ctx, `
INSERT INTO acme_srv_certs (id, account_id, serial, data, version) VALUES ($1, $2, $3, $4, 1)`,
		c.ID, c.AccountID, c.Serial, data)
	if isUniqueViolation(err) {
		return acme.ErrDuplicate
	}
	if err != nil {
		return fmt.Errorf("insert acme certificate: %w", err)
	}
	c.Version = 1
	return nil
}

func (a *acmeServerStore) GetCertificate(ctx context.Context, id string) (*acme.Certificate, error) {
	var data []byte
	var version int64
	err := a.db.QueryRowContext(ctx, `SELECT data, version FROM acme_srv_certs WHERE id = $1`, id).Scan(&data, &version)
	return decodeRow[acme.Certificate](data, version, err)
}

func (a *acmeServerStore) GetCertificateBySerial(ctx context.Context, serial string) (*acme.Certificate, error) {
	var data []byte
	var version int64
	err := a.db.QueryRowContext(ctx, `SELECT data, version FROM acme_srv_certs WHERE serial = $1`, serial).Scan(&data, &version)
	return decodeRow[acme.Certificate](data, version, err)
}

func (a *acmeServerStore) UpdateCertificate(ctx context.Context, c *acme.Certificate) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	// The serial is immutable: a mismatching serial matches no row and is
	// reported as a duplicate, as the memory store does.
	res, err := a.db.ExecContext(ctx, `
UPDATE acme_srv_certs SET data = $2, version = version + 1
WHERE id = $1 AND version = $3 AND serial = $4`, c.ID, data, c.Version, c.Serial)
	if err == nil {
		if n, _ := res.RowsAffected(); n == 0 {
			var serial string
			var version int64
			switch qerr := a.db.QueryRowContext(ctx, `SELECT serial, version FROM acme_srv_certs WHERE id = $1`, c.ID).Scan(&serial, &version); {
			case errors.Is(qerr, sql.ErrNoRows):
				return acme.ErrNotFound
			case qerr != nil:
				return fmt.Errorf("check acme certificate: %w", qerr)
			case version != c.Version:
				return acme.ErrStale
			default:
				return acme.ErrDuplicate
			}
		}
		c.Version++
		return nil
	}
	return fmt.Errorf("update acme certificate: %w", err)
}
