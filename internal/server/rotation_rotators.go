package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lib/pq"
	"github.com/worlddrknss/citadel/internal/store"
)

// rotator implements AWS's four rotation steps for one kind of secret.
// Every step must be idempotent: a failed rotation is retried with the same
// token, from createSecret.
type rotator interface {
	step(name string, r *rotationRun) error
}

// ---- random -----------------------------------------------------------------

// randomRotator replaces the value (or one string field of a JSON object
// value, cfg.JSONKey) with a random password.
type randomRotator struct{}

func (randomRotator) step(name string, r *rotationRun) error {
	switch name {
	case "createSecret":
		if _, ok, err := r.pending(); err != nil || ok {
			return err
		}
		pw, err := generatePassword(r.cfg.passwordRequest())
		if err != nil {
			return err
		}
		if r.cfg.JSONKey == "" {
			return r.putPending(pw)
		}
		cur, err := r.current()
		if err != nil {
			return errors.New("the current value could not be read")
		}
		obj, err := jsonObject(cur)
		if err != nil {
			return err
		}
		obj[r.cfg.JSONKey] = pw
		b, err := json.Marshal(obj)
		if err != nil {
			return err
		}
		return r.putPending(string(b))
	case "setSecret":
		return nil // nothing outside Citadel holds the value
	case "testSecret":
		p, ok, err := r.pending()
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("no AWSPENDING version for this rotation")
		}
		if r.cfg.JSONKey != "" {
			obj, err := jsonObject(p)
			if err != nil {
				return err
			}
			if v, _ := obj[r.cfg.JSONKey].(string); v == "" {
				return fmt.Errorf("the pending value has no %q field", r.cfg.JSONKey)
			}
		} else if p.SecretString == nil || *p.SecretString == "" {
			return errors.New("the pending value is empty")
		}
		return nil
	case "finishSecret":
		return r.finish()
	}
	return fmt.Errorf("unknown step %q", name)
}

// jsonObject decodes a value that must be a JSON object, keeping numbers as
// written.
func jsonObject(v store.SecretValueRecord) (map[string]any, error) {
	if v.SecretString == nil {
		return nil, errors.New("the value is binary, not a JSON object")
	}
	dec := json.NewDecoder(strings.NewReader(*v.SecretString))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil || obj == nil {
		return nil, errors.New("the value is not a JSON object")
	}
	return obj, nil
}

// ---- postgresql -------------------------------------------------------------

const (
	pgSingleUser       = "single-user"
	pgAlternatingUsers = "alternating-users"
	pgCloneSuffix      = "_clone"
	pgConnectTimeout   = 10 * time.Second
	pgStepTimeout      = 30 * time.Second
	// pgExcludeCharacters are left out of generated passwords, as in AWS's
	// templates, so passwords are safe in connection strings.
	pgExcludeCharacters = `:/@"'\`
)

// pgSecret is AWS's standard secret for a PostgreSQL user.
type pgSecret struct {
	Engine    string
	Host      string
	Port      int
	Username  string
	Password  string
	DBName    string
	SSLMode   string
	MasterARN string
	raw       map[string]any
}

func parsePGSecret(v store.SecretValueRecord, what string) (pgSecret, error) {
	obj, err := jsonObject(v)
	if err != nil {
		return pgSecret{}, fmt.Errorf("%s: %v", what, err)
	}
	str := func(k string) string { s, _ := obj[k].(string); return strings.TrimSpace(s) }
	p := pgSecret{raw: obj, Engine: str("engine"), Host: str("host"), Username: str("username"), DBName: str("dbname"), SSLMode: str("sslmode"), MasterARN: str("masterarn")}
	p.Password, _ = obj["password"].(string)
	switch port := obj["port"].(type) {
	case nil:
		p.Port = 5432
	case json.Number:
		n, err := strconv.Atoi(port.String())
		if err != nil {
			return pgSecret{}, fmt.Errorf("%s: port must be a number", what)
		}
		p.Port = n
	case string:
		n, err := strconv.Atoi(port)
		if err != nil {
			return pgSecret{}, fmt.Errorf("%s: port must be a number", what)
		}
		p.Port = n
	default:
		return pgSecret{}, fmt.Errorf("%s: port must be a number", what)
	}
	if p.DBName == "" {
		p.DBName = "postgres"
	}
	if p.SSLMode == "" {
		p.SSLMode = "require"
	}
	switch {
	case p.Engine != "" && p.Engine != "postgres" && p.Engine != "postgresql":
		return pgSecret{}, fmt.Errorf("%s: engine must be postgres", what)
	case p.Host == "" || p.Username == "" || p.Password == "":
		return pgSecret{}, fmt.Errorf("%s: host, username and password are required", what)
	case p.Port < 1 || p.Port > 65535:
		return pgSecret{}, fmt.Errorf("%s: port must be between 1 and 65535", what)
	case strings.ContainsAny(p.Host, "/,") || strings.ContainsFunc(p.Host, func(r rune) bool { return r <= ' ' }):
		return pgSecret{}, fmt.Errorf("%s: host must be one host name or address", what)
	case len(p.Username) > 63:
		return pgSecret{}, fmt.Errorf("%s: username must be at most 63 characters", what)
	}
	switch p.SSLMode {
	case "disable", "require", "verify-ca", "verify-full":
	default:
		return pgSecret{}, fmt.Errorf("%s: sslmode must be disable, require, verify-ca or verify-full", what)
	}
	return p, nil
}

// withPassword returns the secret's JSON with username and password replaced.
func (p pgSecret) withCredentials(username, password string) (string, error) {
	obj := map[string]any{}
	for k, v := range p.raw {
		obj[k] = v
	}
	obj["username"], obj["password"] = username, password
	b, err := json.Marshal(obj)
	return string(b), err
}

// pgConnValue quotes a libpq keyword/value connection parameter.
func pgConnValue(v string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(v) + "'"
}

// rotationDialer refuses loopback, link-local, multicast and cloud metadata
// addresses (checked on the resolved address at dial time).
type rotationDialer struct{ allowLoopback bool }

func (d rotationDialer) dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, Control: rotationDialControl(d.allowLoopback)}
}

func (d rotationDialer) Dial(network, address string) (net.Conn, error) {
	return d.dialer(pgConnectTimeout).Dial(network, address)
}

func (d rotationDialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	return d.dialer(timeout).Dial(network, address)
}

func (d rotationDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dialer(pgConnectTimeout).DialContext(ctx, network, address)
}

var errRotationAddressBlocked = errors.New("the destination address is not allowed (loopback, link-local or metadata)")

func rotationDialControl(allowLoopback bool) func(network, address string, c syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		a, err := netip.ParseAddr(host)
		if err != nil {
			return errRotationAddressBlocked
		}
		a = a.Unmap()
		if allowLoopback && a.IsLoopback() {
			return nil
		}
		if ssrfBlocked(a) {
			return errRotationAddressBlocked
		}
		return nil
	}
}

// pgOpen connects to the database in c with c's credentials.
func (s *Server) pgOpen(ctx context.Context, c pgSecret) (*sql.DB, error) {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s connect_timeout=%d application_name=citadel-rotation",
		pgConnValue(c.Host), c.Port, pgConnValue(c.Username), pgConnValue(c.Password), pgConnValue(c.DBName), c.SSLMode, int(pgConnectTimeout/time.Second))
	conn, err := pq.NewConnector(dsn)
	if err != nil {
		return nil, errors.New("invalid connection settings")
	}
	conn.Dialer(rotationDialer{allowLoopback: s.rot.allowLoopback})
	db := sql.OpenDB(conn)
	db.SetMaxOpenConns(1)
	pctx, cancel := context.WithTimeout(ctx, pgConnectTimeout+5*time.Second)
	defer cancel()
	if err := db.PingContext(pctx); err != nil {
		db.Close()
		return nil, pgError(err)
	}
	return db, nil
}

// pgError keeps the useful part of a connection or SQL error.
func pgError(err error) error {
	var pqe *pq.Error
	if errors.As(err, &pqe) {
		return fmt.Errorf("postgres: %s (%s)", pqe.Message, pqe.Code)
	}
	if errors.Is(err, errRotationAddressBlocked) || strings.Contains(err.Error(), errRotationAddressBlocked.Error()) {
		return errRotationAddressBlocked
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("postgres: connection timed out")
	}
	var nerr net.Error
	if errors.As(err, &nerr) {
		return errors.New("postgres: could not connect")
	}
	return errors.New("postgres: " + err.Error())
}

func (s *Server) pgCanLogin(ctx context.Context, c pgSecret) error {
	db, err := s.pgOpen(ctx, c)
	if err != nil {
		return err
	}
	defer db.Close()
	qctx, cancel := context.WithTimeout(ctx, pgStepTimeout)
	defer cancel()
	var one int
	if err := db.QueryRowContext(qctx, `SELECT 1`).Scan(&one); err != nil {
		return pgError(err)
	}
	return nil
}

// postgresRotator rotates a PostgreSQL user's password, with AWS's
// single-user or alternating-users strategy.
type postgresRotator struct{}

func (postgresRotator) strategy(r *rotationRun, cur pgSecret) (string, string) {
	admin := r.cfg.AdminSecretARN
	if admin == "" {
		admin = cur.MasterARN
	}
	switch r.cfg.Strategy {
	case pgSingleUser:
		return pgSingleUser, ""
	case pgAlternatingUsers:
		return pgAlternatingUsers, admin
	}
	if admin != "" {
		return pgAlternatingUsers, admin
	}
	return pgSingleUser, ""
}

func (pr postgresRotator) step(name string, r *rotationRun) error {
	switch name {
	case "createSecret":
		if _, ok, err := r.pending(); err != nil || ok {
			return err
		}
		curV, err := r.current()
		if err != nil {
			return errors.New("the current value could not be read")
		}
		cur, err := parsePGSecret(curV, "current value")
		if err != nil {
			return err
		}
		req := r.cfg.passwordRequest()
		req.ExcludeCharacters += pgExcludeCharacters
		pw, err := generatePassword(req)
		if err != nil {
			return err
		}
		username := cur.Username
		if strategy, _ := pr.strategy(r, cur); strategy == pgAlternatingUsers {
			if strings.HasSuffix(username, pgCloneSuffix) {
				username = strings.TrimSuffix(username, pgCloneSuffix)
			} else {
				username += pgCloneSuffix
			}
			if len(username) > 63 {
				return errors.New("the alternate username would be longer than 63 characters")
			}
		}
		value, err := cur.withCredentials(username, pw)
		if err != nil {
			return err
		}
		return r.putPending(value)
	case "setSecret":
		return pr.setSecret(r)
	case "testSecret":
		pend, err := pr.pendingSecret(r)
		if err != nil {
			return err
		}
		if err := r.s.pgCanLogin(r.ctx, pend); err != nil {
			return fmt.Errorf("the new credentials don't work: %v", err)
		}
		return nil
	case "finishSecret":
		return r.finish()
	}
	return fmt.Errorf("unknown step %q", name)
}

func (postgresRotator) pendingSecret(r *rotationRun) (pgSecret, error) {
	p, ok, err := r.pending()
	if err != nil {
		return pgSecret{}, err
	}
	if !ok {
		return pgSecret{}, errors.New("no AWSPENDING version for this rotation")
	}
	return parsePGSecret(p, "pending value")
}

func (pr postgresRotator) setSecret(r *rotationRun) error {
	pend, err := pr.pendingSecret(r)
	if err != nil {
		return err
	}
	// Already set (a retry after setSecret succeeded)?
	if r.s.pgCanLogin(r.ctx, pend) == nil {
		return nil
	}
	curV, err := r.current()
	if err != nil {
		return errors.New("the current value could not be read")
	}
	cur, err := parsePGSecret(curV, "current value")
	if err != nil {
		return err
	}
	strategy, adminARN := pr.strategy(r, cur)
	var db *sql.DB
	if strategy == pgAlternatingUsers {
		if adminARN == "" {
			return errors.New("the alternating-users strategy needs an admin secret (adminSecretArn or masterarn)")
		}
		av, err := r.s.store.GetSecretValue(r.ctx, adminARN, "", store.CurrentVersionStage)
		if err != nil {
			return errors.New("the admin secret could not be read in this account")
		}
		admin, err := parsePGSecret(av, "admin secret")
		if err != nil {
			return err
		}
		if !strings.EqualFold(admin.Host, pend.Host) || admin.Port != pend.Port {
			return errors.New("the admin secret is for a different database server")
		}
		if db, err = r.s.pgOpen(r.ctx, admin); err != nil {
			return fmt.Errorf("could not sign in with the admin secret: %v", err)
		}
	} else {
		// The user's own current credentials, falling back to the previous
		// ones (AWS does the same, for a rotation interrupted after the
		// password changed).
		db, err = r.s.pgOpen(r.ctx, cur)
		if err != nil {
			if prevV, perr := r.value(store.PreviousVersionStage, ""); perr == nil {
				if prev, perr := parsePGSecret(prevV, "previous value"); perr == nil && prev.Username == pend.Username {
					db, err = r.s.pgOpen(r.ctx, prev)
				}
			}
		}
		if err != nil {
			return fmt.Errorf("could not sign in with the current credentials: %v", err)
		}
	}
	defer db.Close()
	qctx, cancel := context.WithTimeout(r.ctx, pgStepTimeout)
	defer cancel()
	user, pw := pq.QuoteIdentifier(pend.Username), pq.QuoteLiteral(pend.Password)
	if strategy == pgAlternatingUsers {
		var exists bool
		if err := db.QueryRowContext(qctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, pend.Username).Scan(&exists); err != nil {
			return pgError(err)
		}
		if !exists {
			// Passwords can't be bind parameters in utility statements;
			// both the role and the literal are quoted by the driver.
			if _, err := db.ExecContext(qctx, `CREATE ROLE `+user+` WITH LOGIN PASSWORD `+pw); err != nil {
				return pgError(err)
			}
			if _, err := db.ExecContext(qctx, `GRANT `+pq.QuoteIdentifier(cur.Username)+` TO `+user); err != nil {
				return pgError(err)
			}
			return nil
		}
	}
	if _, err := db.ExecContext(qctx, `ALTER ROLE `+user+` WITH PASSWORD `+pw); err != nil {
		return pgError(err)
	}
	return nil
}

// ---- webhook ----------------------------------------------------------------

const (
	webhookTimeout      = 15 * time.Second
	webhookResponseMax  = 64 << 10
	webhookSignatureHdr = "X-Citadel-Signature"
	webhookTimestampHdr = "X-Citadel-Timestamp"
	webhookStepHdr      = "X-Citadel-Rotation-Step"
)

// webhookRequest is the body POSTed for each step.
type webhookRequest struct {
	Step               string `json:"step"`
	SecretID           string `json:"secretId"`
	SecretName         string `json:"secretName"`
	ClientRequestToken string `json:"clientRequestToken"`
	CurrentValue       string `json:"currentValue,omitempty"`
	PendingValue       string `json:"pendingValue,omitempty"`
}

// webhookCreateResponse is createSecret's optional reply: the new value. When
// absent Citadel generates one with the configured password options.
type webhookCreateResponse struct {
	SecretString string `json:"secretString"`
}

// webhookRotator calls an https endpoint for each step, like a Lambda.
type webhookRotator struct{}

func (webhookRotator) step(name string, r *rotationRun) error {
	req := webhookRequest{Step: name, SecretID: r.arn, SecretName: r.name, ClientRequestToken: r.token}
	switch name {
	case "createSecret":
		if _, ok, err := r.pending(); err != nil || ok {
			return err
		}
		cur, err := r.current()
		if err != nil {
			return errors.New("the current value could not be read")
		}
		if cur.SecretString != nil {
			req.CurrentValue = *cur.SecretString
		}
		body, err := r.s.callRotationWebhook(r, req)
		if err != nil {
			return err
		}
		var resp webhookCreateResponse
		if len(bytes.TrimSpace(body)) > 0 {
			if err := json.Unmarshal(body, &resp); err != nil {
				return errors.New("createSecret: the webhook's response is not JSON")
			}
		}
		value := resp.SecretString
		if value == "" {
			if value, err = generatePassword(r.cfg.passwordRequest()); err != nil {
				return err
			}
		}
		return r.putPending(value)
	case "setSecret", "testSecret":
		p, ok, err := r.pending()
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("no AWSPENDING version for this rotation")
		}
		if p.SecretString != nil {
			req.PendingValue = *p.SecretString
		}
		if name == "setSecret" {
			if cur, err := r.current(); err == nil && cur.SecretString != nil {
				req.CurrentValue = *cur.SecretString
			}
		}
		_, err = r.s.callRotationWebhook(r, req)
		return err
	case "finishSecret":
		if _, err := r.s.callRotationWebhook(r, req); err != nil {
			return err
		}
		return r.finish()
	}
	return fmt.Errorf("unknown step %q", name)
}

// signWebhook returns the signature header value for a body sent at ts:
// "v1=" + hex(HMAC-SHA256(key, ts + "." + body)).
func signWebhook(key, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(ts))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return "v1=" + hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) rotationWebhookClient() *http.Client {
	if s.rot.webhookClient != nil {
		return s.rot.webhookClient
	}
	dialer := &net.Dialer{Timeout: webhookTimeout, Control: rotationDialControl(false)}
	return &http.Client{
		Timeout: webhookTimeout,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   webhookTimeout,
			ResponseHeaderTimeout: webhookTimeout,
			MaxIdleConns:          4,
			IdleConnTimeout:       time.Minute,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// callRotationWebhook POSTs a signed step request and returns the body of a
// 2xx response.
func (s *Server) callRotationWebhook(r *rotationRun, payload webhookRequest) ([]byte, error) {
	if err := validateStreamURL(r.cfg.URL); err != nil {
		return nil, err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(r.ctx, webhookTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("invalid webhook request")
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", AppName+"-rotation/1")
	req.Header.Set(webhookTimestampHdr, ts)
	req.Header.Set(webhookStepHdr, payload.Step)
	req.Header.Set(webhookSignatureHdr, signWebhook(r.signingKey, ts, body))
	resp, err := s.rotationWebhookClient().Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			if errors.Is(uerr.Err, errRotationAddressBlocked) || strings.Contains(uerr.Err.Error(), errRotationAddressBlocked.Error()) {
				return nil, fmt.Errorf("%s: %v", payload.Step, errRotationAddressBlocked)
			}
		}
		return nil, fmt.Errorf("%s: the webhook could not be reached", payload.Step)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, webhookResponseMax))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("%s: the webhook returned HTTP %d", payload.Step, resp.StatusCode)
	}
	return out, nil
}
