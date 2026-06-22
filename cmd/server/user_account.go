package main

import (
	"crypto/rand"
	"encoding/base64"
	"html/template"
	"net/http"
	"strings"
	"sync"
	"time"
)

// oneTimeSecret holds a freshly created access key secret that must be shown to
// the user exactly once. The plaintext secret is never persisted and never
// placed in a URL; it is handed out a single time via an opaque reveal token.
type oneTimeSecret struct {
	accessKeyID string
	secret      string
	expires     time.Time
}

var (
	oneTimeSecretsMu sync.Mutex
	oneTimeSecrets   = map[string]oneTimeSecret{}
)

// stashOneTimeSecret stores a secret server-side and returns an opaque,
// single-use token used to reveal it exactly once within a short window.
func stashOneTimeSecret(accessKeyID, secret string) string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	token := base64.RawURLEncoding.EncodeToString(b)

	oneTimeSecretsMu.Lock()
	defer oneTimeSecretsMu.Unlock()
	now := time.Now()
	for k, v := range oneTimeSecrets {
		if now.After(v.expires) {
			delete(oneTimeSecrets, k)
		}
	}
	oneTimeSecrets[token] = oneTimeSecret{accessKeyID: accessKeyID, secret: secret, expires: now.Add(5 * time.Minute)}
	return token
}

// popOneTimeSecret atomically retrieves and removes a stashed secret. It returns
// ok=false if the token is unknown, already consumed, or expired.
func popOneTimeSecret(token string) (oneTimeSecret, bool) {
	if strings.TrimSpace(token) == "" {
		return oneTimeSecret{}, false
	}
	oneTimeSecretsMu.Lock()
	defer oneTimeSecretsMu.Unlock()
	v, ok := oneTimeSecrets[token]
	if !ok {
		return oneTimeSecret{}, false
	}
	delete(oneTimeSecrets, token)
	if time.Now().After(v.expires) {
		return oneTimeSecret{}, false
	}
	return v, true
}

// handleAccountProfile displays user profile and account information.
func (s *server) handleAccountProfile(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireUISession(w, r, "user")
	if !ok {
		return
	}

	// Render profile page
	pageView := struct {
		Username  string
		AccountID string
		Accounts  []string
	}{
		Username:  session.Username,
		AccountID: session.AccountID,
		Accounts:  session.Accounts,
	}

	const profileHTML = `<!DOCTYPE html>
<html>
<head>
    <title>Profile - KMS</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
        .container { background: #f5f5f5; border-radius: 8px; padding: 20px; }
        h1 { color: #333; margin-bottom: 30px; }
        .profile-card { background: white; border-radius: 6px; padding: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .field { margin-bottom: 15px; }
        .label { font-weight: 600; color: #666; font-size: 12px; text-transform: uppercase; }
        .value { color: #333; font-size: 16px; margin-top: 5px; }
        .button-group { margin-top: 30px; display: flex; gap: 10px; }
        .btn { padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; }
        .btn-primary { background: #0066cc; color: white; }
        .btn-primary:hover { background: #0052a3; }
        .btn-secondary { background: #e0e0e0; color: #333; }
        .btn-secondary:hover { background: #d0d0d0; }
        .nav { margin-bottom: 20px; display: flex; gap: 10px; }
        .nav a { padding: 10px 15px; text-decoration: none; border-radius: 4px; background: #f0f0f0; color: #0066cc; }
        .nav a:hover { background: #e0e0e0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Your Profile</h1>
        
        <div class="nav">
            <a href="/account/profile">Profile</a>
            <a href="/account/keys">Access Keys</a>
            <a href="/account/password">Password</a>
        </div>

        <div class="profile-card">
            <div class="field">
                <div class="label">Username</div>
                <div class="value">{{.Username}}</div>
            </div>
            <div class="field">
                <div class="label">Current Account</div>
                <div class="value"><code>{{.AccountID}}</code></div>
            </div>
            <div class="field">
                <div class="label">All Accessible Accounts</div>
                <div class="value">
                    {{range .Accounts}}
                        <div style="margin: 5px 0;"><code>{{.}}</code></div>
                    {{end}}
                </div>
            </div>
        </div>

        <div class="button-group">
            <form action="/logout" method="post" style="margin: 0;">
                <button type="submit" class="btn btn-secondary">Logout</button>
            </form>
        </div>
    </div>
</body>
</html>`

	t := template.Must(template.New("profile").Parse(profileHTML))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t.Execute(w, pageView)
}

// handleAccountKeys displays and manages access keys.
func (s *server) handleAccountKeys(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireUISession(w, r, "user")
	if !ok {
		return
	}

	ctx := r.Context()

	// Handle form submissions
	if r.Method == http.MethodPost {
		action := strings.TrimSpace(r.FormValue("action"))
		switch action {
		case "create":
			secret, err := s.store.CreateAccessKey(ctx, session.Username, session.AccountID)
			if err != nil {
				// Show error in next render
				http.Redirect(w, r, "/account/keys?error="+strings.ReplaceAll(err.Error(), " ", "+"), http.StatusSeeOther)
				return
			}
			// Stash the secret server-side and reveal it once via an opaque,
			// single-use token. The plaintext secret is never put in a URL.
			revealToken := stashOneTimeSecret(secret.AccessKeyID, secret.SecretKey)
			http.Redirect(w, r, "/account/keys?reveal="+revealToken, http.StatusSeeOther)
			return
		case "delete":
			keyID := strings.TrimSpace(r.FormValue("key_id"))
			if keyID == "" {
				http.Redirect(w, r, "/account/keys?error=missing+key_id", http.StatusSeeOther)
				return
			}
			err := s.store.DeleteAccessKey(ctx, keyID)
			if err != nil {
				http.Redirect(w, r, "/account/keys?error="+strings.ReplaceAll(err.Error(), " ", "+"), http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/account/keys?deleted="+keyID, http.StatusSeeOther)
			return
		case "deactivate":
			keyID := strings.TrimSpace(r.FormValue("key_id"))
			if keyID == "" {
				http.Redirect(w, r, "/account/keys?error=missing+key_id", http.StatusSeeOther)
				return
			}
			err := s.store.SetAccessKeyStatus(ctx, keyID, "Inactive")
			if err != nil {
				http.Redirect(w, r, "/account/keys?error="+strings.ReplaceAll(err.Error(), " ", "+"), http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/account/keys?deactivated="+keyID, http.StatusSeeOther)
			return
		}
	}

	// List existing keys
	keys, err := s.store.ListAccessKeys(ctx, session.Username, session.AccountID)
	if err != nil {
		keys = []accessKeyInfo{}
	}

	// Reveal a freshly created secret exactly once. The secret is retrieved from
	// the server-side single-use cache via an opaque token; it is never read from
	// the URL and cannot be shown again on refresh.
	var createdKeyID, createdSecret string
	if ots, ok := popOneTimeSecret(r.URL.Query().Get("reveal")); ok {
		createdKeyID = ots.accessKeyID
		createdSecret = ots.secret
	}

	pageView := struct {
		Username      string
		AccountID     string
		Keys          []accessKeyInfo
		CreatedKeyID  string
		CreatedSecret string
		DeletedKeyID  string
		DeactivatedID string
		ErrorMsg      string
	}{
		Username:      session.Username,
		AccountID:     session.AccountID,
		Keys:          keys,
		CreatedKeyID:  createdKeyID,
		CreatedSecret: createdSecret,
		DeletedKeyID:  r.URL.Query().Get("deleted"),
		DeactivatedID: r.URL.Query().Get("deactivated"),
		ErrorMsg:      r.URL.Query().Get("error"),
	}

	const keysHTML = `<!DOCTYPE html>
<html>
<head>
    <title>Access Keys - KMS</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
        .container { background: #f5f5f5; border-radius: 8px; padding: 20px; }
        h1 { color: #333; margin-bottom: 30px; }
        .alert { padding: 15px; border-radius: 4px; margin-bottom: 20px; }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-warning { background: #fff3cd; color: #856404; border: 1px solid #ffeeba; }
        .alert-error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .nav { margin-bottom: 20px; display: flex; gap: 10px; }
        .nav a { padding: 10px 15px; text-decoration: none; border-radius: 4px; background: #f0f0f0; color: #0066cc; }
        .nav a:hover { background: #e0e0e0; }
        .card { background: white; border-radius: 6px; padding: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .table { width: 100%; border-collapse: collapse; }
        .table th { background: #f0f0f0; padding: 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #ddd; }
        .table td { padding: 12px; border-bottom: 1px solid #eee; }
        .code { font-family: monospace; background: #f5f5f5; padding: 2px 6px; border-radius: 3px; }
        .status-active { color: #28a745; font-weight: 600; }
        .status-inactive { color: #dc3545; font-weight: 600; }
        .button-group { display: flex; gap: 5px; }
        .btn { padding: 6px 12px; border: none; border-radius: 3px; cursor: pointer; font-size: 12px; }
        .btn-delete { background: #dc3545; color: white; }
        .btn-delete:hover { background: #c82333; }
        .btn-primary { background: #0066cc; color: white; padding: 10px 20px; }
        .btn-primary:hover { background: #0052a3; }
        .secret-display { background: #fff3cd; border: 1px solid #ffeeba; border-radius: 4px; padding: 15px; margin-bottom: 20px; }
        .secret-display .label { font-weight: 600; color: #856404; margin-bottom: 10px; }
        .secret-display code { background: #fff; padding: 8px; border: 1px solid #ffeeba; border-radius: 3px; display: block; word-break: break-all; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Access Keys</h1>
        
        <div class="nav">
            <a href="/account/profile">Profile</a>
            <a href="/account/keys">Access Keys</a>
            <a href="/account/password">Password</a>
        </div>

        {{if .ErrorMsg}}
        <div class="alert alert-error">Error: {{.ErrorMsg}}</div>
        {{end}}

        {{if .CreatedKeyID}}
        <div class="secret-display">
            <div class="label">⚠️ New Access Key Created (shown only once)</div>
            <div style="margin-bottom: 10px;">
                <strong>Access Key ID:</strong><br>
                <code>{{.CreatedKeyID}}</code>
            </div>
            <div>
                <strong>Secret Key:</strong><br>
                <code>{{.CreatedSecret}}</code>
            </div>
            <p style="margin: 10px 0 0 0; color: #856404; font-size: 12px;">Save these credentials securely. You won't be able to see the secret key again.</p>
        </div>
        {{end}}

        {{if .DeletedKeyID}}
        <div class="alert alert-success">Access key {{.DeletedKeyID}} deleted successfully.</div>
        {{end}}

        {{if .DeactivatedID}}
        <div class="alert alert-success">Access key {{.DeactivatedID}} deactivated successfully.</div>
        {{end}}

        <div class="card">
            <h2 style="margin-top: 0;">Create New Access Key</h2>
            <p>You can have up to 2 active access keys per account.</p>
            <form method="post" style="display: inline;">
                <input type="hidden" name="action" value="create">
                <button type="submit" class="btn btn-primary">Create New Key</button>
            </form>
        </div>

        <div class="card">
            <h2 style="margin-top: 0;">Your Access Keys</h2>
            {{if .Keys}}
            <table class="table">
                <thead>
                    <tr>
                        <th>Access Key ID</th>
                        <th>Status</th>
                        <th>Created</th>
                        <th>Last Used</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Keys}}
                    <tr>
                        <td><code class="code">{{.AccessKeyID}}</code></td>
                        <td>
                            {{if eq .Status "Active"}}
                            <span class="status-active">{{.Status}}</span>
                            {{else}}
                            <span class="status-inactive">{{.Status}}</span>
                            {{end}}
                        </td>
                        <td>{{.CreatedAt.Format "2006-01-02 15:04"}}</td>
                        <td>
                            {{if .LastUsedAt}}
                                {{.LastUsedAt.Format "2006-01-02 15:04"}}
                            {{else}}
                                Never
                            {{end}}
                        </td>
                        <td>
                            <div class="button-group">
                                {{if eq .Status "Active"}}
                                <form method="post" style="display: inline;" onsubmit="return confirm('Deactivate this key?');">
                                    <input type="hidden" name="action" value="deactivate">
                                    <input type="hidden" name="key_id" value="{{.AccessKeyID}}">
                                    <button type="submit" class="btn btn-delete">Deactivate</button>
                                </form>
                                {{end}}
                                <form method="post" style="display: inline;" onsubmit="return confirm('Delete this key? This cannot be undone.');">
                                    <input type="hidden" name="action" value="delete">
                                    <input type="hidden" name="key_id" value="{{.AccessKeyID}}">
                                    <button type="submit" class="btn btn-delete">Delete</button>
                                </form>
                            </div>
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
            {{else}}
            <p style="color: #666;">No access keys yet.</p>
            {{end}}
        </div>
    </div>
</body>
</html>`

	t := template.Must(template.New("keys").Parse(keysHTML))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t.Execute(w, pageView)
}

// handleAccountPassword allows users to change their password.
func (s *server) handleAccountPassword(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireUISession(w, r, "user")
	if !ok {
		return
	}

	// Handle form submissions
	if r.Method == http.MethodPost {
		currentPassword := r.FormValue("current_password")
		newPassword := r.FormValue("new_password")
		confirmPassword := r.FormValue("confirm_password")

		if newPassword != confirmPassword {
			http.Redirect(w, r, "/account/password?error=passwords+do+not+match", http.StatusSeeOther)
			return
		}

		if len(newPassword) < 8 {
			http.Redirect(w, r, "/account/password?error=password+must+be+at+least+8+characters", http.StatusSeeOther)
			return
		}

		ctx := r.Context()

		// Verify current password by listing all users and finding the one
		users, err := s.store.ListUIUsers(ctx)
		if err != nil {
			http.Redirect(w, r, "/account/password?error=failed+to+verify+credentials", http.StatusSeeOther)
			return
		}

		var currentUser *uiUserConfig
		for i := range users {
			if users[i].Username == session.Username {
				currentUser = &users[i]
				break
			}
		}

		if currentUser == nil {
			http.Redirect(w, r, "/account/password?error=user+not+found", http.StatusSeeOther)
			return
		}

		if !verifyPassword(currentUser.PasswordHash, currentPassword) {
			http.Redirect(w, r, "/account/password?error=current+password+is+incorrect", http.StatusSeeOther)
			return
		}

		// Update password
		hashedNew, err := hashPassword(newPassword)
		if err != nil {
			http.Redirect(w, r, "/account/password?error=failed+to+hash+password", http.StatusSeeOther)
			return
		}

		currentUser.PasswordHash = hashedNew
		err = s.store.UpsertUIUser(ctx, *currentUser)
		if err != nil {
			http.Redirect(w, r, "/account/password?error=failed+to+update+password", http.StatusSeeOther)
			return
		}

		http.Redirect(w, r, "/account/password?success=1", http.StatusSeeOther)
		return
	}

	pageView := struct {
		Username   string
		SuccessMsg string
		ErrorMsg   string
	}{
		Username:   session.Username,
		SuccessMsg: r.URL.Query().Get("success"),
		ErrorMsg:   r.URL.Query().Get("error"),
	}

	const passwordHTML = `<!DOCTYPE html>
<html>
<head>
    <title>Change Password - KMS</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
        .container { background: #f5f5f5; border-radius: 8px; padding: 20px; }
        h1 { color: #333; margin-bottom: 30px; }
        .alert { padding: 15px; border-radius: 4px; margin-bottom: 20px; }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .nav { margin-bottom: 20px; display: flex; gap: 10px; }
        .nav a { padding: 10px 15px; text-decoration: none; border-radius: 4px; background: #f0f0f0; color: #0066cc; }
        .nav a:hover { background: #e0e0e0; }
        .card { background: white; border-radius: 6px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); max-width: 400px; }
        .field { margin-bottom: 15px; }
        .label { font-weight: 600; color: #333; display: block; margin-bottom: 5px; }
        input[type="password"] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; box-sizing: border-box; }
        input[type="password"]:focus { outline: none; border-color: #0066cc; box-shadow: 0 0 0 2px rgba(0, 102, 204, 0.1); }
        .button-group { margin-top: 20px; display: flex; gap: 10px; }
        .btn { padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; }
        .btn-primary { background: #0066cc; color: white; }
        .btn-primary:hover { background: #0052a3; }
        .btn-secondary { background: #e0e0e0; color: #333; }
        .btn-secondary:hover { background: #d0d0d0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Change Password</h1>
        
        <div class="nav">
            <a href="/account/profile">Profile</a>
            <a href="/account/keys">Access Keys</a>
            <a href="/account/password">Password</a>
        </div>

        {{if .SuccessMsg}}
        <div class="alert alert-success">Password changed successfully!</div>
        {{end}}

        {{if .ErrorMsg}}
        <div class="alert alert-error">Error: {{.ErrorMsg}}</div>
        {{end}}

        <div class="card">
            <form method="post">
                <div class="field">
                    <label class="label">Current Password</label>
                    <input type="password" name="current_password" required autofocus>
                </div>
                <div class="field">
                    <label class="label">New Password</label>
                    <input type="password" name="new_password" required minlength="8">
                </div>
                <div class="field">
                    <label class="label">Confirm New Password</label>
                    <input type="password" name="confirm_password" required minlength="8">
                </div>
                <div class="button-group">
                    <button type="submit" class="btn btn-primary">Change Password</button>
                    <a href="/account/profile" class="btn btn-secondary" style="text-decoration: none; display: inline-block;">Cancel</a>
                </div>
            </form>
        </div>
    </div>
</body>
</html>`

	t := template.Must(template.New("password").Parse(passwordHTML))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t.Execute(w, pageView)
}
