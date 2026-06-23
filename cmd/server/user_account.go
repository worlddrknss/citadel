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

var (
	accountProfileTemplate  = template.Must(template.ParseFS(uiTemplatesFS, "templates/admin_account_profile.html"))
	accountKeysTemplate     = template.Must(template.ParseFS(uiTemplatesFS, "templates/admin_account_keys.html"))
	accountPasswordTemplate = template.Must(template.ParseFS(uiTemplatesFS, "templates/admin_account_password.html"))
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
		Username        string
		AccountID       string
		Accounts        []string
		CurrentUserName string
		CurrentUserRole string
	}{
		Username:        session.Username,
		AccountID:       session.AccountID,
		Accounts:        session.Accounts,
		CurrentUserName: session.DisplayName,
		CurrentUserRole: session.Role,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := accountProfileTemplate.Execute(w, pageView); err != nil {
		http.Error(w, "failed to render profile view", http.StatusInternalServerError)
	}
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
		Username        string
		AccountID       string
		Keys            []accessKeyInfo
		CreatedKeyID    string
		CreatedSecret   string
		DeletedKeyID    string
		DeactivatedID   string
		ErrorMsg        string
		CurrentUserName string
		CurrentUserRole string
	}{
		Username:        session.Username,
		AccountID:       session.AccountID,
		Keys:            keys,
		CreatedKeyID:    createdKeyID,
		CreatedSecret:   createdSecret,
		DeletedKeyID:    r.URL.Query().Get("deleted"),
		DeactivatedID:   r.URL.Query().Get("deactivated"),
		ErrorMsg:        r.URL.Query().Get("error"),
		CurrentUserName: session.DisplayName,
		CurrentUserRole: session.Role,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := accountKeysTemplate.Execute(w, pageView); err != nil {
		http.Error(w, "failed to render access keys view", http.StatusInternalServerError)
	}
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
		Username        string
		SuccessMsg      string
		ErrorMsg        string
		CurrentUserName string
		CurrentUserRole string
	}{
		Username:        session.Username,
		SuccessMsg:      r.URL.Query().Get("success"),
		ErrorMsg:        r.URL.Query().Get("error"),
		CurrentUserName: session.DisplayName,
		CurrentUserRole: session.Role,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := accountPasswordTemplate.Execute(w, pageView); err != nil {
		http.Error(w, "failed to render password view", http.StatusInternalServerError)
	}
}
