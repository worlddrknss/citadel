package main

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

var masterAdminTemplate = template.Must(template.ParseFS(uiTemplatesFS, "templates/admin_master.html"))

type masterAdminUserView struct {
	Username    string
	DisplayName string
	Role        string
	Accounts    string
}

type masterAdminPageView struct {
	Section         string
	CurrentUserName string
	CurrentUserRole string
	AccountScope    []string
	CanAdmin        bool
	Users           []masterAdminUserView
	Roles           []string
	Accounts        []string
	AWSRegion       string
	AWSAccountID    string
	AWSRegions      []string
	Flash           string
	Error           string
}

func (s *server) handleMasterAdminOverview(w http.ResponseWriter, r *http.Request) {
	s.renderMasterAdminSection(w, r, "overview")
}

func (s *server) handleMasterAdminUsers(w http.ResponseWriter, r *http.Request) {
	s.renderMasterAdminSection(w, r, "users")
}

func (s *server) handleMasterAdminRBAC(w http.ResponseWriter, r *http.Request) {
	s.renderMasterAdminSection(w, r, "rbac")
}

func (s *server) handleMasterAdminAccounts(w http.ResponseWriter, r *http.Request) {
	s.renderMasterAdminSection(w, r, "accounts")
}

func (s *server) handleMasterAdminSettings(w http.ResponseWriter, r *http.Request) {
	s.renderMasterAdminSection(w, r, "settings")
}

// handleLegacyTenantsRedirect preserves old bookmarks/links to the former
// /admin/tenants section after the tenant->account rename.
func (s *server) handleLegacyTenantsRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/admin/accounts", http.StatusMovedPermanently)
}

func (s *server) renderMasterAdminSection(w http.ResponseWriter, r *http.Request, section string) {
	session, ok := s.requireUISession(w, r, "admin")
	if !ok {
		return
	}

	action := strings.TrimSpace(r.URL.Query().Get("action"))
	if action != "" {
		s.handleMasterAdminAction(w, r, section, session, action)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	users, roleList, accountList := s.loadMasterAdminData(r)
	region, accountID := s.store.DeploymentIdentity()

	view := masterAdminPageView{
		Section:         section,
		CurrentUserName: session.DisplayName,
		CurrentUserRole: session.Role,
		AccountScope:    append([]string(nil), session.Accounts...),
		CanAdmin:        uiCanAdmin(session),
		Users:           users,
		Roles:           roleList,
		Accounts:        accountList,
		AWSRegion:       region,
		AWSAccountID:    accountID,
		AWSRegions:      append([]string(nil), awsRegions...),
		Flash:           r.URL.Query().Get("ok"),
		Error:           r.URL.Query().Get("err"),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := masterAdminTemplate.Execute(w, view); err != nil {
		http.Error(w, "failed to render master admin view", http.StatusInternalServerError)
		return
	}
}

func (s *server) loadMasterAdminData(r *http.Request) ([]masterAdminUserView, []string, []string) {
	users := make([]masterAdminUserView, 0)
	roles := map[string]struct{}{}
	accounts := map[string]struct{}{}

	runtime := s.uiRuntime()
	runtime.mu.Lock()
	for _, user := range runtime.users {
		roles[user.Role] = struct{}{}
		for _, account := range user.Accounts {
			account = normalizeAccountName(account)
			if account != "" {
				accounts[account] = struct{}{}
			}
		}
		users = append(users, masterAdminUserView{
			Username:    user.Username,
			DisplayName: user.DisplayName,
			Role:        user.Role,
			Accounts:    strings.Join(user.Accounts, ", "),
		})
	}
	runtime.mu.Unlock()

	if storedAccounts, err := s.store.ListUIAccounts(r.Context()); err == nil {
		for _, account := range storedAccounts {
			account = normalizeAccountName(account)
			if account != "" {
				accounts[account] = struct{}{}
			}
		}
	}

	sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
	roleList := make([]string, 0, len(roles))
	for role := range roles {
		roleList = append(roleList, role)
	}
	sort.Strings(roleList)
	accountList := make([]string, 0, len(accounts))
	for account := range accounts {
		accountList = append(accountList, account)
	}
	sort.Strings(accountList)
	return users, roleList, accountList
}

func (s *server) handleMasterAdminAction(w http.ResponseWriter, r *http.Request, section string, session *uiSession, action string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !uiCanAdmin(session) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var err error
	var okMsg string

	switch action {
	case "create_user":
		err, okMsg = s.masterAdminCreateUser(r)
	case "update_user":
		err, okMsg = s.masterAdminUpdateUser(r)
	case "delete_user":
		err, okMsg = s.masterAdminDeleteUser(r, session)
	case "set_role":
		err, okMsg = s.masterAdminSetRole(r)
	case "create_account":
		err, okMsg = s.masterAdminCreateAccount(r)
	case "delete_account":
		err, okMsg = s.masterAdminDeleteAccount(r)
	case "assign_account":
		err, okMsg = s.masterAdminAssignAccount(r)
	case "remove_account":
		err, okMsg = s.masterAdminRemoveAccount(r)
	case "update_aws_settings":
		err, okMsg = s.masterAdminUpdateAWSSettings(r)
	default:
		err = fmt.Errorf("unsupported action: %s", action)
	}

	if err == nil {
		_ = s.reloadRuntimeUsersFromStore(r)
	}

	v := url.Values{}
	if err != nil {
		v.Set("err", err.Error())
	} else {
		v.Set("ok", okMsg)
	}
	http.Redirect(w, r, masterAdminSectionPath(section)+"?"+v.Encode(), http.StatusSeeOther)
}

func (s *server) reloadRuntimeUsersFromStore(r *http.Request) error {
	users, err := s.store.ListUIUsers(r.Context())
	if err != nil {
		return err
	}
	runtime := s.uiRuntime()
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.users = map[string]uiUserConfig{}
	for _, user := range users {
		runtime.users[user.Username] = user
	}
	return nil
}

func (s *server) masterAdminCreateUser(r *http.Request) (error, string) {
	username := strings.TrimSpace(r.FormValue("username"))
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	role := normalizeUIRole(r.FormValue("role"))
	password := r.FormValue("password")
	if username == "" {
		return fmt.Errorf("username is required"), ""
	}
	if strings.TrimSpace(password) == "" {
		return fmt.Errorf("password is required"), ""
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err, ""
	}
	accounts := normalizeAccounts(splitCommaList(accountsFormValue(r)))
	for _, account := range accounts {
		if err := s.store.UpsertUIAccount(r.Context(), account); err != nil {
			return err, ""
		}
	}
	if err := s.store.UpsertUIUser(r.Context(), uiUserConfig{Username: username, PasswordHash: hash, Role: role, DisplayName: displayName, Accounts: accounts}); err != nil {
		return err, ""
	}
	return nil, "user created"
}

func (s *server) masterAdminUpdateUser(r *http.Request) (error, string) {
	username := strings.TrimSpace(r.FormValue("username"))
	if username == "" {
		return fmt.Errorf("username is required"), ""
	}
	users, err := s.store.ListUIUsers(r.Context())
	if err != nil {
		return err, ""
	}
	current, ok := findUser(users, username)
	if !ok {
		return fmt.Errorf("user not found"), ""
	}
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	if displayName == "" {
		displayName = current.DisplayName
	}
	role := normalizeUIRole(r.FormValue("role"))
	if role == "" {
		role = current.Role
	}
	accounts := normalizeAccounts(splitCommaList(accountsFormValue(r)))
	for _, account := range accounts {
		if err := s.store.UpsertUIAccount(r.Context(), account); err != nil {
			return err, ""
		}
	}
	hash := strings.TrimSpace(current.PasswordHash)
	if password := strings.TrimSpace(r.FormValue("password")); password != "" {
		h, err := hashPassword(password)
		if err != nil {
			return err, ""
		}
		hash = h
	}
	if err := s.store.UpsertUIUser(r.Context(), uiUserConfig{Username: username, PasswordHash: hash, Role: role, DisplayName: displayName, Accounts: accounts}); err != nil {
		return err, ""
	}
	return nil, "user updated"
}

func (s *server) masterAdminDeleteUser(r *http.Request, session *uiSession) (error, string) {
	username := strings.TrimSpace(r.FormValue("username"))
	if username == "" {
		return fmt.Errorf("username is required"), ""
	}
	if username == session.Username {
		return fmt.Errorf("you cannot delete your active account"), ""
	}
	if err := s.store.DeleteUIUser(r.Context(), username); err != nil {
		return err, ""
	}
	return nil, "user deleted"
}

func (s *server) masterAdminSetRole(r *http.Request) (error, string) {
	username := strings.TrimSpace(r.FormValue("username"))
	role := normalizeUIRole(r.FormValue("role"))
	if username == "" {
		return fmt.Errorf("username is required"), ""
	}
	users, err := s.store.ListUIUsers(r.Context())
	if err != nil {
		return err, ""
	}
	current, ok := findUser(users, username)
	if !ok {
		return fmt.Errorf("user not found"), ""
	}
	if err := s.store.UpsertUIUser(r.Context(), uiUserConfig{Username: username, PasswordHash: current.PasswordHash, Role: role, DisplayName: current.DisplayName, Accounts: current.Accounts}); err != nil {
		return err, ""
	}
	return nil, "role updated"
}

func (s *server) masterAdminCreateAccount(r *http.Request) (error, string) {
	account := normalizeAccountName(accountFormValue(r))
	if account == "" {
		return fmt.Errorf("account is required"), ""
	}
	if err := s.store.UpsertUIAccount(r.Context(), account); err != nil {
		return err, ""
	}
	return nil, "account created"
}

func (s *server) masterAdminDeleteAccount(r *http.Request) (error, string) {
	account := normalizeAccountName(accountFormValue(r))
	if account == "" {
		return fmt.Errorf("account is required"), ""
	}
	if err := s.store.DeleteUIAccount(r.Context(), account); err != nil {
		return err, ""
	}
	users, err := s.store.ListUIUsers(r.Context())
	if err != nil {
		return err, ""
	}
	for _, user := range users {
		filtered := make([]string, 0, len(user.Accounts))
		for _, a := range user.Accounts {
			if normalizeAccountName(a) != account {
				filtered = append(filtered, a)
			}
		}
		if len(filtered) != len(user.Accounts) {
			if err := s.store.UpsertUIUser(r.Context(), uiUserConfig{Username: user.Username, PasswordHash: user.PasswordHash, Role: user.Role, DisplayName: user.DisplayName, Accounts: filtered}); err != nil {
				return err, ""
			}
		}
	}
	return nil, "account deleted"
}

func (s *server) masterAdminAssignAccount(r *http.Request) (error, string) {
	username := strings.TrimSpace(r.FormValue("username"))
	account := normalizeAccountName(accountFormValue(r))
	if username == "" || account == "" {
		return fmt.Errorf("username and account are required"), ""
	}
	users, err := s.store.ListUIUsers(r.Context())
	if err != nil {
		return err, ""
	}
	current, ok := findUser(users, username)
	if !ok {
		return fmt.Errorf("user not found"), ""
	}
	if err := s.store.UpsertUIAccount(r.Context(), account); err != nil {
		return err, ""
	}
	accounts := append([]string{}, current.Accounts...)
	accounts = append(accounts, account)
	accounts = normalizeAccounts(accounts)
	if err := s.store.UpsertUIUser(r.Context(), uiUserConfig{Username: current.Username, PasswordHash: current.PasswordHash, Role: current.Role, DisplayName: current.DisplayName, Accounts: accounts}); err != nil {
		return err, ""
	}
	return nil, "account assigned"
}

func (s *server) masterAdminRemoveAccount(r *http.Request) (error, string) {
	username := strings.TrimSpace(r.FormValue("username"))
	account := normalizeAccountName(accountFormValue(r))
	if username == "" || account == "" {
		return fmt.Errorf("username and account are required"), ""
	}
	users, err := s.store.ListUIUsers(r.Context())
	if err != nil {
		return err, ""
	}
	current, ok := findUser(users, username)
	if !ok {
		return fmt.Errorf("user not found"), ""
	}
	filtered := make([]string, 0, len(current.Accounts))
	for _, a := range current.Accounts {
		if normalizeAccountName(a) != account {
			filtered = append(filtered, a)
		}
	}
	if err := s.store.UpsertUIUser(r.Context(), uiUserConfig{Username: current.Username, PasswordHash: current.PasswordHash, Role: current.Role, DisplayName: current.DisplayName, Accounts: filtered}); err != nil {
		return err, ""
	}
	return nil, "account removed from user"
}

// masterAdminUpdateAWSSettings persists the deployment region and account ID
// used when building resource ARNs, then rewrites existing ARNs to match.
func (s *server) masterAdminUpdateAWSSettings(r *http.Request) (error, string) {
	dbStoreImpl, ok := s.store.(*dbStore)
	if !ok {
		return fmt.Errorf("AWS settings require a database-backed deployment"), ""
	}
	region := strings.TrimSpace(r.FormValue("aws_region"))
	accountID := strings.TrimSpace(r.FormValue("aws_account_id"))
	if !isValidRegion(region) {
		return fmt.Errorf("invalid region"), ""
	}
	if !isValidAccountID(accountID) {
		return fmt.Errorf("account ID must be 12 digits"), ""
	}
	if err := putSetting(r.Context(), dbStoreImpl.db, settingAWSRegion, region); err != nil {
		return err, ""
	}
	if err := putSetting(r.Context(), dbStoreImpl.db, settingAWSAccountID, accountID); err != nil {
		return err, ""
	}
	dbStoreImpl.region = region
	dbStoreImpl.accountID = accountID
	if err := dbStoreImpl.migrateResourceARNs(r.Context()); err != nil {
		return err, ""
	}
	return nil, "AWS settings updated"
}

// accountFormValue accepts both the new account field and the legacy tenant
// field name so older bookmarked forms keep working.
func accountFormValue(r *http.Request) string {
	if v := strings.TrimSpace(r.FormValue("account")); v != "" {
		return v
	}
	return strings.TrimSpace(r.FormValue("tenant"))
}

func accountsFormValue(r *http.Request) string {
	if v := strings.TrimSpace(r.FormValue("accounts")); v != "" {
		return v
	}
	return strings.TrimSpace(r.FormValue("tenants"))
}

func masterAdminSectionPath(section string) string {
	switch section {
	case "users":
		return "/admin/users"
	case "rbac":
		return "/admin/rbac"
	case "accounts":
		return "/admin/accounts"
	case "settings":
		return "/admin/settings"
	default:
		return "/admin"
	}
}
