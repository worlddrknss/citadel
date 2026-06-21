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
	Tenants     string
}

type masterAdminPageView struct {
	Section         string
	CurrentUserName string
	CurrentUserRole string
	TenantScope     []string
	CanAdmin        bool
	Users           []masterAdminUserView
	Roles           []string
	Tenants         []string
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

func (s *server) handleMasterAdminTenants(w http.ResponseWriter, r *http.Request) {
	s.renderMasterAdminSection(w, r, "tenants")
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

	users, roleList, tenantList := s.loadMasterAdminData(r)

	view := masterAdminPageView{
		Section:         section,
		CurrentUserName: session.DisplayName,
		CurrentUserRole: session.Role,
		TenantScope:     append([]string(nil), session.Tenants...),
		CanAdmin:        uiCanAdmin(session),
		Users:           users,
		Roles:           roleList,
		Tenants:         tenantList,
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
	tenants := map[string]struct{}{}

	runtime := s.uiRuntime()
	runtime.mu.Lock()
	for _, user := range runtime.users {
		roles[user.Role] = struct{}{}
		for _, tenant := range user.Tenants {
			tenant = normalizeTenantName(tenant)
			if tenant != "" {
				tenants[tenant] = struct{}{}
			}
		}
		users = append(users, masterAdminUserView{
			Username:    user.Username,
			DisplayName: user.DisplayName,
			Role:        user.Role,
			Tenants:     strings.Join(user.Tenants, ", "),
		})
	}
	runtime.mu.Unlock()

	if storedTenants, err := s.store.ListUITenants(r.Context()); err == nil {
		for _, tenant := range storedTenants {
			tenant = normalizeTenantName(tenant)
			if tenant != "" {
				tenants[tenant] = struct{}{}
			}
		}
	}

	sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
	roleList := make([]string, 0, len(roles))
	for role := range roles {
		roleList = append(roleList, role)
	}
	sort.Strings(roleList)
	tenantList := make([]string, 0, len(tenants))
	for tenant := range tenants {
		tenantList = append(tenantList, tenant)
	}
	sort.Strings(tenantList)
	return users, roleList, tenantList
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
	case "create_tenant":
		err, okMsg = s.masterAdminCreateTenant(r)
	case "delete_tenant":
		err, okMsg = s.masterAdminDeleteTenant(r)
	case "assign_tenant":
		err, okMsg = s.masterAdminAssignTenant(r)
	case "remove_tenant":
		err, okMsg = s.masterAdminRemoveTenant(r)
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
	tenants := normalizeTenants(splitCommaList(r.FormValue("tenants")))
	for _, tenant := range tenants {
		if err := s.store.UpsertUITenant(r.Context(), tenant); err != nil {
			return err, ""
		}
	}
	if err := s.store.UpsertUIUser(r.Context(), uiUserConfig{Username: username, PasswordHash: hash, Role: role, DisplayName: displayName, Tenants: tenants}); err != nil {
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
	tenants := normalizeTenants(splitCommaList(r.FormValue("tenants")))
	for _, tenant := range tenants {
		if err := s.store.UpsertUITenant(r.Context(), tenant); err != nil {
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
	if err := s.store.UpsertUIUser(r.Context(), uiUserConfig{Username: username, PasswordHash: hash, Role: role, DisplayName: displayName, Tenants: tenants}); err != nil {
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
	if err := s.store.UpsertUIUser(r.Context(), uiUserConfig{Username: username, PasswordHash: current.PasswordHash, Role: role, DisplayName: current.DisplayName, Tenants: current.Tenants}); err != nil {
		return err, ""
	}
	return nil, "role updated"
}

func (s *server) masterAdminCreateTenant(r *http.Request) (error, string) {
	tenant := normalizeTenantName(r.FormValue("tenant"))
	if tenant == "" {
		return fmt.Errorf("tenant is required"), ""
	}
	if err := s.store.UpsertUITenant(r.Context(), tenant); err != nil {
		return err, ""
	}
	return nil, "tenant created"
}

func (s *server) masterAdminDeleteTenant(r *http.Request) (error, string) {
	tenant := normalizeTenantName(r.FormValue("tenant"))
	if tenant == "" {
		return fmt.Errorf("tenant is required"), ""
	}
	if err := s.store.DeleteUITenant(r.Context(), tenant); err != nil {
		return err, ""
	}
	users, err := s.store.ListUIUsers(r.Context())
	if err != nil {
		return err, ""
	}
	for _, user := range users {
		filtered := make([]string, 0, len(user.Tenants))
		for _, t := range user.Tenants {
			if normalizeTenantName(t) != tenant {
				filtered = append(filtered, t)
			}
		}
		if len(filtered) != len(user.Tenants) {
			if err := s.store.UpsertUIUser(r.Context(), uiUserConfig{Username: user.Username, PasswordHash: user.PasswordHash, Role: user.Role, DisplayName: user.DisplayName, Tenants: filtered}); err != nil {
				return err, ""
			}
		}
	}
	return nil, "tenant deleted"
}

func (s *server) masterAdminAssignTenant(r *http.Request) (error, string) {
	username := strings.TrimSpace(r.FormValue("username"))
	tenant := normalizeTenantName(r.FormValue("tenant"))
	if username == "" || tenant == "" {
		return fmt.Errorf("username and tenant are required"), ""
	}
	users, err := s.store.ListUIUsers(r.Context())
	if err != nil {
		return err, ""
	}
	current, ok := findUser(users, username)
	if !ok {
		return fmt.Errorf("user not found"), ""
	}
	if err := s.store.UpsertUITenant(r.Context(), tenant); err != nil {
		return err, ""
	}
	tenants := append([]string{}, current.Tenants...)
	tenants = append(tenants, tenant)
	tenants = normalizeTenants(tenants)
	if err := s.store.UpsertUIUser(r.Context(), uiUserConfig{Username: current.Username, PasswordHash: current.PasswordHash, Role: current.Role, DisplayName: current.DisplayName, Tenants: tenants}); err != nil {
		return err, ""
	}
	return nil, "tenant assigned"
}

func (s *server) masterAdminRemoveTenant(r *http.Request) (error, string) {
	username := strings.TrimSpace(r.FormValue("username"))
	tenant := normalizeTenantName(r.FormValue("tenant"))
	if username == "" || tenant == "" {
		return fmt.Errorf("username and tenant are required"), ""
	}
	users, err := s.store.ListUIUsers(r.Context())
	if err != nil {
		return err, ""
	}
	current, ok := findUser(users, username)
	if !ok {
		return fmt.Errorf("user not found"), ""
	}
	filtered := make([]string, 0, len(current.Tenants))
	for _, t := range current.Tenants {
		if normalizeTenantName(t) != tenant {
			filtered = append(filtered, t)
		}
	}
	if err := s.store.UpsertUIUser(r.Context(), uiUserConfig{Username: current.Username, PasswordHash: current.PasswordHash, Role: current.Role, DisplayName: current.DisplayName, Tenants: filtered}); err != nil {
		return err, ""
	}
	return nil, "tenant removed from user"
}

func masterAdminSectionPath(section string) string {
	switch section {
	case "users":
		return "/admin/users"
	case "rbac":
		return "/admin/rbac"
	case "tenants":
		return "/admin/tenants"
	default:
		return "/admin"
	}
}
