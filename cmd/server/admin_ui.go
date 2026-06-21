package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

//go:embed templates/*.html
var uiTemplatesFS embed.FS

var adminTemplate = template.Must(template.ParseFS(uiTemplatesFS, "templates/admin.html"))

type adminKeyView struct {
	ID           string
	ARN          string
	Description  string
	CreatedAt    string
	Alias        string
	State        string
	DeletionDate string
	IsSelected   bool
}

type adminAliasView struct {
	Name      string
	TargetKey string
}

type adminGrantView struct {
	GrantID           string
	GranteePrincipal  string
	RetiringPrincipal string
	Operations        string
	Name              string
	CreatedAt         string
}

type adminPageView struct {
	Keys            []adminKeyView
	Aliases         []adminAliasView
	AvailableKeyIDs []string
	KeyCount        int
	VisibleKeyCount int
	SelectedKey     *adminKeyView
	SelectedKeyID   string
	SelectedTab     string
	PolicyName      string
	PolicyDocument  string
	Grants          []adminGrantView
	CurrentUserName string
	CurrentUserRole string
	TenantScope     []string
	CanEdit         bool
	CanAdmin        bool
	Flash           string
	Error           string
}

func (s *server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	requiredRole := "viewer"
	switch r.URL.Query().Get("action") {
	case "create_alias", "update_alias", "enable_key", "disable_key":
		requiredRole = "editor"
	case "create_key", "schedule_deletion", "cancel_deletion", "put_key_policy":
		requiredRole = "admin"
	}
	session, ok := s.requireUISession(w, r, requiredRole)
	if !ok {
		return
	}
	action := r.URL.Query().Get("action")
	if action != "" && !uiCanAdmin(session) {
		aliases, _ := s.store.ListAliases(r.Context())
		targetKeyID := strings.TrimSpace(r.FormValue("key_id"))
		if targetKeyID == "" {
			targetKeyID = strings.TrimSpace(r.FormValue("target_key_id"))
		}
		if targetKeyID != "" && !keyVisibleToSession(session, targetKeyID, aliases) {
			s.redirectAdminError(w, r, "requested key is outside your tenant scope")
			return
		}
	}

	switch action {
	case "create_key":
		s.handleAdminCreateKey(w, r)
		return
	case "create_grant":
		s.handleAdminCreateGrant(w, r)
		return
	case "revoke_grant":
		s.handleAdminRevokeGrant(w, r)
		return
	case "bulk_keys":
		s.handleAdminBulkKeys(w, r)
		return
	case "create_alias":
		s.handleAdminCreateAlias(w, r)
		return
	case "update_alias":
		s.handleAdminUpdateAlias(w, r)
		return
	case "enable_key":
		s.handleAdminSetKeyEnabled(w, r, true)
		return
	case "disable_key":
		s.handleAdminSetKeyEnabled(w, r, false)
		return
	case "schedule_deletion":
		s.handleAdminScheduleKeyDeletion(w, r)
		return
	case "cancel_deletion":
		s.handleAdminCancelKeyDeletion(w, r)
		return
	case "force_delete":
		s.handleAdminForceDeleteKey(w, r)
		return
	case "put_key_policy":
		s.handleAdminPutKeyPolicy(w, r)
		return
	}

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	keys, err := s.store.ListKeys(r.Context())
	if err != nil {
		http.Error(w, "failed to list keys", http.StatusInternalServerError)
		return
	}
	aliases, err := s.store.ListAliases(r.Context())
	if err != nil {
		aliases = nil
	}

	view := adminPageView{
		Keys:            make([]adminKeyView, 0, len(keys)),
		Aliases:         make([]adminAliasView, 0, len(aliases)),
		AvailableKeyIDs: make([]string, 0, len(keys)),
		KeyCount:        len(keys),
		CurrentUserName: session.DisplayName,
		CurrentUserRole: session.Role,
		TenantScope:     append([]string(nil), session.Tenants...),
		CanEdit:         uiCanEdit(session),
		CanAdmin:        uiCanAdmin(session),
		SelectedKeyID:   strings.TrimSpace(r.URL.Query().Get("key_id")),
		SelectedTab:     strings.TrimSpace(r.URL.Query().Get("tab")),
		PolicyName:      strings.TrimSpace(r.URL.Query().Get("policy_name")),
		Flash:           r.URL.Query().Get("ok"),
		Error:           r.URL.Query().Get("err"),
	}
	if view.SelectedTab == "" {
		view.SelectedTab = "key-policy"
	}
	if view.PolicyName == "" {
		view.PolicyName = "default"
	}

	aliasByKey := map[string]string{}
	for _, a := range aliases {
		if _, exists := aliasByKey[a.TargetKeyID]; !exists {
			aliasByKey[a.TargetKeyID] = a.AliasName
		}
	}

	for _, k := range keys {
		if !keyVisibleToSession(session, k.ID, aliases) {
			continue
		}
		deletionDate := ""
		if k.DeletionDate != nil {
			deletionDate = k.DeletionDate.UTC().Format(time.RFC3339)
		}
		createdAt := k.CreatedAt.UTC().Format("2006-01-02 15:04:05 MST")
		isSelected := view.SelectedKeyID != "" && k.ID == view.SelectedKeyID
		view.AvailableKeyIDs = append(view.AvailableKeyIDs, k.ID)
		entry := adminKeyView{
			ID:           k.ID,
			ARN:          k.ARN,
			Description:  k.Description,
			CreatedAt:    createdAt,
			Alias:        aliasByKey[k.ID],
			State:        keyState(k),
			DeletionDate: deletionDate,
			IsSelected:   isSelected,
		}
		view.Keys = append(view.Keys, entry)
		if isSelected {
			selected := entry
			view.SelectedKey = &selected
		}
	}
	view.VisibleKeyCount = len(view.Keys)
	for _, a := range aliases {
		if !keyVisibleToSession(session, a.TargetKeyID, aliases) {
			continue
		}
		view.Aliases = append(view.Aliases, adminAliasView{Name: a.AliasName, TargetKey: a.TargetKeyID})
	}
	if view.SelectedKeyID != "" && view.SelectedKey == nil {
		view.Error = "requested key is outside your tenant scope"
	}

	if view.SelectedKey != nil {
		policyDocument, err := s.store.GetKeyPolicy(r.Context(), view.SelectedKeyID, view.PolicyName)
		if err != nil {
			view.Error = fmt.Sprintf("failed to load policy: %v", err)
		} else {
			var doc any
			if jsonErr := json.Unmarshal([]byte(policyDocument), &doc); jsonErr == nil {
				if pretty, marshalErr := json.MarshalIndent(doc, "", "  "); marshalErr == nil {
					policyDocument = string(pretty)
				}
			}
			view.PolicyDocument = policyDocument
		}
		if grants, err := s.store.ListGrants(r.Context(), view.SelectedKeyID); err == nil {
			for _, grant := range grants {
				view.Grants = append(view.Grants, adminGrantView{GrantID: grant.GrantID, GranteePrincipal: grant.GranteePrincipal, RetiringPrincipal: grant.RetiringPrincipal, Operations: strings.Join(grant.Operations, ", "), Name: grant.Name, CreatedAt: grant.CreatedAt.UTC().Format("2006-01-02 15:04:05 MST")})
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := adminTemplate.Execute(w, view); err != nil {
		http.Error(w, "failed to render admin view", http.StatusInternalServerError)
		return
	}
}

func (s *server) handleAdminCreateKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.redirectAdminError(w, r, "create key requires POST")
		return
	}
	description := strings.TrimSpace(r.FormValue("description"))
	k, err := s.store.CreateKey(r.Context(), description, keyUsageEncryptDecrypt, keySpecSymmetricDefault)
	if err != nil {
		s.redirectAdminError(w, r, fmt.Sprintf("create key failed: %v", err))
		return
	}
	s.redirectAdminKeyOK(w, r, k.ID, "key-policy", "key created")
}

func (s *server) handleAdminCreateAlias(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.redirectAdminError(w, r, "create alias requires POST")
		return
	}
	aliasName := normalizeAlias(strings.TrimSpace(r.FormValue("alias_name")))
	targetKeyID := strings.TrimSpace(r.FormValue("target_key_id"))
	if aliasName == "" || targetKeyID == "" {
		s.redirectAdminError(w, r, "alias_name and target_key_id are required")
		return
	}
	if err := s.store.CreateAlias(r.Context(), aliasName, targetKeyID); err != nil {
		s.redirectAdminError(w, r, fmt.Sprintf("create alias failed: %v", err))
		return
	}
	s.redirectAdminKeyOK(w, r, targetKeyID, "aliases", "alias created")
}

func (s *server) handleAdminUpdateAlias(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.redirectAdminError(w, r, "update alias requires POST")
		return
	}
	aliasName := normalizeAlias(strings.TrimSpace(r.FormValue("alias_name")))
	targetKeyID := strings.TrimSpace(r.FormValue("target_key_id"))
	if aliasName == "" || targetKeyID == "" {
		s.redirectAdminError(w, r, "alias_name and target_key_id are required")
		return
	}
	if err := s.store.UpdateAlias(r.Context(), aliasName, targetKeyID); err != nil {
		s.redirectAdminError(w, r, fmt.Sprintf("update alias failed: %v", err))
		return
	}
	s.redirectAdminKeyOK(w, r, targetKeyID, "aliases", "alias updated")
}

func (s *server) handleAdminSetKeyEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	if r.Method != http.MethodPost {
		s.redirectAdminError(w, r, "key state updates require POST")
		return
	}
	keyID := strings.TrimSpace(r.FormValue("key_id"))
	if keyID == "" {
		s.redirectAdminError(w, r, "key_id is required")
		return
	}
	if err := s.store.SetKeyEnabled(r.Context(), keyID, enabled); err != nil {
		s.redirectAdminError(w, r, fmt.Sprintf("update key state failed: %v", err))
		return
	}
	if enabled {
		s.redirectAdminKeyOK(w, r, keyID, "key-policy", "key enabled")
		return
	}
	s.redirectAdminKeyOK(w, r, keyID, "key-policy", "key disabled")
}

func (s *server) handleAdminScheduleKeyDeletion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.redirectAdminError(w, r, "schedule deletion requires POST")
		return
	}
	keyID := strings.TrimSpace(r.FormValue("key_id"))
	if keyID == "" {
		s.redirectAdminError(w, r, "key_id is required")
		return
	}
	days, err := strconv.Atoi(strings.TrimSpace(r.FormValue("window_days")))
	if err != nil || days < 7 || days > 30 {
		s.redirectAdminError(w, r, "window_days must be between 7 and 30")
		return
	}
	if _, err := s.store.ScheduleKeyDeletion(r.Context(), keyID, days); err != nil {
		s.redirectAdminError(w, r, fmt.Sprintf("schedule deletion failed: %v", err))
		return
	}
	s.redirectAdminKeyOK(w, r, keyID, "key-policy", "key deletion scheduled")
}

func (s *server) handleAdminCancelKeyDeletion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.redirectAdminError(w, r, "cancel deletion requires POST")
		return
	}
	keyID := strings.TrimSpace(r.FormValue("key_id"))
	if keyID == "" {
		s.redirectAdminError(w, r, "key_id is required")
		return
	}
	if err := s.store.CancelKeyDeletion(r.Context(), keyID); err != nil {
		s.redirectAdminError(w, r, fmt.Sprintf("cancel deletion failed: %v", err))
		return
	}
	s.redirectAdminKeyOK(w, r, keyID, "key-policy", "key deletion canceled")
}

func (s *server) handleAdminForceDeleteKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.redirectAdminError(w, r, "force delete requires POST")
		return
	}
	if _, ok := s.requireUISession(w, r, "admin"); !ok {
		return
	}
	keyID := strings.TrimSpace(r.FormValue("key_id"))
	if keyID == "" {
		s.redirectAdminError(w, r, "key_id is required")
		return
	}
	if err := s.store.ForceDeleteKey(r.Context(), keyID); err != nil {
		s.redirectAdminError(w, r, fmt.Sprintf("force delete failed: %v", err))
		return
	}
	s.redirectAdminOK(w, r, "key force deleted")
}

func (s *server) handleAdminPutKeyPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.redirectAdminError(w, r, "put key policy requires POST")
		return
	}
	keyID := strings.TrimSpace(r.FormValue("key_id"))
	policyName := strings.TrimSpace(r.FormValue("policy_name"))
	policyDocument := strings.TrimSpace(r.FormValue("policy_document"))
	if keyID == "" {
		s.redirectAdminError(w, r, "key_id is required")
		return
	}
	if policyName == "" {
		policyName = "default"
	}
	if policyDocument == "" {
		s.redirectAdminKeyError(w, r, keyID, "key-policy", "policy_document is required")
		return
	}
	normalizedPolicy, err := normalizePolicyDocument(policyDocument)
	if err != nil {
		s.redirectAdminKeyError(w, r, keyID, "key-policy", "policy_document must be valid JSON")
		return
	}
	if err := s.store.PutKeyPolicy(r.Context(), keyID, policyName, normalizedPolicy); err != nil {
		s.redirectAdminKeyError(w, r, keyID, "key-policy", fmt.Sprintf("put key policy failed: %v", err))
		return
	}
	s.redirectAdminKeyOK(w, r, keyID, "key-policy", "key policy updated")
}

func (s *server) handleAdminBulkKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.redirectAdminError(w, r, "bulk key updates require POST")
		return
	}
	keyIDs := r.Form["key_id"]
	if len(keyIDs) == 0 {
		s.redirectAdminError(w, r, "select at least one key")
		return
	}
	action := strings.TrimSpace(r.FormValue("bulk_action"))
	updated := 0
	for _, keyID := range keyIDs {
		keyID = strings.TrimSpace(keyID)
		if keyID == "" {
			continue
		}
		switch action {
		case "enable":
			if err := s.store.SetKeyEnabled(r.Context(), keyID, true); err == nil {
				updated++
			}
		case "disable":
			if err := s.store.SetKeyEnabled(r.Context(), keyID, false); err == nil {
				updated++
			}
		case "schedule_deletion":
			if _, ok := s.requireUISession(w, r, "admin"); !ok {
				return
			}
			if _, err := s.store.ScheduleKeyDeletion(r.Context(), keyID, 30); err == nil {
				updated++
			}
		case "force_delete":
			if _, ok := s.requireUISession(w, r, "admin"); !ok {
				return
			}
			if err := s.store.ForceDeleteKey(r.Context(), keyID); err == nil {
				updated++
			}
		}
	}
	if updated == 0 {
		s.redirectAdminError(w, r, "no keys were updated")
		return
	}
	s.redirectAdminOK(w, r, fmt.Sprintf("updated %d keys", updated))
}

func (s *server) handleAdminCreateGrant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.redirectAdminError(w, r, "create grant requires POST")
		return
	}
	keyID := strings.TrimSpace(r.FormValue("key_id"))
	principal := strings.TrimSpace(r.FormValue("grantee_principal"))
	operations := splitCommaList(r.FormValue("operations"))
	if keyID == "" || principal == "" || len(operations) == 0 {
		s.redirectAdminKeyError(w, r, keyID, "grants", "key_id, grantee_principal, and operations are required")
		return
	}
	_, err := s.store.CreateGrant(r.Context(), createGrantRequest{KeyID: keyID, GranteePrincipal: principal, RetiringPrincipal: strings.TrimSpace(r.FormValue("retiring_principal")), Operations: operations, Name: strings.TrimSpace(r.FormValue("grant_name"))})
	if err != nil {
		s.redirectAdminKeyError(w, r, keyID, "grants", fmt.Sprintf("create grant failed: %v", err))
		return
	}
	s.redirectAdminKeyOK(w, r, keyID, "grants", "grant created")
}

func (s *server) handleAdminRevokeGrant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.redirectAdminError(w, r, "revoke grant requires POST")
		return
	}
	keyID := strings.TrimSpace(r.FormValue("key_id"))
	grantID := strings.TrimSpace(r.FormValue("grant_id"))
	if keyID == "" || grantID == "" {
		s.redirectAdminKeyError(w, r, keyID, "grants", "key_id and grant_id are required")
		return
	}
	if err := s.store.RevokeGrant(r.Context(), keyID, grantID); err != nil {
		s.redirectAdminKeyError(w, r, keyID, "grants", fmt.Sprintf("revoke grant failed: %v", err))
		return
	}
	s.redirectAdminKeyOK(w, r, keyID, "grants", "grant revoked")
}

func (s *server) redirectAdminOK(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/?ok="+url.QueryEscape(msg), http.StatusSeeOther)
}

func (s *server) redirectAdminError(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/?err="+url.QueryEscape(msg), http.StatusSeeOther)
}

func (s *server) redirectAdminKeyOK(w http.ResponseWriter, r *http.Request, keyID, tab, msg string) {
	v := url.Values{}
	v.Set("ok", msg)
	if keyID != "" {
		v.Set("key_id", keyID)
	}
	if tab != "" {
		v.Set("tab", tab)
	}
	http.Redirect(w, r, "/?"+v.Encode(), http.StatusSeeOther)
}

func (s *server) redirectAdminKeyError(w http.ResponseWriter, r *http.Request, keyID, tab, msg string) {
	v := url.Values{}
	v.Set("err", msg)
	if keyID != "" {
		v.Set("key_id", keyID)
	}
	if tab != "" {
		v.Set("tab", tab)
	}
	http.Redirect(w, r, "/?"+v.Encode(), http.StatusSeeOther)
}

func normalizeAlias(alias string) string {
	if alias == "" {
		return ""
	}
	if strings.HasPrefix(alias, "alias/") {
		return alias
	}
	return "alias/" + alias
}
