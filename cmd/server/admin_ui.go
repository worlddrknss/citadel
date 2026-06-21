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

type adminPageView struct {
	Keys            []adminKeyView
	Aliases         []adminAliasView
	AvailableKeyIDs []string
	SelectedKey     *adminKeyView
	SelectedKeyID   string
	SelectedTab     string
	PolicyName      string
	PolicyDocument  string
	Flash           string
	Error           string
}

func (s *server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Query().Get("action") {
	case "create_key":
		s.handleAdminCreateKey(w, r)
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

	if view.SelectedKeyID == "" && len(keys) > 0 {
		view.SelectedKeyID = keys[0].ID
	}

	for _, k := range keys {
		deletionDate := ""
		if k.DeletionDate != nil {
			deletionDate = k.DeletionDate.UTC().Format(time.RFC3339)
		}
		createdAt := k.CreatedAt.UTC().Format("2006-01-02 15:04:05 MST")
		isSelected := k.ID == view.SelectedKeyID
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
	for _, a := range aliases {
		view.Aliases = append(view.Aliases, adminAliasView{Name: a.AliasName, TargetKey: a.TargetKeyID})
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
	k, err := s.store.CreateKey(r.Context(), description)
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

func (s *server) redirectAdminOK(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/admin?ok="+url.QueryEscape(msg), http.StatusSeeOther)
}

func (s *server) redirectAdminError(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/admin?err="+url.QueryEscape(msg), http.StatusSeeOther)
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
	http.Redirect(w, r, "/admin?"+v.Encode(), http.StatusSeeOther)
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
	http.Redirect(w, r, "/admin?"+v.Encode(), http.StatusSeeOther)
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
