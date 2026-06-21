package main

import (
	"embed"
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
	State        string
	DeletionDate string
}

type adminAliasView struct {
	Name      string
	TargetKey string
}

type adminPageView struct {
	Keys           []adminKeyView
	Aliases        []adminAliasView
	AvailableKeyIDs []string
	Flash          string
	Error          string
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
		Flash:           r.URL.Query().Get("ok"),
		Error:           r.URL.Query().Get("err"),
	}
	for _, k := range keys {
		deletionDate := ""
		if k.DeletionDate != nil {
			deletionDate = k.DeletionDate.UTC().Format(time.RFC3339)
		}
		view.AvailableKeyIDs = append(view.AvailableKeyIDs, k.ID)
		view.Keys = append(view.Keys, adminKeyView{
			ID:           k.ID,
			ARN:          k.ARN,
			State:        keyState(k),
			DeletionDate: deletionDate,
		})
	}
	for _, a := range aliases {
		view.Aliases = append(view.Aliases, adminAliasView{Name: a.AliasName, TargetKey: a.TargetKeyID})
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
	if _, err := s.store.CreateKey(r.Context(), description); err != nil {
		s.redirectAdminError(w, r, fmt.Sprintf("create key failed: %v", err))
		return
	}
	s.redirectAdminOK(w, r, "key created")
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
	s.redirectAdminOK(w, r, "alias created")
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
	s.redirectAdminOK(w, r, "alias updated")
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
		s.redirectAdminOK(w, r, "key enabled")
		return
	}
	s.redirectAdminOK(w, r, "key disabled")
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
	s.redirectAdminOK(w, r, "key deletion scheduled")
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
	s.redirectAdminOK(w, r, "key deletion canceled")
}

func (s *server) redirectAdminOK(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/admin?ok="+url.QueryEscape(msg), http.StatusSeeOther)
}

func (s *server) redirectAdminError(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/admin?err="+url.QueryEscape(msg), http.StatusSeeOther)
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
