package main

import (
	"embed"
	"html/template"
	"net/http"
)

//go:embed templates/*.html
var uiTemplatesFS embed.FS

var adminTemplate = template.Must(template.ParseFS(uiTemplatesFS, "templates/admin.html"))

type adminKeyView struct {
	ID    string
	State string
}

type adminAliasView struct {
	Name      string
	TargetKey string
}

type adminPageView struct {
	Keys    []adminKeyView
	Aliases []adminAliasView
}

func (s *server) handleAdmin(w http.ResponseWriter, r *http.Request) {
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
		Keys:    make([]adminKeyView, 0, len(keys)),
		Aliases: make([]adminAliasView, 0, len(aliases)),
	}
	for _, k := range keys {
		view.Keys = append(view.Keys, adminKeyView{ID: k.ID, State: keyState(k)})
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
