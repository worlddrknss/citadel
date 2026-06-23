package main

import (
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var auditTemplate = template.Must(template.ParseFS(uiTemplatesFS, "templates/admin_audit.html"))

type auditExplorerRow struct {
	ID        int64
	Time      string
	Service   string
	Action    string
	KeyID     string
	Result    string
	ErrorType string
	Actor     string
	PrevHash  string
	EventHash string
}

type auditExplorerView struct {
	Rows            []auditExplorerRow
	SelectedServer  string
	Query           string
	ActorFilter     string
	SelectedEvent   *auditExplorerRow
	TotalCount      int
	VisibleCount    int
	FilteredCount   int
	Page            int
	PageSize        int
	TotalPages      int
	RangeStart      int
	RangeEnd        int
	HasPrev         bool
	HasNext         bool
	PrevPage        int
	NextPage        int
	KMSCount        int
	SecretsCount    int
	ErrorCount      int
	OkCount         int
	CurrentUserName string
	CurrentUserRole string
	Flash           string
	Error           string
}

func (s *server) handleAudit(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireUISession(w, r, "viewer")
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	records, err := s.store.ListAuditEvents(r.Context(), 2000)
	if err != nil {
		http.Error(w, "failed to list audit events", http.StatusInternalServerError)
		return
	}

	serviceFilter := normalizeAuditService(strings.TrimSpace(r.URL.Query().Get("service")))
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	actorFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("actor")))
	selectedEventID := strings.TrimSpace(r.URL.Query().Get("event"))
	view := auditExplorerView{
		SelectedServer:  serviceFilter,
		Query:           strings.TrimSpace(r.URL.Query().Get("q")),
		ActorFilter:     strings.TrimSpace(r.URL.Query().Get("actor")),
		TotalCount:      len(records),
		CurrentUserName: session.DisplayName,
		CurrentUserRole: session.Role,
		Flash:           r.URL.Query().Get("ok"),
		Error:           r.URL.Query().Get("err"),
	}
	if view.SelectedServer == "" {
		view.SelectedServer = "all"
	}

	for _, record := range records {
		svc := auditService(record.Action)
		switch svc {
		case "kms":
			view.KMSCount++
		case "secrets":
			view.SecretsCount++
		}
		if record.Result == "ok" {
			view.OkCount++
		} else {
			view.ErrorCount++
		}
		if view.SelectedServer != "all" && svc != view.SelectedServer {
			continue
		}
		if query != "" && !auditRecordMatches(record, query) {
			continue
		}
		if actorFilter != "" && !strings.Contains(strings.ToLower(record.Actor), actorFilter) {
			continue
		}
		row := auditExplorerRow{
			ID:        record.ID,
			Time:      record.CreatedAt.UTC().Format("2006-01-02 15:04:05 MST"),
			Service:   strings.ToUpper(svc),
			Action:    record.Action,
			KeyID:     record.KeyID,
			Result:    record.Result,
			ErrorType: record.ErrorType,
			Actor:     record.Actor,
			PrevHash:  record.PrevHash,
			EventHash: record.EventHash,
		}
		view.Rows = append(view.Rows, row)
		if selectedEventID != "" && selectedEventID == fmt.Sprintf("%d", record.ID) {
			selected := row
			view.SelectedEvent = &selected
		}
	}
	filtered := view.Rows
	view.FilteredCount = len(filtered)
	const auditPageSize = 50
	view.PageSize = auditPageSize
	page := 1
	if p := strings.TrimSpace(r.URL.Query().Get("page")); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			page = n
		}
	}
	view.TotalPages = (view.FilteredCount + auditPageSize - 1) / auditPageSize
	if view.TotalPages < 1 {
		view.TotalPages = 1
	}
	if page > view.TotalPages {
		page = view.TotalPages
	}
	view.Page = page
	start := (page - 1) * auditPageSize
	end := start + auditPageSize
	if start > view.FilteredCount {
		start = view.FilteredCount
	}
	if end > view.FilteredCount {
		end = view.FilteredCount
	}
	view.Rows = filtered[start:end]
	view.VisibleCount = len(view.Rows)
	if view.FilteredCount == 0 {
		view.RangeStart = 0
	} else {
		view.RangeStart = start + 1
	}
	view.RangeEnd = end
	view.HasPrev = page > 1
	view.HasNext = page < view.TotalPages
	view.PrevPage = page - 1
	view.NextPage = page + 1

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := auditTemplate.Execute(w, view); err != nil {
		http.Error(w, "failed to render audit view", http.StatusInternalServerError)
		return
	}
}

func auditService(action string) string {
	switch {
	case strings.HasPrefix(action, "TrentService."):
		return "kms"
	case strings.HasPrefix(action, "secretsmanager."):
		return "secrets"
	default:
		return "other"
	}
}

func normalizeAuditService(value string) string {
	switch value {
	case "kms", "secrets", "other", "all":
		return value
	default:
		return "all"
	}
}

func auditRecordMatches(record auditRecord, query string) bool {
	haystack := strings.ToLower(strings.Join([]string{
		record.Action,
		record.KeyID,
		record.Result,
		record.ErrorType,
		record.Actor,
		record.EventHash,
		record.PrevHash,
	}, " "))
	return strings.Contains(haystack, query)
}

func auditBadgeClass(result string) string {
	switch strings.ToLower(strings.TrimSpace(result)) {
	case "ok":
		return "ok"
	case "error":
		return "err"
	default:
		return "neutral"
	}
}

func auditTimeShort(ts time.Time) string {
	return ts.UTC().Format("Jan 2 15:04")
}
