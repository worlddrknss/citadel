package main

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

var adminSecretsTemplate = template.Must(template.ParseFS(uiTemplatesFS, "templates/admin_secrets.html"))

type adminSecretView struct {
	Name                string
	ARN                 string
	Description         string
	KMSKeyID            string
	CreatedAt           string
	LastChangedAt       string
	DeletionDate        string
	State               string
	CurrentVersionID    string
	PreviousVersionID   string
	CurrentSecretString string
	CurrentSecretBinary string
	CurrentStages       []string
	HasBinaryValue      bool
	IsSelected          bool
	VersionRows         []adminSecretVersionView
	Tags                []secretTag
	PolicyDocument      string
	RotationEnabled     bool
	RotationLambdaARN   string
	RotationDays        int
	NextRotationDate    string
}

type adminSecretVersionView struct {
	VersionID string
	Stages    string
	CreatedAt string
}

type adminSecretsPageView struct {
	Secrets          []adminSecretView
	AvailableKeyIDs  []string
	SecretCount      int
	VisibleCount     int
	SelectedSecret   *adminSecretView
	SelectedSecretID string
	SelectedTab      string
	CurrentUserName  string
	CurrentUserRole  string
	AccountScope     []string
	CanEdit          bool
	CanAdmin         bool
	Flash            string
	Error            string
}

func (s *server) handleSecretsAdmin(w http.ResponseWriter, r *http.Request) {
	requiredRole := "viewer"
	switch r.URL.Query().Get("action") {
	case "create_secret", "update_secret", "put_secret_value", "tag_secret", "untag_secret", "rotate_secret", "cancel_rotate_secret", "promote_secret_version":
		requiredRole = "editor"
	case "delete_secret", "restore_secret", "put_secret_policy":
		requiredRole = "admin"
	}
	session, ok := s.requireUISession(w, r, requiredRole)
	if !ok {
		return
	}
	action := r.URL.Query().Get("action")
	if action != "" && !uiCanAdmin(session) {
		secretID := strings.TrimSpace(r.FormValue("secret_id"))
		if secretID == "" {
			secretID = strings.TrimSpace(r.FormValue("name"))
		}
		if secretID != "" && !secretVisibleToSession(session, secretID) {
			s.redirectAdminSecretsError(w, r, "requested secret is outside your account scope")
			return
		}
	}

	switch action {
	case "create_secret":
		s.handleAdminCreateSecret(w, r)
		return
	case "bulk_secrets":
		s.handleAdminBulkSecrets(w, r)
		return
	case "update_secret":
		s.handleAdminUpdateSecret(w, r)
		return
	case "put_secret_value":
		s.handleAdminPutSecretValue(w, r)
		return
	case "delete_secret":
		s.handleAdminDeleteSecret(w, r)
		return
	case "restore_secret":
		s.handleAdminRestoreSecret(w, r)
		return
	case "tag_secret":
		s.handleAdminTagSecret(w, r)
		return
	case "untag_secret":
		s.handleAdminUntagSecret(w, r)
		return
	case "put_secret_policy":
		s.handleAdminPutSecretPolicy(w, r)
		return
	case "rotate_secret":
		s.handleAdminRotateSecret(w, r)
		return
	case "cancel_rotate_secret":
		s.handleAdminCancelRotateSecret(w, r)
		return
	case "promote_secret_version":
		s.handleAdminPromoteSecretVersion(w, r)
		return
	}

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	secrets, err := s.store.ListSecrets(r.Context())
	if err != nil {
		http.Error(w, "failed to list secrets", http.StatusInternalServerError)
		return
	}
	keys, err := s.store.ListKeys(r.Context())
	if err != nil {
		keys = nil
	}

	view := adminSecretsPageView{
		Secrets:          make([]adminSecretView, 0, len(secrets)),
		AvailableKeyIDs:  make([]string, 0, len(keys)),
		SecretCount:      len(secrets),
		CurrentUserName:  session.DisplayName,
		CurrentUserRole:  session.Role,
		AccountScope:     append([]string(nil), session.Accounts...),
		CanEdit:          uiCanEdit(session),
		CanAdmin:         uiCanAdmin(session),
		SelectedSecretID: strings.TrimSpace(r.URL.Query().Get("secret_id")),
		SelectedTab:      strings.TrimSpace(r.URL.Query().Get("tab")),
		Flash:            r.URL.Query().Get("ok"),
		Error:            r.URL.Query().Get("err"),
	}
	if view.SelectedTab == "" {
		view.SelectedTab = "overview"
	}
	for _, key := range keys {
		view.AvailableKeyIDs = append(view.AvailableKeyIDs, key.ID)
	}

	for _, secret := range secrets {
		if !secretVisibleToSession(session, secret.Name) {
			continue
		}
		entry := adminSecretView{
			Name:              secret.Name,
			ARN:               secret.ARN,
			Description:       secret.Description,
			KMSKeyID:          secret.KMSKeyID,
			CreatedAt:         secret.CreatedAt.UTC().Format("2006-01-02 15:04:05 MST"),
			LastChangedAt:     secret.LastChangedDate.UTC().Format("2006-01-02 15:04:05 MST"),
			CurrentVersionID:  secret.CurrentVersionID,
			PreviousVersionID: secret.PreviousVersionID,
			State:             adminSecretState(secret),
			IsSelected:        view.SelectedSecretID != "" && view.SelectedSecretID == secret.Name,
		}
		if secret.DeletedDate != nil {
			entry.DeletionDate = secret.DeletedDate.UTC().Format(time.RFC3339)
		}
		view.Secrets = append(view.Secrets, entry)
	}
	view.VisibleCount = len(view.Secrets)

	if view.SelectedSecretID != "" {
		if !secretVisibleToSession(session, view.SelectedSecretID) {
			view.Error = "requested secret is outside your account scope"
		} else {
			meta, err := s.store.DescribeSecret(r.Context(), view.SelectedSecretID)
			if err != nil {
				view.Error = err.Error()
			} else {
				selected := adminSecretView{
					Name:              meta.Name,
					ARN:               meta.ARN,
					Description:       meta.Description,
					KMSKeyID:          meta.KMSKeyID,
					CreatedAt:         meta.CreatedAt.UTC().Format("2006-01-02 15:04:05 MST"),
					LastChangedAt:     meta.LastChangedDate.UTC().Format("2006-01-02 15:04:05 MST"),
					CurrentVersionID:  meta.CurrentVersionID,
					PreviousVersionID: meta.PreviousVersionID,
					Tags:              append([]secretTag(nil), meta.Tags...),
					PolicyDocument:    meta.PolicyDocument,
					RotationEnabled:   meta.RotationEnabled,
					RotationLambdaARN: meta.RotationLambdaARN,
					RotationDays:      meta.RotationDays,
					State:             adminSecretState(meta),
					IsSelected:        true,
				}
				if meta.DeletedDate != nil {
					selected.DeletionDate = meta.DeletedDate.UTC().Format(time.RFC3339)
				}
				if meta.NextRotationDate != nil {
					selected.NextRotationDate = meta.NextRotationDate.UTC().Format(time.RFC3339)
				}
				versions, err := s.store.ListSecretVersionIDs(r.Context(), meta.Name)
				if err == nil {
					for _, version := range versions {
						selected.VersionRows = append(selected.VersionRows, adminSecretVersionView{VersionID: version.VersionID, Stages: strings.Join(version.VersionStages, ", "), CreatedAt: version.CreatedDate.UTC().Format("2006-01-02 15:04:05 MST")})
					}
				} else {
					stageMap := secretVersionStagesMap(meta)
					versionIDs := make([]string, 0, len(stageMap))
					for versionID := range stageMap {
						versionIDs = append(versionIDs, versionID)
					}
					sort.Strings(versionIDs)
					for _, versionID := range versionIDs {
						selected.VersionRows = append(selected.VersionRows, adminSecretVersionView{VersionID: versionID, Stages: strings.Join(stageMap[versionID], ", ")})
					}
				}
				if strings.TrimSpace(selected.PolicyDocument) == "" {
					if policy, err := s.store.GetSecretResourcePolicy(r.Context(), meta.Name); err == nil {
						selected.PolicyDocument = policy
					}
				}
				if value, err := s.store.GetSecretValue(r.Context(), meta.Name, "", currentVersionStage); err == nil {
					selected.CurrentStages = value.VersionStages
					if value.SecretString != nil {
						selected.CurrentSecretString = *value.SecretString
					} else {
						selected.CurrentSecretBinary = value.SecretBinary
						selected.HasBinaryValue = true
					}
				}
				view.SelectedSecret = &selected
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := adminSecretsTemplate.Execute(w, view); err != nil {
		http.Error(w, "failed to render secrets admin view", http.StatusInternalServerError)
		return
	}
}

func (s *server) handleAdminCreateSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.redirectAdminSecretsError(w, r, "create secret requires POST")
		return
	}
	meta, _, err := s.store.CreateSecret(r.Context(), createSecretRequest{
		Name:         strings.TrimSpace(r.FormValue("name")),
		Description:  strings.TrimSpace(r.FormValue("description")),
		KMSKeyID:     strings.TrimSpace(r.FormValue("kms_key_id")),
		SecretString: r.FormValue("secret_string"),
	})
	if err != nil {
		s.redirectAdminSecretsError(w, r, err.Error())
		return
	}
	s.redirectAdminSecretOK(w, r, meta.Name, "overview", "secret created")
}

func (s *server) handleAdminUpdateSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.redirectAdminSecretsError(w, r, "update secret requires POST")
		return
	}
	secretID := strings.TrimSpace(r.FormValue("secret_id"))
	meta, _, err := s.store.UpdateSecret(r.Context(), updateSecretRequest{
		SecretID:    secretID,
		Description: strings.TrimSpace(r.FormValue("description")),
		KMSKeyID:    strings.TrimSpace(r.FormValue("kms_key_id")),
	})
	if err != nil {
		s.redirectAdminSecretError(w, r, secretID, "overview", err.Error())
		return
	}
	s.redirectAdminSecretOK(w, r, meta.Name, "overview", "secret metadata updated")
}

func (s *server) handleAdminPutSecretValue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.redirectAdminSecretsError(w, r, "put secret value requires POST")
		return
	}
	secretID := strings.TrimSpace(r.FormValue("secret_id"))
	value, err := s.store.PutSecretValue(r.Context(), putSecretValueRequest{
		SecretID:     secretID,
		SecretString: r.FormValue("secret_string"),
	})
	if err != nil {
		s.redirectAdminSecretError(w, r, secretID, "retrieve", err.Error())
		return
	}
	s.redirectAdminSecretOK(w, r, value.Name, "retrieve", "secret value updated")
}

func (s *server) handleAdminDeleteSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.redirectAdminSecretsError(w, r, "delete secret requires POST")
		return
	}
	secretID := strings.TrimSpace(r.FormValue("secret_id"))
	forceDelete := strings.EqualFold(strings.TrimSpace(r.FormValue("force_delete")), "true") || r.FormValue("force_delete") == "1"
	recoveryWindowDays := 30
	if forceDelete {
		recoveryWindowDays = 0
	}
	_, err := s.store.DeleteSecret(r.Context(), secretID, recoveryWindowDays, forceDelete)
	if err != nil {
		s.redirectAdminSecretError(w, r, secretID, "overview", err.Error())
		return
	}
	if forceDelete {
		s.redirectAdminSecretOK(w, r, "", "", "secret deleted immediately")
		return
	}
	s.redirectAdminSecretOK(w, r, secretID, "overview", "secret scheduled for deletion")
}

func (s *server) handleAdminRestoreSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.redirectAdminSecretsError(w, r, "restore secret requires POST")
		return
	}
	secretID := strings.TrimSpace(r.FormValue("secret_id"))
	meta, err := s.store.RestoreSecret(r.Context(), secretID)
	if err != nil {
		s.redirectAdminSecretError(w, r, secretID, "overview", err.Error())
		return
	}
	s.redirectAdminSecretOK(w, r, meta.Name, "overview", "secret restored")
}

func (s *server) handleAdminTagSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.redirectAdminSecretsError(w, r, "tag secret requires POST")
		return
	}
	secretID := strings.TrimSpace(r.FormValue("secret_id"))
	key := strings.TrimSpace(r.FormValue("tag_key"))
	value := r.FormValue("tag_value")
	if err := s.store.TagSecret(r.Context(), secretID, []secretTag{{Key: key, Value: value}}); err != nil {
		s.redirectAdminSecretError(w, r, secretID, "tags", err.Error())
		return
	}
	s.redirectAdminSecretOK(w, r, secretID, "tags", "tag updated")
}

func (s *server) handleAdminUntagSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.redirectAdminSecretsError(w, r, "untag secret requires POST")
		return
	}
	secretID := strings.TrimSpace(r.FormValue("secret_id"))
	tagKey := strings.TrimSpace(r.FormValue("tag_key"))
	if err := s.store.UntagSecret(r.Context(), secretID, []string{tagKey}); err != nil {
		s.redirectAdminSecretError(w, r, secretID, "tags", err.Error())
		return
	}
	s.redirectAdminSecretOK(w, r, secretID, "tags", "tag removed")
}

func (s *server) handleAdminPutSecretPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.redirectAdminSecretsError(w, r, "put secret policy requires POST")
		return
	}
	secretID := strings.TrimSpace(r.FormValue("secret_id"))
	policyDocument := strings.TrimSpace(r.FormValue("policy_document"))
	policy, err := normalizePolicyDocument(policyDocument)
	if err != nil {
		s.redirectAdminSecretError(w, r, secretID, "policy", "policy_document must be valid JSON")
		return
	}
	if err := s.store.PutSecretResourcePolicy(r.Context(), secretID, policy); err != nil {
		s.redirectAdminSecretError(w, r, secretID, "policy", err.Error())
		return
	}
	s.redirectAdminSecretOK(w, r, secretID, "policy", "resource policy updated")
}

func (s *server) handleAdminRotateSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.redirectAdminSecretsError(w, r, "rotate secret requires POST")
		return
	}
	secretID := strings.TrimSpace(r.FormValue("secret_id"))
	days := 30
	if parsed := strings.TrimSpace(r.FormValue("rotation_days")); parsed != "" {
		if n, err := strconv.Atoi(parsed); err == nil {
			days = n
		}
	}
	result, err := s.store.RotateSecret(r.Context(), secretID, strings.TrimSpace(r.FormValue("rotation_lambda_arn")), days, r.FormValue("rotate_immediately") != "false", strings.TrimSpace(r.FormValue("client_request_token")))
	if err != nil {
		s.redirectAdminSecretError(w, r, secretID, "rotation", err.Error())
		return
	}
	msg := "rotation configuration updated"
	if result.VersionID != "" {
		msg = "rotation pending version created"
	}
	s.redirectAdminSecretOK(w, r, result.Metadata.Name, "rotation", msg)
}

func (s *server) handleAdminCancelRotateSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.redirectAdminSecretsError(w, r, "cancel rotate secret requires POST")
		return
	}
	secretID := strings.TrimSpace(r.FormValue("secret_id"))
	meta, err := s.store.CancelRotateSecret(r.Context(), secretID)
	if err != nil {
		s.redirectAdminSecretError(w, r, secretID, "rotation", err.Error())
		return
	}
	s.redirectAdminSecretOK(w, r, meta.Name, "rotation", "rotation canceled")
}

func (s *server) handleAdminPromoteSecretVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.redirectAdminSecretsError(w, r, "promote secret version requires POST")
		return
	}
	secretID := strings.TrimSpace(r.FormValue("secret_id"))
	versionID := strings.TrimSpace(r.FormValue("version_id"))
	meta, err := s.store.UpdateSecretVersionStage(r.Context(), secretID, currentVersionStage, versionID, "")
	if err != nil {
		s.redirectAdminSecretError(w, r, secretID, "versions", err.Error())
		return
	}
	s.redirectAdminSecretOK(w, r, meta.Name, "versions", "secret version promoted")
}

func (s *server) handleAdminBulkSecrets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.redirectAdminSecretsError(w, r, "bulk secret updates require POST")
		return
	}
	if _, ok := s.requireUISession(w, r, "admin"); !ok {
		return
	}
	secretIDs := r.Form["secret_id"]
	if len(secretIDs) == 0 {
		s.redirectAdminSecretsError(w, r, "select at least one secret")
		return
	}
	action := strings.TrimSpace(r.FormValue("bulk_action"))
	updated := 0
	for _, secretID := range secretIDs {
		secretID = strings.TrimSpace(secretID)
		if secretID == "" {
			continue
		}
		switch action {
		case "delete":
			if _, err := s.store.DeleteSecret(r.Context(), secretID, 30, false); err == nil {
				updated++
			}
		case "force_delete":
			if _, err := s.store.DeleteSecret(r.Context(), secretID, 0, true); err == nil {
				updated++
			}
		case "restore":
			if _, err := s.store.RestoreSecret(r.Context(), secretID); err == nil {
				updated++
			}
		}
	}
	if updated == 0 {
		s.redirectAdminSecretsError(w, r, "no secrets were updated")
		return
	}
	s.redirectAdminSecretOK(w, r, "", "", fmt.Sprintf("updated %d secrets", updated))
}

func (s *server) redirectAdminSecretsError(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/secrets?err="+url.QueryEscape(msg), http.StatusSeeOther)
}

func (s *server) redirectAdminSecretOK(w http.ResponseWriter, r *http.Request, secretID, tab, msg string) {
	v := url.Values{}
	v.Set("ok", msg)
	if secretID != "" {
		v.Set("secret_id", secretID)
	}
	if tab != "" {
		v.Set("tab", tab)
	}
	http.Redirect(w, r, "/secrets?"+v.Encode(), http.StatusSeeOther)
}

func (s *server) redirectAdminSecretError(w http.ResponseWriter, r *http.Request, secretID, tab, msg string) {
	v := url.Values{}
	v.Set("err", msg)
	if secretID != "" {
		v.Set("secret_id", secretID)
	}
	if tab != "" {
		v.Set("tab", tab)
	}
	http.Redirect(w, r, "/secrets?"+v.Encode(), http.StatusSeeOther)
}

func adminSecretState(meta secretMetadataRecord) string {
	if meta.DeletedDate != nil {
		return "PendingDeletion"
	}
	return "Active"
}
