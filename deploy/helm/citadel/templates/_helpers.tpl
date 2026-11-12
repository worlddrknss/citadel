{{/* vim: set filetype=mustache: */}}

{{- define "citadel.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "citadel.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "citadel.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "citadel.selectorLabels" -}}
app.kubernetes.io/name: {{ include "citadel.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "citadel.labels" -}}
helm.sh/chart: {{ include "citadel.chart" . }}
{{ include "citadel.selectorLabels" . }}
app.kubernetes.io/version: {{ include "citadel.imageTag" . | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: citadel
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{- define "citadel.imageTag" -}}
{{- default .Chart.AppVersion .Values.image.tag | toString | trunc 63 }}
{{- end }}

{{- define "citadel.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag | toString) }}
{{- end }}
{{- end }}

{{- define "citadel.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "citadel.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "citadel.secretName" -}}
{{- printf "%s-secrets" (include "citadel.fullname" .) }}
{{- end }}

{{- define "citadel.replicas" -}}
{{- if .Values.autoscaling.enabled }}{{ .Values.autoscaling.minReplicas }}{{ else }}{{ .Values.replicaCount }}{{ end }}
{{- end }}

{{- define "citadel.scheme" -}}
{{- if .Values.tls.enabled }}HTTPS{{ else }}HTTP{{ end }}
{{- end }}

{{/*
Sensitive settings: values key -> environment variable, and whether the
server cannot start without it (in database mode).
*/}}
{{- define "citadel.secretSpecs" -}}
- {name: databaseUrl, env: KMS_DB_URL, required: db}
- {name: wrappingKey, env: KMS_WRAPPING_KEY_B64, required: db}
- {name: previousWrappingKeys, env: KMS_PREVIOUS_WRAPPING_KEYS_B64}
- {name: auditHmacKey, env: KMS_AUDIT_HMAC_KEY_B64}
- {name: accessKeyId, env: KMS_ACCESS_KEY_ID}
- {name: secretAccessKey, env: KMS_SECRET_ACCESS_KEY}
- {name: bootstrapToken, env: KMS_BOOTSTRAP_TOKEN}
- {name: uiUsersJson, env: KMS_UI_USERS_JSON}
- {name: masterKey, env: KMS_MASTER_KEY_B64, required: memory}
{{- end }}

{{/* True when at least one inline secret value is set. */}}
{{- define "citadel.hasInlineSecrets" -}}
{{- range (include "citadel.secretSpecs" . | fromYamlArray) }}
{{- $entry := index $.Values.secrets .name | default dict }}
{{- if $entry.value }}true{{ end }}
{{- end }}
{{- end }}

{{/*
Fails the render on unsafe or incomplete configuration.
*/}}
{{- define "citadel.validate" -}}
{{- $v := .Values }}
{{- $mode := ternary "memory" "db" $v.devMode.inMemory }}
{{- range (include "citadel.secretSpecs" . | fromYamlArray) }}
{{- $entry := index $v.secrets .name | default dict }}
{{- if and $entry.value (not $v.secrets.create) }}
{{- fail (printf "secrets.%s.value is set but secrets.create=false. Inline secret values are stored in Helm release history and usually in Git. Reference an existing Secret (secrets.existingSecret or secrets.%s.existingSecret), managed by External Secrets Operator, Sealed Secrets or similar, or set secrets.create=true to accept the risk." .name .name) }}
{{- end }}
{{- $provided := or $entry.existingSecret $v.secrets.existingSecret (and $v.secrets.create $entry.value) }}
{{- if and (eq (toString .required) $mode) (not $provided) }}
{{- fail (printf "%s is required: set secrets.existingSecret (holding key %s), secrets.%s.existingSecret, or secrets.%s.value with secrets.create=true." .env (default .env $entry.existingSecretKey) .name .name) }}
{{- end }}
{{- end }}
{{- if $v.devMode.inMemory }}
{{- if or $v.autoscaling.enabled (gt (int $v.replicaCount) 1) }}
{{- fail "devMode.inMemory keeps all data inside one process: set replicaCount=1 and autoscaling.enabled=false, or configure PostgreSQL (secrets.databaseUrl) for more than one replica." }}
{{- end }}
{{- end }}
{{- if and $v.tls.enabled (not $v.tls.existingSecret) }}
{{- fail "tls.enabled requires tls.existingSecret (a kubernetes.io/tls Secret)." }}
{{- end }}
{{- if lt (int $v.terminationGracePeriodSeconds) (add 15 (int $v.preStopSleepSeconds) | int) }}
{{- fail (printf "terminationGracePeriodSeconds must be at least preStopSleepSeconds + 15 (%d): the server drains for up to 15s after SIGTERM." (add 15 (int $v.preStopSleepSeconds))) }}
{{- end }}
{{- if and $v.metrics.serviceMonitor.enabled (not $v.metrics.enabled) }}
{{- fail "metrics.serviceMonitor.enabled requires metrics.enabled." }}
{{- end }}
{{- if and $v.httpRoute.enabled (not $v.httpRoute.parentRefs) }}
{{- fail "httpRoute.enabled requires at least one httpRoute.parentRefs entry." }}
{{- end }}
{{- $db := $v.networkPolicy.egress.database }}
{{- if and $v.networkPolicy.enabled (not $v.devMode.inMemory) (not (or $db.cidrs $db.namespaceSelector $db.podSelector)) }}
{{- fail "networkPolicy.enabled would block PostgreSQL: set networkPolicy.egress.database.cidrs, or its namespaceSelector / podSelector." }}
{{- end }}
{{- range $v.config.trustedProxies }}
{{- if or (eq . "0.0.0.0/0") (eq . "::/0") }}
{{- fail "config.trustedProxies must not contain 0.0.0.0/0 or ::/0: any client could then forge its source address. List your proxies' ranges." }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Environment variables for sensitive settings, as secretKeyRefs.
*/}}
{{- define "citadel.secretEnv" -}}
{{- $v := .Values }}
{{- $mode := ternary "memory" "db" $v.devMode.inMemory }}
{{- range (include "citadel.secretSpecs" . | fromYamlArray) }}
{{- $entry := index $v.secrets .name | default dict }}
{{- $key := default .env $entry.existingSecretKey }}
{{- $required := eq (toString .required) $mode }}
{{- if $entry.existingSecret }}
- name: {{ .env }}
  valueFrom:
    secretKeyRef:
      name: {{ $entry.existingSecret | quote }}
      key: {{ $key | quote }}
{{- else if and $v.secrets.create $entry.value }}
- name: {{ .env }}
  valueFrom:
    secretKeyRef:
      name: {{ include "citadel.secretName" $ | quote }}
      key: {{ .env | quote }}
{{- else if $v.secrets.existingSecret }}
- name: {{ .env }}
  valueFrom:
    secretKeyRef:
      name: {{ $v.secrets.existingSecret | quote }}
      key: {{ $key | quote }}
      {{- if not $required }}
      optional: true
      {{- end }}
{{- end }}
{{- end }}
{{- end }}
