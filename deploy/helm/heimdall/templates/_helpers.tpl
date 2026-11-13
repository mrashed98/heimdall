{{- define "heimdall.name" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "heimdall.labels" -}}
app.kubernetes.io/name: heimdall
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "heimdall.selector" -}}
app.kubernetes.io/name: heimdall
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
