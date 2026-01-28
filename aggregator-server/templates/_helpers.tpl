{{- define "aggregator.labels" -}}
app.kubernetes.io/name: aggregator-server
app.kubernetes.io/part-of: aggregator-platform
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: "{{ .Chart.AppVersion }}"
app.kubernetes.io/managed-by: Helm
{{- end }}

{{- define "aggregator.annotations" -}}
meta.helm.sh/release-name: "{{ .Release.Name }}"
meta.helm.sh/release-namespace: "{{ .Release.Namespace }}"
{{- end }}
