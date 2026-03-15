{{/*
Expand the name of the chart.
*/}}
{{- define "traffic-harvester.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "traffic-harvester.fullname" -}}
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

{{/*
Common labels
*/}}
{{- define "traffic-harvester.labels" -}}
helm.sh/chart: {{ include "traffic-harvester.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Chart label
*/}}
{{- define "traffic-harvester.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Hub labels
*/}}
{{- define "traffic-harvester.hub.labels" -}}
{{ include "traffic-harvester.labels" . }}
app.kubernetes.io/name: {{ include "traffic-harvester.name" . }}-hub
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: hub
{{- end }}

{{/*
Hub selector labels
*/}}
{{- define "traffic-harvester.hub.selectorLabels" -}}
app.kubernetes.io/name: {{ include "traffic-harvester.name" . }}-hub
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Spoke labels
*/}}
{{- define "traffic-harvester.spoke.labels" -}}
{{ include "traffic-harvester.labels" . }}
app.kubernetes.io/name: {{ include "traffic-harvester.name" . }}-spoke
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: spoke
{{- end }}

{{/*
Spoke selector labels
*/}}
{{- define "traffic-harvester.spoke.selectorLabels" -}}
app.kubernetes.io/name: {{ include "traffic-harvester.name" . }}-spoke
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Hub ServiceAccount name
*/}}
{{- define "traffic-harvester.hub.serviceAccountName" -}}
{{- if .Values.hub.serviceAccount.create }}
{{- default (printf "%s-hub" (include "traffic-harvester.fullname" .)) }}
{{- else }}
{{- default "default" }}
{{- end }}
{{- end }}

{{/*
Spoke ServiceAccount name
*/}}
{{- define "traffic-harvester.spoke.serviceAccountName" -}}
{{- if .Values.spoke.serviceAccount.create }}
{{- default (printf "%s-spoke" (include "traffic-harvester.fullname" .)) }}
{{- else }}
{{- default "default" }}
{{- end }}
{{- end }}

{{/*
Namespace helper
*/}}
{{- define "traffic-harvester.namespace" -}}
{{- default .Release.Namespace .Values.namespace }}
{{- end }}

