{{- define "oath.tls" -}}
{{- $cn := printf "oath-webhook.%s.svc" .Release.Namespace -}}
{{- $existing := lookup "v1" "Secret" .Release.Namespace "oath-webhook-tls" -}}
{{- if $existing -}}
ca: {{ index $existing.data "ca.crt" }}
crt: {{ index $existing.data "tls.crt" }}
key: {{ index $existing.data "tls.key" }}
{{- else -}}
{{- $ca := genCA "oath-ca" 825 -}}
{{- $cert := genSignedCert $cn nil (list "oath-webhook" (printf "oath-webhook.%s" .Release.Namespace) (printf "oath-webhook.%s.svc" .Release.Namespace)) 825 $ca -}}
ca: {{ $ca.Cert | b64enc }}
crt: {{ $cert.Cert | b64enc }}
key: {{ $cert.Key | b64enc }}
{{- end -}}
{{- end -}}
