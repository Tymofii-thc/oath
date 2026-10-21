#!/usr/bin/env bash
# Installs the oath admission webhook into the current kubectl context.
# Usage: OATH_SIGNER=<pubkey[,pubkey]> [OATH_NETWORK=devnet|mainnet] [SOLANA_RPC=url[,url]] [OATH_IMAGE=…] [OATH_FAILURE_POLICY=Fail|Ignore] [OATH_QUORUM=2] [OATH_ATTEST_REPO=owner/repo] [OATH_PROGRAM=<id>] [OATH_MODE=enforce|audit] [OATH_AUDIT_SCHEDULE="*/30 * * * *"] [OATH_STALE_OK_HOURS=1] [OATH_LIMIT=1000] [OATH_ALLOWED_REGISTRIES=ghcr.io,host2] [OATH_REGISTRY_AUTH='{"ghcr.io":{"username":"u","password":"token"}}'] deploy/install.sh
# OATH_PROGRAM: experimental account-based backend instead of Memo scanning (README, "On-chain records"); empty = Memo (default).
# SOLANA_RPC overrides OATH_NETWORK's default endpoint (comma-separate several for failover); useful against the public RPCs' rate limits.
# Fail (default): if the webhook is unreachable, new pods are rejected. Ignore: they are admitted unchecked (use with `oath audit`).
set -euo pipefail
: "${OATH_SIGNER:?set OATH_SIGNER to the CI signer public key (comma-separate several)}"
OATH_NETWORK="${OATH_NETWORK:-devnet}"
SOLANA_RPC="${SOLANA_RPC:-}"
OATH_FAILURE_POLICY="${OATH_FAILURE_POLICY:-Fail}"
OATH_QUORUM="${OATH_QUORUM:-1}"
OATH_STALE_OK_HOURS="${OATH_STALE_OK_HOURS:-1}"
OATH_LIMIT="${OATH_LIMIT:-1000}"
OATH_ALLOWED_REGISTRIES="${OATH_ALLOWED_REGISTRIES:-}"   # e.g. ghcr.io,myregistry.azurecr.io : the only hosts the webhook will contact
OATH_MODE="${OATH_MODE:-enforce}"
case "$OATH_MODE" in enforce|audit) ;; *) echo "OATH_MODE must be enforce or audit" >&2; exit 2;; esac
OATH_ATTEST_REPO="${OATH_ATTEST_REPO:-}"
OATH_PROGRAM="${OATH_PROGRAM:-}"
case "$OATH_FAILURE_POLICY" in Fail|Ignore) ;; *) echo "OATH_FAILURE_POLICY must be Fail or Ignore" >&2; exit 2;; esac
OATH_IMAGE="${OATH_IMAGE:-ghcr.io/tymofii-thc/oath-webhook:latest}"
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
svc=oath-webhook; ns=oath-system

openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=oath-ca" -keyout "$tmp/ca.key" -out "$tmp/ca.crt" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=$svc.$ns.svc" -keyout "$tmp/tls.key" -out "$tmp/tls.csr" 2>/dev/null
printf "subjectAltName=DNS:%s,DNS:%s.%s,DNS:%s.%s.svc\n" "$svc" "$svc" "$ns" "$svc" "$ns" > "$tmp/san.ext"
openssl x509 -req -in "$tmp/tls.csr" -CA "$tmp/ca.crt" -CAkey "$tmp/ca.key" -CAcreateserial -days 825 -extfile "$tmp/san.ext" -out "$tmp/tls.crt" 2>/dev/null

kubectl get ns "$ns" >/dev/null 2>&1 || kubectl create ns "$ns"
kubectl label ns "$ns" oath.io/exempt=true --overwrite >/dev/null
kubectl -n "$ns" create secret tls oath-webhook-tls --cert="$tmp/tls.crt" --key="$tmp/tls.key" --dry-run=client -o yaml | kubectl apply -f -

if [ -n "${OATH_REGISTRY_AUTH:-}" ]; then
  kubectl -n "$ns" create secret generic oath-registry-auth --from-literal=auth="$OATH_REGISTRY_AUTH" --dry-run=client -o yaml | kubectl apply -f -
fi

# RPC endpoints often carry an API key, so they live in a Secret, not in the Deployment spec
if [ -n "$SOLANA_RPC" ]; then
  kubectl -n "$ns" create secret generic oath-rpc --from-literal=rpc="$SOLANA_RPC" --dry-run=client -o yaml | kubectl apply -f -
else
  kubectl -n "$ns" delete secret oath-rpc --ignore-not-found >/dev/null
fi
tls_sum="$(sha256sum < "$tmp/tls.crt" | cut -c1-16)"
auth_sum="$(printf '%s' "${OATH_REGISTRY_AUTH:-}" | sha256sum | cut -c1-16)"
rpc_sum="$(printf '%s' "$SOLANA_RPC" | sha256sum | cut -c1-16)"

ca="$(base64 -w0 < "$tmp/ca.crt")"
# values go into sed replacements: escape the characters that mean something there (a URL with ?a=1&b=2 would otherwise be mangled)
esc() { printf '%s' "$1" | sed -e 's/[&|\\]/\\&/g'; }
sed -e "s|__OATH_IMAGE__|$(esc "$OATH_IMAGE")|" -e "s|__OATH_SIGNER__|$(esc "$OATH_SIGNER")|" -e "s|__OATH_NETWORK__|$(esc "$OATH_NETWORK")|" -e "s|__FAILURE_POLICY__|$(esc "$OATH_FAILURE_POLICY")|" -e "s|__OATH_MODE__|$(esc "$OATH_MODE")|" -e "s|__OATH_QUORUM__|$(esc "$OATH_QUORUM")|" -e "s|__OATH_STALE_OK_HOURS__|$(esc "$OATH_STALE_OK_HOURS")|" -e "s|__OATH_LIMIT__|$(esc "$OATH_LIMIT")|" -e "s|__ALLOWED_REGISTRIES__|$(esc "$OATH_ALLOWED_REGISTRIES")|" -e "s|__OATH_ATTEST_REPO__|$(esc "$OATH_ATTEST_REPO")|" -e "s|__OATH_PROGRAM__|$(esc "$OATH_PROGRAM")|" -e "s|__CA_BUNDLE__|$(esc "$ca")|" -e "s|__RPC_SUM__|$rpc_sum|" -e "s|__TLS_SUM__|$tls_sum|" -e "s|__AUTH_SUM__|$auth_sum|" "$here/k8s/oath.yaml" | kubectl apply -f -
kubectl -n "$ns" rollout status deploy/oath-webhook --timeout=120s
# Pods that were already running are not seen by the webhook, so audit them: hourly by default, and once right now.
# OATH_AUDIT_SCHEDULE is a cron expression; "off" skips the CronJob and the first run.
OATH_AUDIT_SCHEDULE="${OATH_AUDIT_SCHEDULE-0 * * * *}"
if [ -n "$OATH_AUDIT_SCHEDULE" ] && [ "$OATH_AUDIT_SCHEDULE" != off ]; then
  sed -e "s|__OATH_IMAGE__|$(esc "$OATH_IMAGE")|" -e "s|__OATH_SIGNER__|$(esc "$OATH_SIGNER")|" -e "s|__OATH_NETWORK__|$(esc "$OATH_NETWORK")|" -e "s|__OATH_QUORUM__|$(esc "$OATH_QUORUM")|" -e "s|__OATH_AUDIT_SCHEDULE__|$(esc "$OATH_AUDIT_SCHEDULE")|" "$here/k8s/audit-cronjob.yaml" | kubectl apply -f -
  echo "Audit CronJob installed (schedule: $OATH_AUDIT_SCHEDULE). Failed jobs = unverified or revoked Pods: kubectl -n $ns get jobs"
  first="oath-audit-first-$(date +%s)"
  if kubectl -n "$ns" create job "$first" --from=cronjob/oath-audit >/dev/null; then
    echo "Auditing the Pods that are already running..."
    # a Job that finds a bad image ends Failed, so "wait for complete" would sit out its whole timeout: poll for either end state
    for _ in $(seq 1 60); do
      st="$(kubectl -n "$ns" get "job/$first" -o jsonpath='{.status.succeeded}{.status.failed}' 2>/dev/null || true)"
      [ -n "$st" ] && break
      sleep 2
    done
    kubectl -n "$ns" logs "job/$first" 2>/dev/null || true
    kubectl -n "$ns" delete job "$first" --ignore-not-found >/dev/null 2>&1 || true
  fi
fi

# "rollout finished" does not mean the Service accepts connections yet: probe until the API server can actually call the webhook
# (a denial from oath is fine here, "failed calling webhook" is not).
ready=0
for _ in $(seq 1 60); do
  out="$(kubectl run oath-probe --image=oath.invalid/probe --restart=Never --dry-run=server 2>&1 || true)"
  if ! grep -q "failed calling webhook" <<<"$out"; then ready=1; break; fi
  sleep 2
done
[ "$ready" = 1 ] || { echo "webhook is installed but not answering admission requests: check 'kubectl -n $ns logs deploy/oath-webhook'" >&2; exit 1; }
if [ "$OATH_MODE" = audit ]; then echo "oath is running in AUDIT mode: unrecorded images are admitted with a warning. Test: kubectl run t --image=nginx"; else echo "oath is enforcing. Test: kubectl run t --image=nginx  (expected: denied)"; fi
