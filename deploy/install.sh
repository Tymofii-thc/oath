#!/usr/bin/env bash
# Installs the oath admission webhook into the current kubectl context.
# Usage: OATH_SIGNER=<pubkey[,pubkey]> [OATH_NETWORK=devnet|mainnet] [SOLANA_RPC=url[,url]] [OATH_IMAGE=…] [OATH_FAILURE_POLICY=Fail|Ignore] [OATH_QUORUM=2] [OATH_ATTEST_REPO=owner/repo] [OATH_MODE=enforce|audit] [OATH_AUDIT_SCHEDULE="*/30 * * * *"] [OATH_STALE_OK_HOURS=1] [OATH_LIMIT=1000] [OATH_REGISTRY_AUTH='{"ghcr.io":{"username":"u","password":"token"}}'] deploy/install.sh
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
OATH_MODE="${OATH_MODE:-enforce}"
case "$OATH_MODE" in enforce|audit) ;; *) echo "OATH_MODE must be enforce or audit" >&2; exit 2;; esac
OATH_ATTEST_REPO="${OATH_ATTEST_REPO:-}"
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

ca="$(base64 -w0 < "$tmp/ca.crt")"
sed -e "s|__OATH_IMAGE__|$OATH_IMAGE|" -e "s|__OATH_SIGNER__|$OATH_SIGNER|" -e "s|__OATH_NETWORK__|$OATH_NETWORK|" -e "s|__SOLANA_RPC__|$SOLANA_RPC|" -e "s|__FAILURE_POLICY__|$OATH_FAILURE_POLICY|" -e "s|__OATH_MODE__|$OATH_MODE|" -e "s|__OATH_QUORUM__|$OATH_QUORUM|" -e "s|__OATH_STALE_OK_HOURS__|$OATH_STALE_OK_HOURS|" -e "s|__OATH_LIMIT__|$OATH_LIMIT|" -e "s|__OATH_ATTEST_REPO__|$OATH_ATTEST_REPO|" -e "s|__CA_BUNDLE__|$ca|" "$here/k8s/oath.yaml" | kubectl apply -f -
kubectl -n "$ns" rollout status deploy/oath-webhook --timeout=120s
# Optional: periodic audit of Pods that were already running before the webhook (cron expression, e.g. "*/30 * * * *")
if [ -n "${OATH_AUDIT_SCHEDULE:-}" ]; then
  sed -e "s|__OATH_IMAGE__|$OATH_IMAGE|" -e "s|__OATH_SIGNER__|$OATH_SIGNER|" -e "s|__OATH_NETWORK__|$OATH_NETWORK|" -e "s|__SOLANA_RPC__|$SOLANA_RPC|" -e "s|__OATH_QUORUM__|$OATH_QUORUM|" -e "s|__OATH_AUDIT_SCHEDULE__|$OATH_AUDIT_SCHEDULE|" "$here/k8s/audit-cronjob.yaml" | kubectl apply -f -
  echo "Audit CronJob installed (schedule: $OATH_AUDIT_SCHEDULE). Failed jobs = unverified or revoked Pods: kubectl -n $ns get jobs"
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
