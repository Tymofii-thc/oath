#!/usr/bin/env bash
# Installs the oath admission webhook into the current kubectl context.
# Usage: OATH_SIGNER=<pubkey[,pubkey]> [OATH_NETWORK=devnet|mainnet] [SOLANA_RPC=url[,url]] [OATH_IMAGE=…] [OATH_IMAGE_SIGNER=<pubkey> OATH_IMAGE_ATTEST=owner/repo/workflow.yml@refs/heads/main] [OATH_VERIFY_IMAGE=skip] [OATH_APPROVALS=yes] [OATH_FAILURE_POLICY=Fail|Ignore] [OATH_QUORUM=2] [OATH_ATTEST_REPO=owner/repo] [OATH_MODE=enforce|audit] [OATH_AUDIT_SCHEDULE="*/30 * * * *"] [OATH_STALE_OK_HOURS=1] [OATH_LIMIT=1000] [OATH_ALLOWED_REGISTRIES=ghcr.io,host2] [OATH_REGISTRY_AUTH='{"ghcr.io":{"username":"u","password":"token"}}'] deploy/install.sh
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
OATH_APPROVALS="${OATH_APPROVALS:-}"   # yes = decide from signed approvals (ConfigMap oath-approvals) instead of the chain; OATH_SIGNER then lists the approver keys
OATH_APPROVALS_DIR=""
[ "$OATH_APPROVALS" = yes ] && OATH_APPROVALS_DIR=/approvals
case "$OATH_FAILURE_POLICY" in Fail|Ignore) ;; *) echo "OATH_FAILURE_POLICY must be Fail or Ignore" >&2; exit 2;; esac
OFFICIAL_IMAGE=ghcr.io/tymofii-thc/oath-webhook
OATH_IMAGE="${OATH_IMAGE:-$OFFICIAL_IMAGE:latest}"
here="$(cd "$(dirname "$0")" && pwd)"
# The webhook is the gate for the whole cluster and its namespace is exempt from itself, so what runs there must be what the project's
# pipeline built. The official image is therefore CHECKED before anything is installed (recorded on Solana by the project's CI key and
# carrying a Sigstore build attestation from the release workflow on main) and installed by DIGEST, so the cluster runs exactly what was
# checked and a moved tag changes nothing. Your own image: set OATH_IMAGE_SIGNER (and OATH_IMAGE_ATTEST) to check it against your pipeline;
# without them a custom image is installed as given and the script says so. OATH_VERIFY_IMAGE=skip turns the check off (loudly).
# The trust anchor is this script: take it from a tag or a commit you reviewed.
case "$OATH_IMAGE" in "$OFFICIAL_IMAGE"|"$OFFICIAL_IMAGE":*|"$OFFICIAL_IMAGE"@*) official=1;; *) official=0;; esac
if [ "$official" = 1 ] && [ -z "${OATH_IMAGE_SIGNER:-}" ]; then
  OATH_IMAGE_SIGNER=5D4W8x8UeqW3qVi9uzNzvJPWiJZQaRWVR9ru2ckFhoih
  OATH_IMAGE_ATTEST="${OATH_IMAGE_ATTEST:-Tymofii-thc/oath/.github/workflows/release-webhook.yml@refs/heads/main}"
fi
if [ "${OATH_VERIFY_IMAGE:-}" = skip ]; then
  echo "WARNING: OATH_VERIFY_IMAGE=skip: the webhook image $OATH_IMAGE is installed WITHOUT checking that your pipeline built it." >&2
elif [ -n "${OATH_IMAGE_SIGNER:-}" ]; then
  root="$(cd "$here/.." && pwd)"
  run_oath() {
    if [ -n "${OATH_CLI:-}" ]; then $OATH_CLI "$@"
    elif [ -d "$root/node_modules/sigstore" ] && command -v node >/dev/null 2>&1; then node "$root/bin/oath.mjs" "$@"
    elif command -v npx >/dev/null 2>&1; then npx --yes "oath-verify@$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "$root/package.json" | head -1)" "$@"
    else echo "cannot check the webhook image: neither a checkout with node_modules nor npx is available (install Node, or set OATH_VERIFY_IMAGE=skip and accept the risk)" >&2; return 2
    fi
  }
  echo "Checking the webhook image $OATH_IMAGE against its signer ${OATH_IMAGE_SIGNER}..."
  vargs=(verify --signer "$OATH_IMAGE_SIGNER" --image "$OATH_IMAGE" --network "${OATH_IMAGE_NETWORK:-devnet}" --rpc "${OATH_IMAGE_RPC:-https://api.devnet.solana.com}")
  [ -n "${OATH_IMAGE_ATTEST:-}" ] && vargs+=(--attest "$OATH_IMAGE_ATTEST")
  if ! vout="$(OATH_QUIET=1 run_oath "${vargs[@]}")"; then
    echo "$vout" >&2
    echo "The webhook image $OATH_IMAGE is NOT verified: refusing to install it. (OATH_VERIFY_IMAGE=skip overrides, at your own risk.)" >&2
    exit 1
  fi
  echo "$vout" | sed 's/^/  /'
  vdigest="$(sed -n 's/^VERIFIED  \(sha256:[0-9a-f]\{64\}\).*/\1/p' <<<"$vout" | head -1)"
  [ -n "$vdigest" ] || { echo "the check did not report a digest: refusing to install" >&2; exit 1; }
  img_repo="${OATH_IMAGE%%@*}"; case "${img_repo##*/}" in *:*) img_repo="${img_repo%:*}";; esac
  OATH_IMAGE="$img_repo@$vdigest"
  echo "Installing exactly $OATH_IMAGE"
else
  echo "note: $OATH_IMAGE is a custom image: it is installed as given (set OATH_IMAGE_SIGNER to have it checked against your pipeline)." >&2
fi
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
svc=oath-webhook; ns=oath-system

openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=oath-ca" -keyout "$tmp/ca.key" -out "$tmp/ca.crt" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=$svc.$ns.svc" -keyout "$tmp/tls.key" -out "$tmp/tls.csr" 2>/dev/null
printf "subjectAltName=DNS:%s,DNS:%s.%s,DNS:%s.%s.svc\n" "$svc" "$svc" "$ns" "$svc" "$ns" > "$tmp/san.ext"
openssl x509 -req -in "$tmp/tls.csr" -CA "$tmp/ca.crt" -CAkey "$tmp/ca.key" -CAcreateserial -days 825 -extfile "$tmp/san.ext" -out "$tmp/tls.crt" 2>/dev/null

kubectl get ns "$ns" >/dev/null 2>&1 || kubectl create ns "$ns"
kubectl label ns "$ns" oath.io/exempt=true --overwrite >/dev/null
if [ "$OATH_APPROVALS" = yes ] && ! kubectl -n "$ns" get configmap oath-approvals >/dev/null 2>&1; then kubectl -n "$ns" create configmap oath-approvals >/dev/null; fi
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
sed -e "s|__OATH_IMAGE__|$(esc "$OATH_IMAGE")|" -e "s|__OATH_SIGNER__|$(esc "$OATH_SIGNER")|" -e "s|__OATH_NETWORK__|$(esc "$OATH_NETWORK")|" -e "s|__FAILURE_POLICY__|$(esc "$OATH_FAILURE_POLICY")|" -e "s|__OATH_MODE__|$(esc "$OATH_MODE")|" -e "s|__OATH_QUORUM__|$(esc "$OATH_QUORUM")|" -e "s|__OATH_STALE_OK_HOURS__|$(esc "$OATH_STALE_OK_HOURS")|" -e "s|__OATH_LIMIT__|$(esc "$OATH_LIMIT")|" -e "s|__ALLOWED_REGISTRIES__|$(esc "$OATH_ALLOWED_REGISTRIES")|" -e "s|__APPROVALS_DIR__|$(esc "$OATH_APPROVALS_DIR")|" -e "s|__OATH_ATTEST_REPO__|$(esc "$OATH_ATTEST_REPO")|" -e "s|__CA_BUNDLE__|$(esc "$ca")|" -e "s|__RPC_SUM__|$rpc_sum|" -e "s|__TLS_SUM__|$tls_sum|" -e "s|__AUTH_SUM__|$auth_sum|" "$here/k8s/oath.yaml" | kubectl apply -f -
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
