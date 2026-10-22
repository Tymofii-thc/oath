#!/usr/bin/env bash
# End-to-end test of the admission webhook in a throwaway kind cluster. Needs docker, kind, kubectl, openssl and internet (Solana devnet + Docker Hub).
# Usage: OATH_SIGNER=<pubkey> OK_IMAGE=<image anchored by that signer> BAD_IMAGE=<image NOT anchored> test/e2e-kind.sh
set -uo pipefail
: "${OATH_SIGNER:?}" "${OK_IMAGE:?}" "${BAD_IMAGE:?}"
root="$(cd "$(dirname "$0")/.." && pwd)"; cluster=oath-e2e; fails=0
check(){ if [ "$2" = "$3" ]; then echo "PASS  $1"; else echo "FAIL  $1 (expected $2, got $3)"; fails=$((fails+1)); fi; }
trap 'kind delete cluster --name $cluster >/dev/null 2>&1' EXIT

docker build -q -t oath:e2e "$root" >/dev/null
kind create cluster --name $cluster --wait 120s >/dev/null 2>&1
kind load docker-image oath:e2e --name $cluster >/dev/null 2>&1
OATH_SIGNER=$OATH_SIGNER OATH_IMAGE=oath:e2e "$root/deploy/install.sh" >/dev/null 2>&1

kubectl get validatingwebhookconfiguration oath >/dev/null 2>&1; check "the verdict is a ValidatingWebhookConfiguration" 0 $?
kubectl get mutatingwebhookconfiguration oath >/dev/null 2>&1; check "pinning is a separate MutatingWebhookConfiguration" 0 $?
[ "$(kubectl get mutatingwebhookconfiguration oath -o jsonpath='{.webhooks[0].reinvocationPolicy}' 2>/dev/null)" = "IfNeeded" ]; check "the pin webhook is reinvoked after other mutators" 0 $?
[ "$(kubectl get mutatingwebhookconfiguration oath -o jsonpath='{.webhooks[0].failurePolicy}' 2>/dev/null)" = "Ignore" ]; check "an unavailable pin webhook does not block Pods (the verdict still does)" 0 $?

kubectl run ok --image="$OK_IMAGE" --restart=Never -- sleep 30 >/dev/null 2>&1; check "anchored image admitted" 0 $?
img=$(kubectl get pod ok -o jsonpath='{.spec.containers[0].image}' 2>/dev/null)
case "$OK_IMAGE" in
  *@sha256:*) echo "SKIP  tag pinned to digest (OK_IMAGE is already a digest; covered by unit tests)";;
  *) case "$img" in *@sha256:*) check "tag pinned to digest" ok ok;; *) check "tag pinned to digest" ok "$img";; esac;;
esac
kubectl run bad --image="$BAD_IMAGE" --restart=Never >/dev/null 2>&1; check "un-anchored image denied" 1 $?
kubectl create deploy evil --image="$BAD_IMAGE" >/dev/null 2>&1; sleep 8
msg=$(kubectl get rs -l app=evil -o jsonpath='{.items[0].status.conditions[*].message}' 2>/dev/null)
case "$msg" in *"refusing to admit"*) check "deployment pods blocked" ok ok;; *) check "deployment pods blocked" ok "none";; esac

# the API server really calls the pin webhook (the pin counter of the webhook pods, summed over replicas)
pins=0
for pod in $(kubectl -n oath-system get pods -l app=oath-webhook -o name 2>/dev/null); do
  n=$(kubectl -n oath-system exec "$pod" -- node -e "process.env.NODE_TLS_REJECT_UNAUTHORIZED='0';fetch('https://127.0.0.1:8443/metrics').then(r=>r.text()).then(t=>console.log((t.match(/oath_pin_requests_total (\\d+)/)||[])[1]||0))" 2>/dev/null || echo 0)
  pins=$((pins + ${n:-0}))
done
[ "$pins" -ge 1 ]; check "the API server calls the pin webhook (/pin)" 0 $?

# a bare Pod's image can be edited in place; ephemeral containers (kubectl debug) can be added: both must be checked too
kubectl patch pod ok -p "{\"spec\":{\"containers\":[{\"name\":\"ok\",\"image\":\"$BAD_IMAGE\"}]}}" >/dev/null 2>&1; check "in-place image swap on a running pod denied" 1 $?
kubectl debug ok --image="$BAD_IMAGE" --target=ok -- sleep 1 >/dev/null 2>&1; check "ephemeral container with un-anchored image denied" 1 $?
kubectl label pod ok touched=yes >/dev/null 2>&1; check "metadata-only update of a running pod still works" 0 $?

kubectl -n oath-system scale deploy/oath-webhook --replicas=0 >/dev/null 2>&1
kubectl -n oath-system wait --for=delete pod -l app=oath-webhook --timeout=60s >/dev/null 2>&1
kubectl run down --image="$BAD_IMAGE" --restart=Never >/dev/null 2>&1; check "webhook down => fail closed (denied)" 1 $?
kubectl run down2 --image="$OK_IMAGE" --restart=Never >/dev/null 2>&1; check "webhook down => even anchored image denied" 1 $?

# OATH_PROGRAM (experimental, README: "On-chain records"): the real devnet-deployed program, in the real
# shipped Docker image, inside a real cluster. The fixtures are the same ones test/live-devnet-pda.mjs
# uses, anchored/revoked live on devnet — real on-chain state, not a mock. The webhook is reinstalled for this section
# with the program id below.
PDA_PROG=EWse8WXE3BYTeLvyDHufhp1Z73Pjqiq7nohAPE4cLSEc
PDA_SIGNER=5D4W8x8UeqW3qVi9uzNzvJPWiJZQaRWVR9ru2ckFhoih
PDA_IMG=ghcr.io/tymofii-thc/oath-records-devnet-check
PDA_OK="sha256:$(printf 'd%.0s' $(seq 1 64))"       # anchored, never revoked
PDA_REVOKED="sha256:$(printf 'e%.0s' $(seq 1 64))"  # anchored, then revoked
OATH_SIGNER=$PDA_SIGNER OATH_IMAGE=oath:e2e OATH_PROGRAM=$PDA_PROG "$root/deploy/install.sh" >/dev/null 2>&1
kubectl -n oath-system rollout status deploy/oath-webhook --timeout=60s >/dev/null 2>&1
kubectl run pda-ok --image="$PDA_IMG@$PDA_OK" --restart=Never >/dev/null 2>&1; check "OATH_PROGRAM: anchored (never revoked) digest admitted" 0 $?
kubectl run pda-revoked --image="$PDA_IMG@$PDA_REVOKED" --restart=Never >/dev/null 2>&1; check "OATH_PROGRAM: revoked digest denied" 1 $?

# Human-approved releases: the webhook decides from signed approvals in a ConfigMap, with no chain and no RPC at all.
# The only trusted key is a fresh "human" key; whoever controls the pipeline (and its key) cannot change what the cluster accepts.
case "$OK_IMAGE" in
  *@sha256:*)
    adir="$(mktemp -d)"; mkdir "$adir/files"
    node --input-type=module -e '
      import { generateKeyPairSync } from "node:crypto"; import { writeFileSync } from "node:fs"; import { b58encode } from "'"$root"'/lib/approval.mjs";
      const { privateKey, publicKey } = generateKeyPairSync("ed25519");
      const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32), pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
      writeFileSync("'"$adir"'/human.json", JSON.stringify([...Buffer.concat([seed, pub])]), { mode: 0o600 }); writeFileSync("'"$adir"'/human.pub", b58encode(pub));'
    HUMAN="$(cat "$adir/human.pub")"
    OATH_SIGNER=$HUMAN OATH_IMAGE=oath:e2e OATH_APPROVALS=yes "$root/deploy/install.sh" >/dev/null 2>&1
    kubectl -n oath-system rollout status deploy/oath-webhook --timeout=90s >/dev/null 2>&1
    waitfile() { for _ in $(seq 1 40); do kubectl -n oath-system exec deploy/oath-webhook -- ls /approvals 2>/dev/null | grep -q "$1" && return 0; sleep 3; done; return 1; }
    kubectl run appr-none --image="$OK_IMAGE" --restart=Never >/dev/null 2>&1; check "approvals: nothing approved yet -> denied" 1 $?
    SOLANA_SECRET_KEY="$(cat "$adir/human.json")" node "$root/bin/oath.mjs" approve --image "${OK_IMAGE%@*}" --digest "${OK_IMAGE#*@}" --commit 0123456789ab --out "$adir/files/approval.json" >/dev/null 2>&1
    kubectl -n oath-system create configmap oath-approvals --from-file="$adir/files" --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    waitfile approval.json; sleep 7
    kubectl run appr-ok --image="$OK_IMAGE" --restart=Never -- sleep 20 >/dev/null 2>&1; check "approvals: a digest the human approved is admitted" 0 $?
    kubectl run appr-bad --image="$BAD_IMAGE" --restart=Never >/dev/null 2>&1; check "approvals: an image nobody approved is denied" 1 $?
    SOLANA_SECRET_KEY="$(cat "$adir/human.json")" node "$root/bin/oath.mjs" approve --revoke --digest "${OK_IMAGE#*@}" --reason e2e --out "$adir/files/revoke.json" >/dev/null 2>&1
    kubectl -n oath-system create configmap oath-approvals --from-file="$adir/files" --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    waitfile revoke.json; sleep 7
    kubectl run appr-rev --image="$OK_IMAGE" --restart=Never >/dev/null 2>&1; check "approvals: a revoked digest is denied" 1 $?
    rm -rf "$adir";;
  *) echo "SKIP  approvals (OK_IMAGE is not a digest reference)";;
esac

[ $fails -eq 0 ] && echo "ALL PASSED" || { echo "$fails FAILED"; exit 1; }
