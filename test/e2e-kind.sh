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

kubectl run ok --image="$OK_IMAGE" --restart=Never -- sleep 30 >/dev/null 2>&1; check "anchored image admitted" 0 $?
img=$(kubectl get pod ok -o jsonpath='{.spec.containers[0].image}' 2>/dev/null)
case "$img" in *@sha256:*) check "tag pinned to digest" ok ok;; *) check "tag pinned to digest" ok "$img";; esac
kubectl run bad --image="$BAD_IMAGE" --restart=Never >/dev/null 2>&1; check "un-anchored image denied" 1 $?
kubectl create deploy evil --image="$BAD_IMAGE" >/dev/null 2>&1; sleep 8
msg=$(kubectl get rs -l app=evil -o jsonpath='{.items[0].status.conditions[*].message}' 2>/dev/null)
case "$msg" in *"refusing to admit"*) check "deployment pods blocked" ok ok;; *) check "deployment pods blocked" ok "none";; esac

# a bare Pod's image can be edited in place; ephemeral containers (kubectl debug) can be added: both must be checked too
kubectl patch pod ok -p "{\"spec\":{\"containers\":[{\"name\":\"ok\",\"image\":\"$BAD_IMAGE\"}]}}" >/dev/null 2>&1; check "in-place image swap on a running pod denied" 1 $?
kubectl debug ok --image="$BAD_IMAGE" --target=ok -- sleep 1 >/dev/null 2>&1; check "ephemeral container with un-anchored image denied" 1 $?
kubectl label pod ok touched=yes >/dev/null 2>&1; check "metadata-only update of a running pod still works" 0 $?

kubectl -n oath-system scale deploy/oath-webhook --replicas=0 >/dev/null 2>&1
kubectl -n oath-system wait --for=delete pod -l app=oath-webhook --timeout=60s >/dev/null 2>&1
kubectl run down --image="$BAD_IMAGE" --restart=Never >/dev/null 2>&1; check "webhook down => fail closed (denied)" 1 $?
kubectl run down2 --image="$OK_IMAGE" --restart=Never >/dev/null 2>&1; check "webhook down => even anchored image denied" 1 $?

[ $fails -eq 0 ] && echo "ALL PASSED" || { echo "$fails FAILED"; exit 1; }
