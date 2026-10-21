#!/usr/bin/env bash
# End-to-end test of the experimental --program (on-chain account) backend, against a REAL local Solana
# validator running the actual compiled program — not a mock. Same reasoning as test/e2e-kind.sh: build
# once, run the real CLI binary, check real exit codes. Needs: solana, cargo-build-sbf, solana-test-validator.
# Usage: test/e2e-pda.sh
set -uo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"; fails=0
check(){ if [ "$2" = "$3" ]; then echo "PASS  $1"; else echo "FAIL  $1 (expected $2, got $3)"; fails=$((fails+1)); fi; }

prog_dir="$root/program/oath_records"
ledger="$(mktemp -d)"
cleanup() { kill "$validator_pid" >/dev/null 2>&1; wait "$validator_pid" 2>/dev/null; rm -rf "$ledger" "$key_dir"; }
trap cleanup EXIT

(cd "$prog_dir" && cargo build-sbf >/dev/null) || { echo "cargo build-sbf failed"; exit 2; }

key_dir="$(mktemp -d)"
solana-keygen new --no-bip39-passphrase -o "$key_dir/program.json" --force >/dev/null 2>&1
PROGRAM_ID="$(solana address -k "$key_dir/program.json")"
solana-keygen new --no-bip39-passphrase -o "$key_dir/ci.json" --force >/dev/null 2>&1
CI_PUB="$(solana address -k "$key_dir/ci.json")"
[ -f "$HOME/.config/solana/id.json" ] || solana-keygen new --no-bip39-passphrase -o "$HOME/.config/solana/id.json" --force >/dev/null 2>&1

solana-test-validator --reset --quiet --ledger "$ledger" --bpf-program "$PROGRAM_ID" "$prog_dir/target/deploy/oath_records.so" >/tmp/oath-e2e-pda-validator.log 2>&1 &
validator_pid=$!
RPC=http://127.0.0.1:8899
for _ in $(seq 1 30); do solana cluster-version --url $RPC >/dev/null 2>&1 && break; sleep 1; done
solana cluster-version --url $RPC >/dev/null 2>&1 || { echo "validator did not come up"; cat /tmp/oath-e2e-pda-validator.log; exit 2; }
solana airdrop 2 "$CI_PUB" --url $RPC >/dev/null 2>&1

D="sha256:$(printf 'd%.0s' $(seq 1 64))"
export SOLANA_SECRET_KEY="$(cat "$key_dir/ci.json")"

node "$root/bin/oath.mjs" verify --program "$PROGRAM_ID" --signer "$CI_PUB" --digest "$D" --rpc $RPC >/dev/null 2>&1
check "unrecorded digest is NOT VERIFIED before anchoring" 1 $?

node "$root/bin/oath.mjs" anchor --program "$PROGRAM_ID" --image ghcr.io/me/e2e --digest "$D" --commit deadbeefcafe --rpc $RPC >/dev/null 2>&1
check "anchor --program exits 0" 0 $?

node "$root/bin/oath.mjs" verify --program "$PROGRAM_ID" --signer "$CI_PUB" --image ghcr.io/me/e2e --digest "$D" --rpc $RPC >/dev/null 2>&1
check "verify --program finds the anchored digest" 0 $?

# --image and --digest together ignore --image for binding purposes (resolveTarget() in bin/oath.mjs
# treats --digest as authoritative, repo: null); binding only applies via a pinned ref or a bare tag.
node "$root/bin/oath.mjs" verify --program "$PROGRAM_ID" --signer "$CI_PUB" --image "ghcr.io/me/other@$D" --rpc $RPC >/dev/null 2>&1
check "verify --program rejects the same digest under a different image name" 1 $?

node "$root/bin/oath.mjs" revoke --program "$PROGRAM_ID" --digest "$D" --reason "e2e test" --rpc $RPC >/dev/null 2>&1
check "revoke --program exits 0" 0 $?

out="$(node "$root/bin/oath.mjs" verify --program "$PROGRAM_ID" --signer "$CI_PUB" --digest "$D" --rpc $RPC 2>&1)"
check "verify --program reports REVOKED after revocation" 1 $?
case "$out" in *REVOKED*) check "output says REVOKED" ok ok;; *) check "output says REVOKED" ok "$out";; esac

[ $fails -eq 0 ] && echo "ALL PASSED" || { echo "$fails FAILED"; exit 1; }
