# Changelog

## Unreleased

- A malformed `OATH_REGISTRY_AUTH` is reported as exactly that (with the character position, never the value) instead of "cannot get the digest".

## 0.3.2

- `oath --help` explains every command; `oath <command> --help` lists its options; `oath --version`. An unknown command exits 2 with the command list.

## 0.3.1

- `oath init` prints shorter, grouped next steps (three numbered steps, one optional hint); the approver output points to `oath anchor` and the approve page.

## 0.3.0

**CLI**
- `oath anchor --image <ref>`: record a build from any CI. The digest comes from the registry, the commit from `GITHUB_SHA` / `BUILD_SOURCEVERSION` / `CI_COMMIT_SHA` or git, the key from `SOLANA_SECRET_KEY` or `--key-file`. No docker needed.
- `oath verify --image repo@sha256:…` needs neither docker nor a registry call. A tag that is not in local docker is resolved through the registry (`OATH_REGISTRY_AUTH` for private ones).
- `oath init --approver` creates the second key for `--quorum 2` without the CI-secret steps; the single-signer note is shown only on a terminal.
- RPC: a comma list fails over at once on 429, backs off only when a whole round failed.

**Kubernetes**
- The webhook answers before the API server's 15 s timeout (`OATH_DEADLINE_MS`), caches at most 5000 entries, and exposes `/metrics`.
- `install.sh` and the Helm chart audit Pods that were already running: one run at install and an hourly CronJob (`OATH_AUDIT_SCHEDULE=off` / `auditSchedule: ""` to skip).
- Re-running `install.sh` restarts the Pods onto the new certificate (it used to leave them serving the old one). Pods also restart when `SOLANA_RPC` or the registry credentials change.
- `install.sh` escapes `&` and `|` in values; the RPC URL lives in a Secret.
- Image: Node 26, no npm in the final layer.

**Site and docs**
- New site design; the verifier no longer trips the public devnet rate limit (signature checks are cached and run on demand).
- The approve page lets you choose between installed wallets; signing is confirmed with Phantom and Solflare (Ledger is untested).
- `examples/github-minimal.yml` and `examples/azure-pipelines.yml` (the Azure one was tested on a real pipeline with ACR; the release notes of v0.3.2 said it was not).

## 0.2.0

First npm release. Forged-record fix (a record counts only if the signer really signed the transaction), the webhook also checks UPDATE and ephemeral containers, signer quorum, revocation, Helm chart.
