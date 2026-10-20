# Changelog

## 0.3.3

From an independent security review (every point was checked against the code first; the open ones are listed in THREAT-MODEL.md, "Not covered").
- **`oath verify --image <tag>` asks the registry first.** It used to trust the local docker copy, which in a CI job is the image the job had just pushed, so a tag moved in the registry before the deploy went unnoticed. The local copy is now only a fallback and says so. The examples verify and deploy the **same digest** (`repo@sha256:…`); `oath anchor` prints a `Digest :` line for that.
- **`oath anchor --image <tag>` records the local copy's digest** (what the job pushed) and falls back to the registry; `--dry-run` shows the record without a key.
- Loopback registries are matched exactly (`localhost.example` no longer counts as loopback).
- `OATH_ALLOWED_REGISTRIES` can be set from `install.sh` and Helm (`allowedRegistries`); it is still empty (any host) by default.
- A malformed `OATH_REGISTRY_AUTH` is reported as exactly that (with the character position, never the value).
- `oath init --out ci-key.json` now writes the right `.gitignore` line; `action.yml` passes its inputs through the environment instead of pasting them into the shell; `scripts/keygen.mjs` (prints a secret) is no longer in the npm package.
- The browser verifier and the docs no longer call it "the same check as the CLI"; the threat model lists what is still open.

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
