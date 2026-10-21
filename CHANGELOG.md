# Changelog

## Unreleased

- The browser verifier shows `REVOKED` (a revocation signed by the entered signer wins over a record).
- Image volumes (`volumes[].image.reference`) are verified and pinned like container images (tested in a kind cluster with ImageVolume on).
- `oath init` prints `Tymofii-thc/oath@v<version>` for the actions instead of `@main`; the docs pin `@v0.4.0`.
- `jayson` is overridden to 5.x in this repository: 0 `npm audit` advisories for a checkout, CI and the webhook image (see THREAT-MODEL.md).

## 0.4.0

**Upgrading.** Re-run `deploy/install.sh` (or `helm upgrade` with the new chart): the webhook is now two webhooks, and `install.sh` now needs Node (`npx`) or a checkout with `npm ci`, because it checks the webhook image before installing it. Everything else keeps working as before.

**Kubernetes**
- **The verdict is a `ValidatingWebhookConfiguration`** (`/verdict`), and tag pinning is a separate `MutatingWebhookConfiguration` (`/pin`, `reinvocationPolicy: IfNeeded`, `failurePolicy: Ignore`, never denies). Before, one mutating webhook with `reinvocationPolicy: Never` did both, so another mutating webhook that ran after it could change the Pod unseen. The old `/validate` path still answers (both in one) so a half-upgraded install keeps working. The kind e2e checks both configurations and that the API server calls `/pin`.
- **The webhook image is verified before it is installed, and installed by digest.** `install.sh` runs `oath verify --attest` on `ghcr.io/tymofii-thc/oath-webhook` (recorded on Solana by the project's key, Sigstore attestation from `release-webhook.yml` on `main`) and applies `…@sha256:…`; a failed check installs nothing. `release-webhook` now attests the image's build, CI checks the published image on every run, and the Helm release job checks it and ships the chart with its digest. Your own image: `OATH_IMAGE_SIGNER` / `OATH_IMAGE_ATTEST`; `OATH_VERIFY_IMAGE=skip` turns it off, loudly.
- The webhook warns on startup if `OATH_ALLOWED_REGISTRIES` is unset (any image host can be contacted: SSRF), and `OATH_MAX_AGE_DAYS` together with `OATH_PROGRAM` refuses to start.

**Image volumes are checked.** A Pod's `volumes[].image.reference` (Kubernetes ImageVolume) is verified and pinned like a container image, on CREATE and UPDATE. Tested in a kind cluster with the feature gate on: a Pod whose only un-anchored image is a volume is denied.

**`--attest` can be pinned to a workflow and a ref:** `owner/repo/workflow.yml@refs/heads/main` (also `OATH_ATTEST_REPO` and Helm `attestRepo`). A plain `owner/repo` still accepts any workflow and any ref of the repository, as before, but the docs now recommend pinning. A malformed requirement refuses to start the webhook and exits 2 in the CLI. Checked against this repository's real Sigstore attestation: the pinned workflow and ref pass, another ref or workflow is refused. This repository's own pipeline uses the pinned form.

**On-chain records (experimental): `--program <id>`**, a native Solana program (`program/oath_records`, no Anchor): one account per `(signer, digest)`, looked up directly instead of scanned out of transaction history, so a revocation cannot be pushed out of a scanned window by spam. For `anchor`, `verify`, `revoke` and the webhook (`OATH_PROGRAM`).
- Deployed on devnet: `EWse8WXE3BYTeLvyDHufhp1Z73Pjqiq7nohAPE4cLSEc`, built by CI and checksum-checked. A review found that anyone could block a record or a revocation forever by sending lamports to its address first; the program now tops such an account up, allocates and assigns it (`test/e2e-pda.sh` covers it, and it was reproduced on the first deployment and shown fixed on this one, live). The first deployment `6n6fJ6WQ…` is deprecated: it has that flaw, and its upgrade authority is a key the maintainer does not have.
- **Honestly experimental:** devnet only, no external audit, a single upgrade-authority key (a file on the maintainer's machine, no recovery phrase), not frozen. Whoever holds the authority can make the program create records for any signer, so **do not combine `--program` with `--quorum`**, and on mainnet audit first, then freeze or use a multisig. `--max-age` is refused with `--program`. CI publishes the built program with its checksum; `program/oath_records/DEPLOY.md` says how it was deployed.

**Known issue.** `npm audit` reports 4 moderate advisories in `@solana/web3.js` 1.x's dependencies (`jayson` 4 → `stream-json`, `uuid`). Fixed in this repository (and so in CI and the webhook image) by overriding `jayson` to 5.x; a plain `npm install oath-verify` still gets web3.js's own jayson 4, because npm does not apply a dependency's overrides. See THREAT-MODEL.md.

**Docs.** README: "why Solana, honestly" moved to the top, with a named comparison against Rekor, cosign/policy-controller and Kyverno. `THREAT-MODEL.md` lists what is still open (the commit field is only a label, rollback to an old recorded digest, a stolen CI key can revoke, image volumes, the webhook certificate lasts 825 days, and more).

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
