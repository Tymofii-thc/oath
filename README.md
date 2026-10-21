<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="verifier/assets/logo-white.svg">
    <img src="verifier/assets/logo-black.svg" alt="oath." height="64">
  </picture>
</p>

**English** · [Українська](README.uk.md)

*Don't deploy what the pipeline didn't build.*

> The version submitted to the hackathon is tagged [`hackathon-submission`](https://github.com/Tymofii-thc/oath/tree/hackathon-submission). `main` contains later security fixes (see [THREAT-MODEL.md](THREAT-MODEL.md)).

Oath stops a container image from reaching production unless your CI recorded it (a signed record of its digest on Solana). Live verifier: **https://tymofii-thc.github.io/oath/**

**Problem.** A swapped image in the registry, a manual `docker push` that bypasses CI, a compromised token: nobody notices that production runs something other than what was built. That is a supply-chain attack, and the code in git can be perfectly clean.

**Solution.** Every CI build records `commit → image digest → time` on Solana as a standard Memo transaction signed by the CI key (no custom smart contract). Before deploy, `oath verify` checks the digest of the image about to run against those records and **stops the deploy** if there is none.

```
build ──► image digest ──► Solana Memo tx (signed by the CI key)
                                  │
deploy ──► docker pull ──► oath verify ──► ✔ exit 0  → deploy proceeds
                                         ✘ exit 1  → deploy stopped
```

**Why Solana, honestly.** Not for extra cryptographic security — a signed, append-only log (what Sigstore's Rekor already is) gives the same tamper-evidence, and oath does not cryptographically verify the chain either: the RPC answer is trusted, not light-client-checked (see THREAT-MODEL.md, "Trust assumptions"). What a public ledger buys instead is a trust root nobody operates: records live on thousands of independent validators, not a server we (or anyone) can quietly edit or take offline, and anyone can read or verify them with no account. Named comparisons, since vague "decentralization" isn't an answer:
- **Sigstore/Rekor** is the closest cousin, and also a public transparency log — the difference is operational (no Sigstore-project infrastructure to depend on), not cryptographic. oath also *uses* Sigstore itself (`--attest`, for build provenance); it is not a replacement for it.
- **cosign + policy-controller, Kyverno, Connaisseur** are mature, free, widely-adopted Kubernetes admission webhooks that already verify image signatures/attestations. oath's webhook does the same policy job; what differs is the backing store (a public ledger instead of a registry-attached signature), not the enforcement model.

If you already run Rekor or one of those webhooks, this isn't a reason to switch. It's for teams who want a provenance gate without standing up that infrastructure.

**Install:** `npm install -g oath-verify` gives you the `oath` command. Or skip the install and put `npx --yes oath-verify` in front of any command below (handy in CI: pin it as `npx --yes oath-verify@0.3.2`). In a clone, `node bin/oath.mjs` is the same thing. `oath` below means any of these.

## Set up in 3 steps

**1. A CI key** (once, about a minute):
```bash
npx --yes oath-verify init      # or: node bin/oath.mjs init  in a clone
```
`oath init` creates a key in `.oath/ci-key.json` (the secret is never printed and `.oath/` goes into `.gitignore`), asks the devnet faucet for SOL, and if the public faucet refuses (it often does) it prints the link and **waits until you've funded the key**. It then prints exactly what to add to your repository: the secret `SOLANA_SECRET_KEY`, the variable `OATH_SIGNER`, and the two workflow steps below. With the GitHub CLI installed and logged in, `oath init --set-github` sets the secret and variable for you (checked with a real `gh` on a throwaway private repository).

**2. Record after the build** (in your workflow):
```yaml
- uses: Tymofii-thc/oath@main
  with:
    image: ghcr.io/${{ github.repository }}
    digest: ${{ steps.build.outputs.digest }}
    secret-key: ${{ secrets.SOLANA_SECRET_KEY }}
```

**3. Verify before deploy** (no npx, no flags):
```yaml
- uses: Tymofii-thc/oath/verify@main
  with:
    signer: ${{ vars.OATH_SIGNER }}
    image: ghcr.io/${{ github.repository }}:latest
```
The action pulls the image and fails the job (exit 1) if the digest has no record. Optional inputs: `network`, `rpc`, `quorum`, `max-age`, `attest` (see below), or `digest` instead of `image`.

A complete minimal workflow (about 40 lines): [`examples/github-minimal.yml`](examples/github-minimal.yml). Optional hardening on top of it, such as SLSA build provenance (needed for `--attest`), an SBOM and a Trivy scan, is in this repository's own [`deploy.yml`](.github/workflows/deploy.yml). Step-by-step testing guide: [TESTING.md](TESTING.md).

## CLI
```bash
oath verify --signer <pubkey> --digest sha256:…
oath verify --signer <pubkey> --image ghcr.io/me/app:latest
oath verify --signer <pubkey> --container prod      # the image that is running RIGHT NOW
oath audit  --signer <pubkey>                       # every Pod running in the current kube context
oath anchor --image ghcr.io/me/app:latest           # record a build from any CI (SOLANA_SECRET_KEY; the digest comes from the registry, no docker)
```
Exit codes: `0` verified, `1` not verified, `2` error (network, arguments). Options: `--network devnet|mainnet` or `--rpc <url>`, `--max-age <days>`, `--quorum <N>`, `--attest <owner/repo>`, `--no-bind`.

`verify --image repo@sha256:…` needs neither docker nor a registry call; for a tag that is not in local docker the digest is read from the registry (private ones: `OATH_REGISTRY_AUTH`). CI examples: [`examples/github-minimal.yml`](examples/github-minimal.yml) and [`examples/azure-pipelines.yml`](examples/azure-pipelines.yml) (the Azure one was tested on a real Azure DevOps pipeline with ACR).

`verifier/` is a simplified check in the browser, for demos and for people who avoid the terminal: it confirms that the signer really recorded the digest, but it does not look at revocations, quorum, the image name, `--max-age` or attestations. Use the CLI for decisions.

## Azure DevOps (and other CI systems)
`oath anchor` and `oath verify` are plain commands, so any CI works. [`examples/azure-pipelines.yml`](examples/azure-pipelines.yml) is a complete pipeline for Azure Container Registry. **Tested on a real Azure DevOps pipeline with ACR (2026-10-20): record and verify both passed.** Not tested: Azure Container Apps deploys, Key Vault-backed variables.

Setup: `oath init`, then a variable group with `SOLANA_SECRET_KEY` (secret), `OATH_SIGNER` and `OATH_REGISTRY_AUTH` (secret, `{"<registry>.azurecr.io":{"username":"…","password":"…"}}`, host in lowercase). Azure does not pass secret variables to scripts by itself: map each one in `env`. For the ACR login use the admin user (username = registry name), or a repository token with read scope (username = token name), or a service principal with `AcrPull`.

**What this protects, and what it does not.** The `verify` step is voluntary: whoever controls the deployment can leave it out, and a pipeline that does not contain it deploys anything. It becomes mandatory only where the image runs (the Kubernetes webhook) or where deployment rights belong to your pipeline alone. There is no admission webhook for Azure Container Apps, so there the gate is the `verify` step plus those rights.
- Stolen registry credentials: an attacker can push an image, but cannot record its digest, so the pipeline refuses to deploy it. A swapped tag is refused the same way, as long as you verify and deploy the same digest (`repo@sha256:…`), as the examples do.
- The records live on Solana, outside Azure: someone who gets admin in Azure cannot rewrite what was recorded.
- Someone who can edit your pipeline or read the `SOLANA_SECRET_KEY` variable can record anything: use `--quorum 2` with an approver key that is not in Azure DevOps (see below), and limit who can edit pipelines.
- Someone with direct rights on the registry and the Container App can still replace the running image by hand (portal, `az`). oath cannot block that. Take `AcrPush` and write access to the Container App away from people, leaving them to the pipeline's service connection, and check what is running: `oath verify --signer <key> --image <the image from az containerapp show>` fails if it was not built by the pipeline.

## Protecting the cluster (Kubernetes admission webhook)
A CI step can't stop someone who runs `kubectl apply` directly. So there is a webhook inside the cluster:

```bash
OATH_SIGNER=<public key> OATH_NETWORK=mainnet deploy/install.sh   # generates TLS, installs into namespace oath-system
kubectl run t --image=nginx        # → denied: no pipeline build anchored by the trusted signer(s)
```
- For each new Pod it takes every image (`initContainers`, `containers`, `ephemeralContainers`), resolves the tag to a digest through the registry and looks for a record on Solana. No record: the Pod is not created (including Pods of Deployments and Jobs).
- **Pins the tag to the verified digest** (`app:latest` → `app@sha256:…`), so the kubelet pulls exactly what was verified and the tag can't be moved between check and pull.
- **Fails closed:** an unreachable registry, RPC or the webhook itself means the Pod is rejected (`failurePolicy: Fail`). Exempt: `kube-system`, `kube-public`, `kube-node-lease` and `oath-system`, so the cluster can't lock itself out.
- **Helm instead of `install.sh`:** `helm install oath oci://ghcr.io/tymofii-thc/charts/oath --version 0.2.0 -n oath-system --create-namespace --set signer=<pubkey>` (values: `network`, `rpc` / `rpcSecret`, `mode`, `failurePolicy`, `quorum`, `attestRepo`, `program`, `staleOkHours`, `registryAuth`, `allowedRegistries`, `auditSchedule`; TLS is generated by Helm and reused on upgrade). Tested in kind: install, deny, `mode=audit` upgrade, audit CronJob, uninstall. The API server may need a few seconds after `helm install` before the Service answers.
- `OATH_MODE=audit` allows everything but returns warnings: useful for a first rollout.
- `OATH_FAILURE_POLICY=Ignore deploy/install.sh` sets `failurePolicy: Ignore` (availability over enforcement; combine with `oath audit`). The webhook runs 2 replicas with a PodDisruptionBudget.
- Private registries: `OATH_REGISTRY_AUTH='{"ghcr.io":{"username":"u","password":"token"}}'` (tested against a password-protected registry and a mock token registry; note that the kubelet still needs its own `imagePullSecrets` to pull the image).
- **Two webhooks, on purpose:** the verdict comes from a `ValidatingWebhookConfiguration`, which sees the Pod after every mutating webhook in the cluster (sidecar injectors and the like) has run, so nothing can change an image behind its back. Pinning a tag to its digest is a separate `MutatingWebhookConfiguration` that never denies and is reinvoked after other mutators; if it is down, the verdict still checks the tag. Upgrading from an older install: re-run `install.sh` / `helm upgrade`; the old single `/validate` endpoint still works until you do.
- Tested in a real cluster (kind): `test/e2e-kind.sh` covers admit, tag pinning, deny, Deployment pods blocked, both webhook configurations, and fail-closed with the webhook down.

## Pods that are already running
The webhook only checks new Pods. For the ones already running:
```bash
oath audit --signer <pubkey> --network mainnet [--skip-namespaces kube-system,…] [--file pods.json]
```
It reads every container of the current kube context (`kubectl get pods -A -o json`, using the real digests from `imageID`), checks them against the records and exits 1 if anything is unverified. Tested in kind: Pods created before the webhook are found (`alpine` VERIFIED, `nginx` NOT VERIFIED).

## Build attestation (SLSA provenance)
A record on Solana proves "the signer recorded this digest", not "the build was honest". So CI also issues a build-provenance attestation through GitHub/Sigstore (keyless, no long-lived key), and `oath verify` can require it:
```bash
oath verify --signer <pubkey> --image ghcr.io/me/app:latest --attest me/app/deploy.yml@refs/heads/main
```
**Pin the workflow and the ref.** `--attest me/app` alone accepts an attestation from *any* workflow of the repository on *any* branch, tag or pull request, so anyone who can push a branch or add a workflow file gets a valid one. `owner/repo/workflow.yml@refs/heads/main` requires that exact workflow on that exact ref (a bare file name means `.github/workflows/<file>`; `owner/repo@refs/heads/main` pins only the ref). Write the full ref (`refs/heads/main`, `refs/tags/v1.0.0`). This repository does it in its own pipeline.
It checks the cryptographic signature and the Sigstore transparency-log entry (via the `sigstore` library, Fulcio certificate chain), that the signer is GitHub Actions of the repository `me/app` (and, if you pinned them, that workflow file and that ref), and that the signed statement is about exactly this digest and image. A missing attestation, a different repository, a different digest or an API error gives `NOT VERIFIED` (exit 1) or exit 2, never "ok". For the webhook: `OATH_ATTEST_REPO=me/app/deploy.yml@refs/heads/main deploy/install.sh` (a malformed value stops the webhook from starting). Tested against our CI's real attestation, including negative cases (another repository, an image without an attestation).

## Signer quorum (recommended — closes the stolen-CI-key hole)
The 3-step setup above has exactly one key: whoever holds `SOLANA_SECRET_KEY` can record a forged digest, full stop. That is the one attack in the [threat model](THREAT-MODEL.md) that isn't a mitigation away from working, so we recommend doing this next, not treating it as optional hardening. `oath init` prints it as the next step after setup. An image is then accepted only if **N different keys** each recorded its digest:
```bash
# make the approver's key (kept OUTSIDE CI; it prints the public key and the next steps, and never asks you to add it to GitHub):
oath init --approver
# the CI key records automatically; a human approver records with their own key (laptop, separate device):
SOLANA_SECRET_KEY="$(cat approver.json)" node scripts/anchor.mjs --image ghcr.io/me/app --digest sha256:… --commit <sha>
# before deploy:
oath verify --signer <ciKey>,<approverKey> --quorum 2 --image ghcr.io/me/app:latest      # webhook: OATH_QUORUM=2
```
Someone who steals the CI key can record a forged digest but cannot produce the approver's second record, so the quorum is not met. Tested on live devnet: a digest with two records passes (`quorum 2/2`), a digest with only the CI record does not.

**About hardware keys, honestly.** A quorum protects you if the approver key is kept separately from CI. Signing with a hardware key *inside CI* is impossible (there is no device), and signing with a Ledger or wallet is **not implemented or tested** in this tool: `anchor.mjs` signs with a key from a file. Hardware storage of the approver key is up to the operator; we only guarantee that without a second independent record the deploy does not pass.

## On-chain records (experimental)
The Memo path above has one structural limitation (see THREAT-MODEL.md): verification pages back through a signer's transaction history, bounded by `--limit`/`OATH_LIMIT`. Someone can spam a signer's address with enough transactions to push an old revocation out of that scanned window — a revoked digest can start verifying again. `program/oath_records` is a small, native (no Anchor) Solana program that closes this structurally: one account per `(signer, digest)`, derived deterministically and looked up directly (`getAccountInfo`), never scanned. A revocation account has no window to be evicted from — it exists or it doesn't, permanently; this program has no instruction that ever deletes one.

```bash
oath anchor --program <programId> --image ghcr.io/me/app:latest --digest sha256:…     # one account, not a Memo tx
oath verify --program <programId> --signer <pubkey> --image ghcr.io/me/app:latest
oath revoke --program <programId> --digest sha256:… --reason "…"                       # not evictable by spam
```
`--program <id>` (or `OATH_PROGRAM`) switches `anchor`/`verify`/`revoke` to this backend instead of Memo transactions; omit it and nothing changes, every example and workflow above is unaffected. It needs `@solana/web3.js` (the same optional dependency `oath init` already needs). **The webhook honors `OATH_PROGRAM` too** — this is the one that matters most: the threat model notes that a `verify` step in a pipeline is voluntary (whoever controls the pipeline can remove it), so the revocation-eviction gap is most worth closing at the admission webhook, the actually-mandatory enforcement point.

**Deployed and tested live on devnet**: program `6n6fJ6WQgSQFie6BQHfGxFgw9groqusUgwC48Y7hgpJq`. The anchor→verify→revoke→verify-again cycle was run against it for real (not mocked), through both the CLI and the webhook: a digest anchored and never revoked is admitted, a revoked one is denied with a real on-chain account lookup backing the decision, and re-anchoring after a revocation does not un-revoke it — see `test/live-devnet-pda.mjs` (a permanent regression against that exact deployment) and `test/e2e-pda.sh` (the same cycle through a fresh local validator and the real compiled program, in CI).

**Honestly, what "experimental" means here**: this is new, has no external audit, is not the default for any command, and the program's upgrade authority is currently the project's own CI key (a single point of control, and worse than the key's power over Memo records: whoever holds the upgrade authority can replace the program with one that creates "records" for any signer, **including the approver, which defeats `--quorum 2`**. Do not rely on `--program` together with a quorum until the upgrade authority is a different key from CI's, or the program is frozen). `--max-age` is not supported with `--program` (the command refuses to run rather than ignore it: the time in an on-chain record is supplied by the signer). **A review found that anyone could block a record or a revocation forever by sending lamports to its address first (the plain `create_account` failed on a funded address). The program source now handles that (top up, allocate, assign) and `test/e2e-pda.sh` covers it; the program already deployed on devnet is the OLD build and has the hole until it is upgraded.** Treat it as a demonstration that the structural fix works, not yet as a drop-in replacement for the Memo path in production.

## Approve or revoke with a wallet
`verifier/approve.html` (live: https://tymofii-thc.github.io/oath/approve.html) lets a human approver add the second quorum signature, or revoke a digest, from a browser wallet (Phantom, Solflare; both can use a Ledger). The page builds one Memo transaction, shows exactly what will be signed, and asks the wallet to sign it; your private key never touches the page. Compare the digest with the one in the CI log before you approve.
**Tested** with a real Phantom (browser extension) on live devnet: the page's transaction was signed by the wallet, accepted, and `oath verify --quorum 2` passed (and failed with the CI key alone). Signing was also confirmed with a real Solflare (2026-10-20). **Not tested** with a Ledger.

## Mainnet
Everything works the same way: `--network mainnet` (CLI), `OATH_NETWORK=mainnet` (webhook), `?net=mainnet` or the dropdown (page), and for recording in CI the action's `rpc` input (or the repository variable `SOLANA_RPC`). A record costs roughly 0.000005 SOL in fees. The browser verifier uses `solana-rpc.publicnode.com` for mainnet because `api.mainnet-beta.solana.com` answers 403 to every browser request (the `Origin` header); the CLI and webhook are unaffected. The public `api.mainnet-beta.solana.com` is rate-limited; for production use your own RPC (Helius, QuickNode, …) via `--rpc` / `SOLANA_RPC`. We have **not** run CI on live mainnet yet; there is a manual `anchor-mainnet` workflow for it.

## Keys: rotation, revocation, expiry
- `--signer a,b` / `OATH_SIGNER=a,b` accepts several keys (a record from any one is enough unless `--quorum` is set). **Rotation:** add the new key → switch CI → remove the old key after a grace period.
- **Revoking a key:** remove the compromised key from the list; all its records stop counting immediately (this is verification policy, not on-chain data).
- **Revoking a digest:** `oath revoke --digest sha256:… --reason "…"` (with `SOLANA_SECRET_KEY` or `--key-file`) writes a signed revocation record. A revocation by **any trusted signer is final**: that digest never verifies again, even if it was anchored again later. `verify` and `audit` then report `REVOKED` with the reason. This is how you mark a forged record once you notice it, without waiting for a key rotation.
- `--max-age <days>`: old records are not accepted, so a stolen old digest doesn't live forever.
- A record is bound to the image name: a digest recorded for `ghcr.io/me/other` will not verify `ghcr.io/me/app` (disable with `--no-bind`).
- Verification pages through the signer's history (up to `--limit` transactions, 1000 by default), not just the latest 100.

## Availability
- `--rpc a,b,c` / `SOLANA_RPC=a,b,c`: several RPC endpoints are tried in order, so one dead or rate-limited endpoint does not block verification. If all of them fail, verification still fails closed.
- A `429` from an endpoint moves on to the next endpoint at once; only when every endpoint has failed and one of them was rate limited does it back off and go round again (`OATH_RPC_RETRIES` rounds, default 3). With a single endpoint that is plain retry with backoff. The public devnet RPC mostly returns 429 under load.
- The webhook answers within `OATH_DEADLINE_MS` (default 12000, below the API server's 15 s): a slow lookup gives a clear denial ("verification took longer than 12s; retry shortly") instead of an opaque "failed calling webhook", and it keeps running to fill the cache, so the retry is usually instant.
- `OATH_SIGNER` sets the trusted signer(s); `SOLANA_RPC` (CLI env var, `deploy/install.sh` argument, or the Helm `rpc` value) overrides the network default for the CLI, the webhook and the audit CronJob alike. In the cluster the URL is stored in a Secret (`oath-rpc`; Helm: `rpc`, or `rpcSecret` to name your own), because RPC URLs usually carry an API key.
- The "single-signer verification" note of `oath verify` is printed only on an interactive terminal (silence it with `OATH_QUIET=1`), so CI logs stay clean.
- The webhook keeps a short-lived result for every verified image. With `OATH_STALE_OK_HOURS` (default 1; `0` = strictly fail closed) an image that was verified within that window is still admitted while the RPC is unreachable. Records are immutable, so the only thing this can miss is a revocation made during the outage.
- `deploy/install.sh` also installs a CronJob (hourly by default; `OATH_AUDIT_SCHEDULE="*/30 * * * *"` changes it, `OATH_AUDIT_SCHEDULE=off` skips it) that runs `oath audit --in-cluster`, and runs it once right after install, so Pods that were running before the webhook are checked too. A Job that finds an unverified or revoked image fails: `kubectl -n oath-system get jobs`. The Helm chart has the same hourly CronJob (`auditSchedule`, empty = off).

## Vulnerability scanning (optional)
Oath proves provenance, not safety. The CI pipeline also publishes a signed **SBOM** (CycloneDX, generated by Trivy and attested through Sigstore) next to the build attestation. To avoid recording vulnerable images, set the repository variable `OATH_SCAN=true`: Trivy then checks the image for fixable CRITICAL vulnerabilities (tune with `OATH_SCAN_SEVERITY`, e.g. `HIGH,CRITICAL`, and `OATH_SCAN_INCLUDE_UNFIXED=true`) before recording, and if it finds any no record is written, so the `deploy` step fails.

## Run the demo yourself
A scripted version of the whole story: it builds an image, records it on Solana, verifies it, then swaps the image under the same tag and shows the check fail.
```bash
SOLANA_SECRET_KEY="$(cat .oath/ci-key.json)" demo/demo.sh     # needs docker and a funded devnet key (see `oath init`)
```
Expect `VERIFIED` with exit code 0, then `NOT VERIFIED` with exit code 1. The same two checks are one click each in the [live verifier](https://tymofii-thc.github.io/oath/).

## More
- **Admin status page: https://tymofii-thc.github.io/oath/root/** — live CI badges, the actual CHANGELOG.md/THREAT-MODEL.md content (fetched, not duplicated), recent commits, and the key/cert/backup facts an operator needs. No marketing copy. Not linked from the homepage, not access-controlled either — nothing on it is secret, it's just not for visitors.
- [THREAT-MODEL.md](THREAT-MODEL.md): attacks, what happens, what is not covered, and what a security review of the code found and fixed (including a forgery hole, reproduced and closed).
- The webhook checks `UPDATE` too (editing a running Pod's image, `kubectl debug`), exposes Prometheus metrics at `/metrics`, and has optional `OATH_ALLOWED_REGISTRIES` (comma-separated registries it may contact) and `OATH_LIMIT` (transactions scanned per signer).
- **`OATH_ALLOWED_REGISTRIES` is empty (any host) by default, and that is an SSRF surface**, not a theoretical one: anyone who can create a Pod picks the image field, and the webhook resolves it. The webhook warns loudly on startup if it is unset; set it to the registries you actually use (`install.sh`: `OATH_ALLOWED_REGISTRIES=ghcr.io,myregistry.azurecr.io`; Helm: `allowedRegistries`). See THREAT-MODEL.md for the full attack row.

## Limitations (we say them before you ask)
- **CI key.** Whoever steals `SOLANA_SECRET_KEY` can record a forged digest. A quorum with an independent approver key closes this, but it needs a human in the loop and a separately stored key; without a quorum you only get mitigations (rotation, revocation, `--max-age`, image binding). Hardware keys and Ledger signing are **not implemented**.
- **Honesty of the build.** A Solana record only proves "the signer recorded this digest". `--attest` verifies the SLSA build attestation (Sigstore) and proves that the named repository's workflow built the digest (the exact workflow and ref, when you pin them: see "Build attestation"), but not that the code itself is safe (the optional Trivy gate covers known vulnerabilities).
- **Network.** devnet by default (free, but no retention guarantees). Mainnet is supported but not exercised in CI.
- **Registry and RPC as dependencies.** The webhook fails closed, so while the RPC or registry is unreachable new Pods are not created (running Pods are untouched). Production needs a reliable RPC.
- **Pods created before the webhook was installed** are not blocked (the webhook only sees new ones); they are audited at install and hourly after that, so a bad image is reported, not stopped.
- Closest alternative without a blockchain: Sigstore/Rekor. Our difference: a public ledger that doesn't depend on a single operator.

## Tests
```bash
npm test                      # unit tests (mocked Solana RPC, quorum, attestations, admission logic, audit)
OATH_SIGNER=… OK_IMAGE=alpine:3.20 BAD_IMAGE=nginx:alpine test/e2e-kind.sh   # needs docker, kind, kubectl
```

## License
MIT, see [LICENSE](LICENSE).
