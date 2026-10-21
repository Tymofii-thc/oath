# Threat model

What oath protects, against whom, and where it stops. Everything below was either tested (marked **tested**) or is stated as an assumption.

## What is being protected
That a container image running in your cluster (or about to be deployed) is **one your own pipeline built and recorded**. The record is a Solana Memo transaction `commit → image digest → time`, signed by the CI key; verification reads the signer's history and requires the digest to be there.

## Trust assumptions
- The CI signing key (and, with `--quorum`, the approver keys) are not controlled by the attacker.
- The Solana RPC you query tells the truth. `--rpc a,b,c` is failover for availability, not a cross-check: the first answer wins, and the transaction is not verified cryptographically, so a lying RPC could fabricate a record. Use your own node or a provider you trust.
- The webhook binary and its Kubernetes configuration are the ones you installed (`deploy/install.sh` checks the official image before installing it, and installs it by digest: recorded by the project's CI key, with a Sigstore attestation from the `release-webhook` workflow on `main`; the published Helm chart ships a digest that its release job checked. The script itself is the trust anchor: take it from a tag or commit you reviewed. **tested** with a stand-in for the check in `test/install.test.mjs`; the real image check is run in CI).
- **`--program` (experimental, README: "On-chain records") additionally assumes the deployed program's upgrade authority is not controlled by the attacker.** It currently is the project's own CI key (`66RLA5s2R3XHGG7KPzcEWqitDZ3bbBDcb2XPhDgNw7uj`) — the same key already trusted for Memo records, so this adds no new single point of failure, but it means the program has not been made immutable and has had no external audit.

## Attacks and what happens

| Attack | Result |
|---|---|
| Swap an image in the registry under the same tag | Denied: the tag resolves to a different digest that has no record (**tested**, kind + devnet). In a pipeline this holds only if you verify and deploy the **same digest** (`repo@sha256:…`), not the tag: see `examples/` |
| Manual `docker push`, bypassing CI | Denied: no record for that digest (**tested**) |
| `kubectl apply` of an unrecorded image | Denied by the webhook, including Pods of Deployments/Jobs (**tested**) |
| Edit the image of a running bare Pod, or `kubectl debug` with a foreign image | Denied: the webhook checks `UPDATE` and `pods/ephemeralcontainers` (**tested**) |
| Move the tag between check and pull | The pin webhook rewrites the tag to the digest before the verdict webhook looks at it, so the Pod runs that digest (**tested**). If the pin webhook is down (`failurePolicy: Ignore` on purpose), the verdict still resolves and checks the tag, and a window of seconds remains between that check and the kubelet's pull |
| Forge a record without the CI key: send a transaction that only *mentions* the CI address next to a Memo the attacker signed | Ignored: a record counts only if the signer actually signed the transaction (**tested live on devnet**; this was a real hole in earlier versions, see "Found in review") |
| Steal the CI key and record a malicious digest | Passes with one key. With `--quorum 2` it also needs the approver's record (**tested** with real Phantom and Solflare). Revoke afterwards with `oath revoke` (**tested**) |
| Honest build of malicious code (compromised dependency or developer) | Not stopped. Mitigations: `--attest` (proves *which workflow* built it), SBOM attestation, optional Trivy gate |
| Spam a signer's address with transactions to push records out of the scanned window (Memo path) | Old digests stop verifying (availability), and **a revocation made by a trusted key can be pushed out the same way, so a revoked digest verifies again** (reproduced with a mock RPC in the 2026-10-20 review; costs about a fee per transaction). Raise `--limit` / `OATH_LIMIT`, or use `--program` (below), which has no window to spam out of (**tested live on devnet**: re-anchoring after a revocation does not un-revoke it). Caveat found in review: the first version of the program could be blocked by pre-funding an address (anyone can send lamports to it), which would have stopped a revocation forever; fixed in the source, not yet redeployed on devnet |
| Make the webhook contact arbitrary hosts via an image name (SSRF) | Anyone who can create a Pod can make the webhook send a HEAD/GET to a host of their choosing (the error text comes back in the denial). Set `OATH_ALLOWED_REGISTRIES` (`install.sh`, Helm `allowedRegistries`; **empty by default = any host**). Registry credentials are never sent to a host outside the registry's own domain (**tested**) |
| Take down the RPC or the webhook | New Pods are refused (`failurePolicy: Fail`). Already running Pods are unaffected. **A stale-ok window of 1 hour is on by default** (`OATH_STALE_OK_HOURS`): during an RPC outage an image verified in the last hour is admitted, so a revocation made in that time is not seen. Set `OATH_STALE_OK_HOURS=0` for strict behaviour. `failurePolicy: Ignore` turns the webhook off when it is down |
| Revoke-spam: forge revocations of good digests | Ignored for the same reason as forged records: a revocation must be signed by a trusted key |

## Not covered
- Anything about the *content* of an honestly built image.
- Pods created before the webhook was installed: `install.sh` and the Helm chart run `oath audit` once at install and then hourly (a failed Job = unverified or revoked image). Detection, not blocking: those Pods keep running.
- Namespaces exempt from the webhook (`kube-system`, `kube-public`, `kube-node-lease`, the webhook's own namespace, and any labelled `oath.io/exempt=true`). Anyone who can label a namespace can exempt it: restrict that permission.
- An attacker with cluster-admin can delete the webhook configuration.
- Revocation is seen by the webhook after its cache expires (up to 5 minutes).
- A stolen CI key can also **revoke** any digest, including the one in production (revocation by any trusted signer is final): a denial-of-service on new Pods.
- Rolling back to an old digest that was recorded and later turned out vulnerable. Limit it with `--max-age` (off by default) or revoke the digest.
- The `commit` field in a record is a label: nothing checks that the image was built from that commit.
- The verdict is given by a *ValidatingWebhookConfiguration*, so it sees the Pod after every mutating webhook has run (sidecar injectors included). Before 0.4.0 one mutating webhook with `reinvocationPolicy: Never` did both, and another mutator running after it could change the Pod unseen.
- Images mounted as volumes (`volumes[].image`, newer Kubernetes) are not checked. A verified image can still run with any command or privileges: oath does not restrict the Pod spec.
- The webhook certificate lasts 825 days and is not rotated. When it expires, `failurePolicy: Fail` blocks new Pods in the whole cluster: re-run `install.sh` (it makes a new one and restarts the Pods) before that.
- Removing the old key from the trusted list after a rotation makes every record that only it signed invalid: images that were recorded only by the old key cannot be re-scheduled until they are recorded again.
- The browser verifier is a simplified check (no revocation, quorum, image-name binding, `--max-age` or attestation).
- `--attest owner/repo` alone accepts an attestation from **any workflow and any ref** of that repository, so it shows "built by this repository's Actions". Pin it with `--attest owner/repo/workflow.yml@refs/heads/main` (also `OATH_ATTEST_REPO`, Helm `attestRepo`) to require that workflow on that ref; the loose form stays the default so existing setups keep working. Someone who can edit the pinned workflow on the pinned branch can still produce a valid attestation: protect that branch.
- The `verify` step in a pipeline is voluntary: whoever controls the pipeline can remove it. Only the webhook, or deployment rights held by your pipeline alone, makes it mandatory.
- Mainnet is supported but not exercised in CI; Ledger is untested (Phantom and Solflare are tested).
- `--program` (on-chain records): whoever holds the upgrade authority of the deployed program can make it create records for any signer, **including the approver (so `--quorum 2` is void)**, or close accounts it owns, including revocations: "a revocation is final" holds only for an immutable program. Today that authority is the CI key; the plan and the commands to move it to an offline key are in `program/oath_records/DEPLOY.md`. On mainnet: audit, then freeze or a multisig. `--max-age` is refused (the account format has no trustworthy age). `--attest` runs after either backend through the same code path, but the combination has not been run live. It is deployed to devnet only, has no external audit, and its upgrade authority is a single key (see "Trust assumptions"). It is not the default for any command.

## Found in review
A second, independent review (2026-10-20, another model, read-only, mock RPC) found: a tag swapped between verify and deploy in the Azure example because `verify --image <tag>` trusted the local docker copy (fixed: the registry is asked first, the examples deploy by digest); `anchor` could record a moved tag (fixed: the local copy is preferred); loopback detection by prefix (fixed); `OATH_ALLOWED_REGISTRIES` not settable from the installers (fixed); the browser verifier described as "the same check" (corrected); and the open items above. Each claim was checked against the code before being written here.

A security review of the code (2026-10-19) found and fixed:
1. **Forged records.** `getSignaturesForAddress` returns every transaction that mentions the address, not only those it signed. Anyone could add the CI address as a read-only account in a transaction carrying a Memo they signed themselves, and `oath verify` showed `VERIFIED`. Reproduced on devnet, then fixed in the CLI, the webhook and the browser verifier: the signer must be a real signer of the transaction.
2. **Running Pods could be edited.** The webhook handled only `CREATE`; changing the image of a bare Pod in place bypassed it. It now also checks `UPDATE` and ephemeral containers.
3. Registry credentials could be sent to the host named in an auth challenge; they are now sent only to the registry's own domain. Token requests have a timeout; an optional registry allowlist was added; the verification cache is capped.
4. The runtime image shipped npm with outdated bundled packages (10 HIGH findings in Trivy); npm is removed from the image (0 HIGH/CRITICAL now). GitHub Actions are pinned to commit SHAs.
