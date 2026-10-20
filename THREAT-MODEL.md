# Threat model

What oath protects, against whom, and where it stops. Everything below was either tested (marked **tested**) or is stated as an assumption.

## What is being protected
That a container image running in your cluster (or about to be deployed) is **one your own pipeline built and recorded**. The record is a Solana Memo transaction `commit → image digest → time`, signed by the CI key; verification reads the signer's history and requires the digest to be there.

## Trust assumptions
- The CI signing key (and, with `--quorum`, the approver keys) are not controlled by the attacker.
- The Solana RPC you query tells the truth (use several endpoints with `--rpc a,b,c`, or your own node).
- The webhook binary and its Kubernetes configuration are the ones you installed (the webhook image is itself built and recorded by this pipeline).

## Attacks and what happens

| Attack | Result |
|---|---|
| Swap an image in the registry under the same tag | Denied: the tag resolves to a different digest that has no record (**tested**, kind + devnet) |
| Manual `docker push`, bypassing CI | Denied: no record for that digest (**tested**) |
| `kubectl apply` of an unrecorded image | Denied by the webhook, including Pods of Deployments/Jobs (**tested**) |
| Edit the image of a running bare Pod, or `kubectl debug` with a foreign image | Denied: the webhook checks `UPDATE` and `pods/ephemeralcontainers` (**tested**) |
| Move the tag between check and pull | Not possible: the webhook rewrites the tag to the verified digest (**tested**) |
| Forge a record without the CI key: send a transaction that only *mentions* the CI address next to a Memo the attacker signed | Ignored: a record counts only if the signer actually signed the transaction (**tested live on devnet**; this was a real hole in earlier versions, see "Found in review") |
| Steal the CI key and record a malicious digest | Passes with one key. With `--quorum 2` it also needs the approver's record (**tested** with real Phantom and Solflare). Revoke afterwards with `oath revoke` (**tested**) |
| Honest build of malicious code (compromised dependency or developer) | Not stopped. Mitigations: `--attest` (proves *which workflow* built it), SBOM attestation, optional Trivy gate |
| Spam the CI address with transactions to push old records out of the scanned window | Old digests stop verifying (availability). Raise `--limit` / `OATH_LIMIT`; the webhook keeps recent verifications for `OATH_STALE_OK_HOURS` |
| Make the webhook contact arbitrary hosts via an image name (SSRF) | Limit with `OATH_ALLOWED_REGISTRIES`; registry credentials are never sent to a host outside the registry's own domain (**tested**) |
| Take down the RPC or the webhook | Fails closed by default (new Pods are refused). Already running Pods are unaffected. Optional: stale-ok window or `failurePolicy: Ignore` |
| Revoke-spam: forge revocations of good digests | Ignored for the same reason as forged records: a revocation must be signed by a trusted key |

## Not covered
- Anything about the *content* of an honestly built image.
- Pods created before the webhook was installed: `install.sh` and the Helm chart run `oath audit` once at install and then hourly (a failed Job = unverified or revoked image). Detection, not blocking: those Pods keep running.
- Namespaces exempt from the webhook (`kube-system`, `kube-public`, `kube-node-lease`, the webhook's own namespace, and any labelled `oath.io/exempt=true`). Anyone who can label a namespace can exempt it: restrict that permission.
- An attacker with cluster-admin can delete the webhook configuration.
- Revocation is seen by the webhook after its cache expires (up to 5 minutes).
- Mainnet is supported but not exercised in CI; Ledger is untested (Phantom and Solflare are tested).

## Found in review
A security review of the code (2026-10-19) found and fixed:
1. **Forged records.** `getSignaturesForAddress` returns every transaction that mentions the address, not only those it signed. Anyone could add the CI address as a read-only account in a transaction carrying a Memo they signed themselves, and `oath verify` showed `VERIFIED`. Reproduced on devnet, then fixed in the CLI, the webhook and the browser verifier: the signer must be a real signer of the transaction.
2. **Running Pods could be edited.** The webhook handled only `CREATE`; changing the image of a bare Pod in place bypassed it. It now also checks `UPDATE` and ephemeral containers.
3. Registry credentials could be sent to the host named in an auth challenge; they are now sent only to the registry's own domain. Token requests have a timeout; an optional registry allowlist was added; the verification cache is capped.
4. The runtime image shipped npm with outdated bundled packages (10 HIGH findings in Trivy); npm is removed from the image (0 HIGH/CRITICAL now). GitHub Actions are pinned to commit SHAs.
