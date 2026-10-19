# Security policy

oath is a security tool, so reports are welcome.

**Report a vulnerability privately:** GitHub → Security → "Report a vulnerability" on this repository (private advisory), or email the maintainer listed on the repository profile. Please do not open a public issue for something exploitable.

What helps: the version or commit, how to reproduce, and what an attacker gains. We aim to answer within a few days.

**Scope:** the CLI (`bin/`, `lib/`), the admission webhook, the Helm chart and manifests (`deploy/`), the GitHub Actions in this repository, and the browser pages in `verifier/`.

**Already known and documented** (see [THREAT-MODEL.md](THREAT-MODEL.md)): a stolen CI key can record a forged digest unless `--quorum` is used, honest builds of malicious code are not detected, and devnet has no retention guarantees.

**History:** a review on 2026-10-19 found that records could be forged without the CI key by a transaction that only mentions its address, and that running Pods could be edited past the webhook. Both are fixed; details in THREAT-MODEL.md.
