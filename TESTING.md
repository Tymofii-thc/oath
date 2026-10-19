# Testing oath

Four levels, from 5 minutes to an hour. Each says what you should see. If something differs, that's a bug we want to hear about.

## 1. Five minutes: no accounts, no keys
```bash
git clone https://github.com/Tymofii-thc/oath && cd oath
npm ci
npm test                       # expect: 36 tests, all pass
node bin/oath.mjs verify \
  --signer 5D4W8x8UeqW3qVi9uzNzvJPWiJZQaRWVR9ru2ckFhoih \
  --digest sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
echo $?                        # expect: VERIFIED, 0
node bin/oath.mjs verify --signer 5D4W8x8UeqW3qVi9uzNzvJPWiJZQaRWVR9ru2ckFhoih \
  --digest sha256:1111111111111111111111111111111111111111111111111111111111111111
echo $?                        # expect: NOT VERIFIED, 1
```
Or use the browser verifier: https://tymofii-thc.github.io/oath/ (the two buttons do the same against Solana devnet).

## 2. Fifteen minutes: put it in your own repository
```bash
npx --yes --allow-git=all github:Tymofii-thc/oath init     # creates .oath/ci-key.json, funds it, prints the next steps
```
If the public devnet faucet refuses, `init` prints a link (https://faucet.solana.com, choose devnet) and waits for you to fund the key. Then add what it prints to your repository (a secret and a variable), and add two steps to a workflow that builds and pushes a container image:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: { contents: read, packages: write }
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with: { registry: ghcr.io, username: "${{ github.actor }}", password: "${{ secrets.GITHUB_TOKEN }}" }
      - id: build
        uses: docker/build-push-action@v6
        with: { context: ., push: true, tags: "ghcr.io/${{ github.repository }}:latest" }   # GHCR needs a lowercase repo name
      - uses: Tymofii-thc/oath@main                      # records the digest on Solana
        with:
          image: ghcr.io/${{ github.repository }}
          digest: ${{ steps.build.outputs.digest }}
          secret-key: ${{ secrets.SOLANA_SECRET_KEY }}
  deploy:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: docker/login-action@v3
        with: { registry: ghcr.io, username: "${{ github.actor }}", password: "${{ secrets.GITHUB_TOKEN }}" }
      - uses: Tymofii-thc/oath/verify@main               # fails the job if there is no record
        with:
          signer: ${{ vars.OATH_SIGNER }}
          image: ghcr.io/${{ github.repository }}:latest
```
Expect: the build job logs `Anchored: pod1|…` with an Explorer link, and the deploy job logs `VERIFIED`. To see it block, push a different image to the same tag yourself (`docker push` from your laptop) and re-run only the deploy job: it should fail with `NOT VERIFIED`.

## 3. Ten minutes: the attack, scripted
```bash
SOLANA_SECRET_KEY="$(cat .oath/ci-key.json)" demo/demo.sh     # needs docker and a funded key
```
Builds an image, records it, verifies it (VERIFIED, exit 0), then swaps the image under the same tag and verifies again (NOT VERIFIED, exit 1).

## 4. An hour: Kubernetes
```bash
OATH_SIGNER=5D4W8x8UeqW3qVi9uzNzvJPWiJZQaRWVR9ru2ckFhoih OK_IMAGE=alpine:3.20 BAD_IMAGE=nginx:alpine test/e2e-kind.sh
```
Needs docker, kind and kubectl. Expect six `PASS` lines and `ALL PASSED` (admit, tag pinning, deny, Deployment pods blocked, fail-closed twice). To use it on your own cluster: `OATH_SIGNER=<your public key> deploy/install.sh`, then `kubectl run t --image=nginx` should be denied. `oath audit --signer <key>` checks Pods that were already running.

## Known rough edges
- The public devnet faucet is rate-limited; fund keys by hand if `init` asks you to.
- Mainnet is supported in code but has not been run in CI.
- Hardware-wallet signing is not implemented.
- `--attest` for **private** repositories is untested.
- `oath init --set-github` was checked with a real GitHub CLI (secret and variable set in a throwaway private repo). `--attest` for private repositories is untested: build attestations for private repos need a GitHub plan that supports them, and Sigstore's private instance has a different trust root.
- The kubelet needs its own `imagePullSecrets` for private images; oath only needs `OATH_REGISTRY_AUTH` to read their digests.
- Only the author has run this so far. You are the first outside tester.

## What to tell us
Where you got stuck, the exact command and output, your OS and Node version (`node -v`), and whether the README or this file was misleading.
