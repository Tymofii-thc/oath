# Deploying oath_records

**Who holds the upgrade authority is the security of this program.** Whoever has it can replace the program with one that creates records
for *any* signer (including your approver, which defeats `--quorum 2`) or closes accounts it owns (including revocations). So:

- the authority must be a key that **you** hold: not the CI key, never a GitHub secret, never pasted into a chat;
- keep it on your machine only, ideally offline or on a hardware wallet, and use it only for the commands below;
- on mainnet, do not run an upgradeable program with a single key. Get an independent audit first, then either freeze the program
  (`solana program set-upgrade-authority <program> --final`, irreversible) or move the authority to a multisig (for example Squads) with a delay.

**Why a new deployment.** The devnet instance `6n6fJ6WQgSQFie6BQHfGxFgw9groqusUgwC48Y7hgpJq` has an upgrade authority (`66RLA5s2R3XHGG7KPzcEWqitDZ3bbBDcb2XPhDgNw7uj`)
that the maintainer does not have, so it cannot be fixed or handed over. The fixed program has to go to a **new program ID**.

The commands are for devnet and written for the fish shell. Check each flag with `solana program --help`: the CLI changes between releases.

## One time: the CLI and two keys

```fish
curl -sSfL https://release.anza.xyz/stable/install | sh              # about 85 MB to download; lands in ~/.local/share/solana
fish_add_path ~/.local/share/solana/install/active_release/bin
solana --version

solana-keygen new -o ~/oath-program-authority.json                    # the AUTHORITY: write the seed phrase on paper; never commit or paste this file
solana-keygen new -o ~/oath-records-program.json                      # the program's own address: its public key becomes the new program ID
solana config set --url devnet --keypair ~/oath-program-authority.json
solana airdrop 2                                                      # or https://faucet.solana.com (devnet); the deploy needs a few tenths of a SOL
```

## Deploy a build

1. Download the artifact `oath_records-<commit>` of the `ci` workflow run for the commit you want (with `gh`:
   `gh run download <run id> -D ~/oath-deploy -p 'oath_records-*'`).
2. Compare the checksum: `sha256sum -c oath_records.so.sha256` in the folder with both files.
3. Deploy (first time, so the program keypair is given):
   `solana program deploy oath_records.so --program-id ~/oath-records-program.json --upgrade-authority ~/oath-program-authority.json`
4. Check: `solana program show (solana address -k ~/oath-records-program.json)`: "Authority" must be the address of `~/oath-program-authority.json`.
5. Tell the repository its new ID (it replaces the old one in the docs, `test/live-devnet-pda.mjs` and `test/e2e-kind.sh`) and run `node test/live-devnet-pda.mjs`.

Later upgrades: the same `solana program deploy` with `--program-id <the address>` and the authority key.

The artifact is what CI built from the commit, but a plain `cargo build-sbf` is not guaranteed to be byte-for-byte reproducible. For mainnet
use a verifiable build (`solana-verify`, Docker) so that anyone can check that the deployed bytes come from this source.
