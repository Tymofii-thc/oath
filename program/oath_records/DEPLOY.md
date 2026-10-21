# Deploying or upgrading oath_records

**Who holds the upgrade authority is the security of this program.** Whoever has it can replace the program with one that creates records
for *any* signer (including your approver, which defeats `--quorum 2`) or closes accounts it owns (including revocations). So:

- it must **not** be the CI key, and must never be a GitHub secret or pass through a chat;
- use a separate key that lives on your machine only, ideally offline or on a hardware wallet, and is used only for the commands below;
- on mainnet, do not run an upgradeable program with a single key. Get an independent audit first, then either freeze the program
  (`solana program set-upgrade-authority <program> --final`, irreversible) or move the authority to a multisig (for example Squads) with a delay.

The commands below are for devnet. Check each flag with `solana program --help`: the CLI changes between releases.

## One time: the key and the CLI

```bash
sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"     # about 85 MB to download; lands in ~/.local/share/solana
solana-keygen new -o ~/oath-program-authority.json                  # write the seed phrase on paper; never commit or paste this file
solana config set --url devnet --keypair ~/oath-program-authority.json
solana airdrop 2                                                    # or https://faucet.solana.com (devnet)
```

## Move the authority away from the CI key (once)

```bash
solana program show 6n6fJ6WQgSQFie6BQHfGxFgw9groqusUgwC48Y7hgpJq    # "Authority" is now the CI key 5D4W8x8U...
solana program set-upgrade-authority 6n6fJ6WQgSQFie6BQHfGxFgw9groqusUgwC48Y7hgpJq \
  --upgrade-authority <path to the CI key file> \
  --new-upgrade-authority ~/oath-program-authority.json              # the new key signs too, so a typo cannot lock the program
solana program show 6n6fJ6WQgSQFie6BQHfGxFgw9groqusUgwC48Y7hgpJq    # "Authority" must now be your new address
```

From here the CI key can no longer change the program. (Its other jobs, signing records, are unaffected.)

## Deploy a build

1. Download the artifact `oath_records-<commit>` of the `ci` workflow run for the commit you want (Actions, the run, Artifacts).
2. Compare the checksum: `sha256sum -c oath_records.so.sha256` in the folder with both files.
3. Deploy: `solana program deploy oath_records.so --program-id 6n6fJ6WQgSQFie6BQHfGxFgw9groqusUgwC48Y7hgpJq --upgrade-authority ~/oath-program-authority.json`
4. Check it works on devnet: `node test/live-devnet-pda.mjs` from a checkout of the same commit.

The artifact is what CI built from the commit, but a plain `cargo build-sbf` is not guaranteed to be byte-for-byte reproducible. For mainnet
use a verifiable build (`solana-verify`, Docker) so that anyone can check that the deployed bytes come from this source.
