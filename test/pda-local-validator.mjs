// Integration test of program/oath_records against a REAL Solana runtime: a local solana-test-validator
// running the actual compiled program (not a mock RPC). Not part of `npm test` (needs the validator up
// and the program deployed), same reasoning as test/live-devnet.mjs for the Memo path.
//
// Run:
//   cd program/oath_records && cargo build-sbf
//   solana-test-validator --reset --quiet --bpf-program <PROGRAM_ID> target/deploy/oath_records.so &
//   PROGRAM_ID=<PROGRAM_ID> node test/pda-local-validator.mjs
import { Connection, Keypair, LAMPORTS_PER_SOL } from "@solana/web3.js";
import { sendRecord, sendRevoke, checkPda } from "../lib/pda.mjs";

const PROGRAM_ID = process.env.PROGRAM_ID;
if (!PROGRAM_ID) { console.error("set PROGRAM_ID to the deployed program's address"); process.exit(2); }
const rpcUrl = process.env.RPC_URL || "http://127.0.0.1:8899";
const connection = new Connection(rpcUrl, "confirmed");

const D1 = "sha256:" + "a".repeat(64);
const D2 = "sha256:" + "b".repeat(64);
let fails = 0;
const check = (name, ok) => { console.log(`${ok ? "PASS" : "FAIL"}  ${name}`); if (!ok) fails++; };

async function fundedKeypair(sol = 2) {
  const kp = Keypair.generate();
  const sig = await connection.requestAirdrop(kp.publicKey, sol * LAMPORTS_PER_SOL);
  await connection.confirmTransaction(sig, "confirmed");
  return kp;
}

const ci = await fundedKeypair();
const approver = await fundedKeypair();

// 1. A fresh digest has no record: missing.
let r = await checkPda({ connection, programId: PROGRAM_ID, signers: [ci.publicKey.toBase58()], digest: D1 });
check("unrecorded digest is missing", r.status === "missing");

// 2. Anchor it; now it verifies.
const rec = await sendRecord({ connection, programId: PROGRAM_ID, payer: ci, digest: D1, image: "ghcr.io/me/app", commit: "0123456789ab" });
check("record transaction landed", !!rec.signature);
r = await checkPda({ connection, programId: PROGRAM_ID, signers: [ci.publicKey.toBase58()], digest: D1, image: "ghcr.io/me/app" });
check("anchored digest verifies", r.status === "verified" && r.rec.commit === "0123456789ab");

// 3. Bound to the image name: the same digest under a different image does not verify.
r = await checkPda({ connection, programId: PROGRAM_ID, signers: [ci.publicKey.toBase58()], digest: D1, image: "ghcr.io/me/other" });
check("image binding rejects a different image name", r.status === "missing");

// 4. Re-anchoring the same (signer, digest) is idempotent, not an error.
const rec2 = await sendRecord({ connection, programId: PROGRAM_ID, payer: ci, digest: D1, image: "ghcr.io/me/app", commit: "0123456789ab" });
check("re-anchoring the same record is idempotent (no error)", !!rec2.signature);

// 5. Quorum: one signer is not enough for quorum 2.
r = await checkPda({ connection, programId: PROGRAM_ID, signers: [ci.publicKey.toBase58(), approver.publicKey.toBase58()], digest: D1, image: "ghcr.io/me/app", quorum: 2 });
check("quorum 2 not met with only the CI record", r.status === "missing");
await sendRecord({ connection, programId: PROGRAM_ID, payer: approver, digest: D1, image: "ghcr.io/me/app", commit: "0123456789ab" });
r = await checkPda({ connection, programId: PROGRAM_ID, signers: [ci.publicKey.toBase58(), approver.publicKey.toBase58()], digest: D1, image: "ghcr.io/me/app", quorum: 2 });
check("quorum 2 met once both signers recorded it", r.status === "verified" && r.rec.signers.length === 2);

// 6. Revocation: final, and NOT evictable by spam (the whole point — this is a direct address lookup,
// not a scan, so there is no window to spam out of).
await sendRevoke({ connection, programId: PROGRAM_ID, payer: ci, digest: D1, reason: "stolen build" });
r = await checkPda({ connection, programId: PROGRAM_ID, signers: [ci.publicKey.toBase58()], digest: D1 });
check("revoked digest reports revoked", r.status === "revoked" && r.reason === "stolen build");
// simulate "spam": re-anchor the same digest again after the revocation, the way an attacker spamming
// transactions would try to bury the revocation in the Memo model. A direct account lookup is unaffected.
await sendRecord({ connection, programId: PROGRAM_ID, payer: ci, digest: D1, image: "ghcr.io/me/app", commit: "ffffffffffff" });
r = await checkPda({ connection, programId: PROGRAM_ID, signers: [ci.publicKey.toBase58()], digest: D1 });
check("re-anchoring after revocation does not un-revoke it", r.status === "revoked");

// 7. Revoking a different digest is independent: D2 gets its own reason, D1 is untouched by it.
await sendRevoke({ connection, programId: PROGRAM_ID, payer: ci, digest: D2, reason: "unrelated" });
r = await checkPda({ connection, programId: PROGRAM_ID, signers: [ci.publicKey.toBase58()], digest: D2 });
check("D2 is revoked with its own reason", r.status === "revoked" && r.reason === "unrelated");
r = await checkPda({ connection, programId: PROGRAM_ID, signers: [ci.publicKey.toBase58()], digest: D1 });
check("revoking D2 did not change D1's reason", r.status === "revoked" && r.reason === "stolen build");

console.log(fails ? `${fails} FAILED` : "ALL PASSED");
process.exit(fails ? 1 : 0);
