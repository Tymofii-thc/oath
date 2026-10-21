// Unit tests of the PDA client logic (lib/pda.mjs) against a stubbed `connection` (no live validator
// needed for `npm test`; test/pda-local-validator.mjs is the real-runtime integration test, separate
// for the same reason test/live-devnet.mjs is separate from the Memo path's unit tests).
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkPda, deriveRecordAddress, deriveRevokeAddress, _internal } from "../lib/pda.mjs";

const { Keypair, SystemProgram } = await import("@solana/web3.js");
const PROGRAM_ID = SystemProgram.programId.toBase58(); // any valid base58 pubkey works for derivation; no live chain involved
const D1 = "sha256:" + "a".repeat(64);
const SIGNER_A = Keypair.generate().publicKey.toBase58();
const SIGNER_B = Keypair.generate().publicKey.toBase58();

test("commitBytes round-trips a commit that ends in the digit 0 (regression: '0'-padding used to strip it)", () => {
  const encoded = _internal.commitBytes("abc1230000");
  const decoded = Buffer.concat([Buffer.alloc(98), encoded, Buffer.alloc(8)]);
  decoded[0] = 1; // RECORD tag, so decodeRecord accepts it
  assert.equal(_internal.decodeRecord(decoded).commit, "abc1230000");
});

test("commitBytes pads short commits with null bytes, not the printable digit 0", () => {
  const encoded = _internal.commitBytes("ab12");
  assert.equal(encoded.length, 12);
  assert.equal(encoded.subarray(4).every((b) => b === 0), true);
});

// A stub `connection` serving whatever records/revokes the test puts in, keyed by base58 address.
function stubConnection(byAddress) {
  return { getAccountInfo: async (pubkey) => byAddress[pubkey.toBase58()] || null };
}

async function recordAccount({ signer, digest, image, commit, ts = 1 }) {
  const data = Buffer.alloc(_internal.RECORD_LEN);
  data[0] = 1;
  const { PublicKey } = await import("@solana/web3.js");
  new PublicKey(signer).toBuffer().copy(data, 2);
  _internal.digestBytes(digest).copy(data, 34);
  _internal.imageHash(image).copy(data, 66);
  _internal.commitBytes(commit).copy(data, 98);
  data.writeBigInt64LE(BigInt(ts), 110);
  return { data };
}

async function revokeAccount({ signer, digest, reason, ts = 1 }) {
  const data = Buffer.alloc(_internal.REVOKE_LEN);
  data[0] = 2;
  const { PublicKey } = await import("@solana/web3.js");
  new PublicKey(signer).toBuffer().copy(data, 2);
  _internal.digestBytes(digest).copy(data, 34);
  Buffer.from(reason, "utf8").copy(data, 66);
  data.writeBigInt64LE(BigInt(ts), 130);
  return { data };
}

test("missing when neither a record nor a revoke account exists", async () => {
  const r = await checkPda({ connection: stubConnection({}), programId: PROGRAM_ID, signers: [SIGNER_A], digest: D1 });
  assert.equal(r.status, "missing");
});

test("verified when the record account exists and the image matches", async () => {
  const recAddr = (await deriveRecordAddress({ programId: PROGRAM_ID, signer: SIGNER_A, digest: D1 })).toBase58();
  const conn = stubConnection({ [recAddr]: await recordAccount({ signer: SIGNER_A, digest: D1, image: "ghcr.io/me/app", commit: "0123456789ab" }) });
  const r = await checkPda({ connection: conn, programId: PROGRAM_ID, signers: [SIGNER_A], digest: D1, image: "ghcr.io/me/app" });
  assert.equal(r.status, "verified");
  assert.equal(r.rec.commit, "0123456789ab");
});

test("image binding: the same digest recorded for a different image does not verify", async () => {
  const recAddr = (await deriveRecordAddress({ programId: PROGRAM_ID, signer: SIGNER_A, digest: D1 })).toBase58();
  const conn = stubConnection({ [recAddr]: await recordAccount({ signer: SIGNER_A, digest: D1, image: "ghcr.io/me/other", commit: "0123456789ab" }) });
  const r = await checkPda({ connection: conn, programId: PROGRAM_ID, signers: [SIGNER_A], digest: D1, image: "ghcr.io/me/app" });
  assert.equal(r.status, "missing");
});

test("revoked wins even when a record account for the same digest also exists", async () => {
  const recAddr = (await deriveRecordAddress({ programId: PROGRAM_ID, signer: SIGNER_A, digest: D1 })).toBase58();
  const revAddr = (await deriveRevokeAddress({ programId: PROGRAM_ID, signer: SIGNER_A, digest: D1 })).toBase58();
  const conn = stubConnection({
    [recAddr]: await recordAccount({ signer: SIGNER_A, digest: D1, image: "ghcr.io/me/app", commit: "0123456789ab" }),
    [revAddr]: await revokeAccount({ signer: SIGNER_A, digest: D1, reason: "stolen build" }),
  });
  const r = await checkPda({ connection: conn, programId: PROGRAM_ID, signers: [SIGNER_A], digest: D1 });
  assert.equal(r.status, "revoked");
  assert.equal(r.reason, "stolen build");
});

test("quorum: needs N distinct signers, each with their own record account", async () => {
  const addrA = (await deriveRecordAddress({ programId: PROGRAM_ID, signer: SIGNER_A, digest: D1 })).toBase58();
  const addrB = (await deriveRecordAddress({ programId: PROGRAM_ID, signer: SIGNER_B, digest: D1 })).toBase58();
  const oneSigner = stubConnection({ [addrA]: await recordAccount({ signer: SIGNER_A, digest: D1, image: "a/b", commit: "0123456789ab" }) });
  let r = await checkPda({ connection: oneSigner, programId: PROGRAM_ID, signers: [SIGNER_A, SIGNER_B], digest: D1, quorum: 2 });
  assert.equal(r.status, "missing", "only one of two signers has recorded it");

  const bothSigners = stubConnection({
    [addrA]: await recordAccount({ signer: SIGNER_A, digest: D1, image: "a/b", commit: "0123456789ab" }),
    [addrB]: await recordAccount({ signer: SIGNER_B, digest: D1, image: "a/b", commit: "0123456789ab" }),
  });
  r = await checkPda({ connection: bothSigners, programId: PROGRAM_ID, signers: [SIGNER_A, SIGNER_B], digest: D1, quorum: 2 });
  assert.equal(r.status, "verified");
  assert.equal(r.rec.signers.length, 2);
});

test("quorum above the number of listed signers can never pass", async () => {
  const r = await checkPda({ connection: stubConnection({}), programId: PROGRAM_ID, signers: [SIGNER_A], digest: D1, quorum: 2 });
  assert.equal(r.status, "missing");
});

