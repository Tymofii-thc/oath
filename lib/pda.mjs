// Client for the oath_records program (program/oath_records): one account per (signer, digest), looked
// up directly by address instead of scanned out of transaction history. This is what closes the
// revocation-eviction-by-spam gap in THREAT-MODEL.md ("Spam a signer's address..."): a revoke account
// has no window to be pushed out of, it just exists or does not. Additive to the Memo-based path in
// lib/oath.mjs; nothing here changes the default `oath verify`/`oath anchor` behavior unless --program
// is given.
import { createHash } from "node:crypto";
import { repoName } from "./oath.mjs";

export const RECORD_SEED = Buffer.from("oath1rec");
export const REVOKE_SEED = Buffer.from("oath1rev");
const RECORD_LEN = 1 + 1 + 32 + 32 + 32 + 12 + 8;
const REVOKE_LEN = 1 + 1 + 32 + 32 + 64 + 8;

function digestBytes(digest) {
  const hex = String(digest).replace(/^sha256:/, "");
  if (!/^[0-9a-f]{64}$/i.test(hex)) throw new Error(`bad digest: ${digest}`);
  return Buffer.from(hex, "hex");
}

function imageHash(image) {
  return createHash("sha256").update(repoName(image) || "").digest();
}

function commitBytes(commit) {
  const buf = Buffer.alloc(12); // zero (null-byte) padded, not "0"-padded: a real commit can end in the digit 0
  Buffer.from(String(commit || "").toLowerCase().slice(0, 12), "ascii").copy(buf);
  return buf;
}

async function findSeededAddress(web3, seed, programId, signer, digest) {
  const [pda, bump] = web3.PublicKey.findProgramAddressSync([seed, new web3.PublicKey(signer).toBuffer(), digestBytes(digest)], new web3.PublicKey(programId));
  return { pda, bump };
}

export async function deriveRecordAddress({ programId, signer, digest }) {
  const web3 = await import("@solana/web3.js");
  return (await findSeededAddress(web3, RECORD_SEED, programId, signer, digest)).pda;
}

export async function deriveRevokeAddress({ programId, signer, digest }) {
  const web3 = await import("@solana/web3.js");
  return (await findSeededAddress(web3, REVOKE_SEED, programId, signer, digest)).pda;
}

function decodeRecord(data) {
  if (data.length !== RECORD_LEN || data[0] !== 1) return null;
  return {
    signer: data.subarray(2, 34),
    digest: data.subarray(34, 66),
    imageHash: data.subarray(66, 98),
    commit: data.subarray(98, 110).toString("ascii").replace(/\0+$/, ""),
    ts: Number(data.readBigInt64LE(110)),
  };
}

function decodeRevoke(data) {
  if (data.length !== REVOKE_LEN || data[0] !== 2) return null;
  return {
    signer: data.subarray(2, 34),
    digest: data.subarray(34, 66),
    reason: data.subarray(66, 130).toString("utf8").replace(/\0+$/, ""),
    ts: Number(data.readBigInt64LE(130)),
  };
}

// opts.image, opts.commit bind the on-chain record the same way lib/oath.mjs's checkRecord does for Memo
// records: a digest anchored for a different image name, or a revocation address mismatch, does not count.
// Returns { status: "verified", rec } | { status: "revoked", signer, reason } | { status: "missing" }, same
// shape as checkRecord() in lib/oath.mjs so callers can treat the two backends interchangeably.
// opts.rpcUrl is a plain URL (like checkRecord's), unless opts.connection is given directly (tests use this
// to pass a Connection pointed at a local validator or a stub, without needing a real network).
export async function checkPda({ rpcUrl, connection, programId, signers, digest, image, commit, quorum = 1 }) {
  const web3 = await import("@solana/web3.js");
  const conn = connection || new web3.Connection(rpcUrl, "confirmed");
  const need = Math.max(1, Number(quorum) || 1);
  const unique = [...new Set(signers)];
  if (need > unique.length) return { status: "missing" };
  const wantImage = image ? imageHash(image) : null;

  const hits = [];
  for (const signer of unique) {
    const { pda: revokePda } = await findSeededAddress(web3, REVOKE_SEED, programId, signer, digest);
    const revokeAcc = await conn.getAccountInfo(revokePda);
    if (revokeAcc?.data?.length) {
      const rv = decodeRevoke(revokeAcc.data);
      if (rv) return { status: "revoked", signer, reason: rv.reason };
    }
    const { pda: recordPda } = await findSeededAddress(web3, RECORD_SEED, programId, signer, digest);
    const recAcc = await conn.getAccountInfo(recordPda);
    if (recAcc?.data?.length) {
      const rec = decodeRecord(recAcc.data);
      if (!rec) continue;
      if (wantImage && Buffer.compare(Buffer.from(rec.imageHash), wantImage) !== 0) continue;
      if (commit && rec.commit && rec.commit !== String(commit).toLowerCase().slice(0, 12)) continue;
      hits.push({ signer, commit: rec.commit, ts: rec.ts });
    }
  }
  if (hits.length < need) return { status: "missing" };
  hits.sort((a, b) => b.ts - a.ts);
  return { status: "verified", rec: { ...hits[0], signers: hits.map((h) => h.signer) } };
}

export async function sendRecord({ connection, programId, payer, digest, image, commit, ts = Math.floor(Date.now() / 1000) }) {
  const web3 = await import("@solana/web3.js");
  const prog = new web3.PublicKey(programId);
  const { pda } = await findSeededAddress(web3, RECORD_SEED, programId, payer.publicKey, digest);
  const data = Buffer.concat([Buffer.from([0]), digestBytes(digest), imageHash(image), commitBytes(commit), le64(ts)]);
  const ix = new web3.TransactionInstruction({
    programId: prog,
    keys: [
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: pda, isSigner: false, isWritable: true },
      { pubkey: web3.SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
  const sig = await web3.sendAndConfirmTransaction(connection, new web3.Transaction().add(ix), [payer], { commitment: "confirmed" });
  return { signature: sig, address: pda.toBase58() };
}

export async function sendRevoke({ connection, programId, payer, digest, reason = "", ts = Math.floor(Date.now() / 1000) }) {
  const web3 = await import("@solana/web3.js");
  const prog = new web3.PublicKey(programId);
  const { pda } = await findSeededAddress(web3, REVOKE_SEED, programId, payer.publicKey, digest);
  const reasonBuf = Buffer.alloc(64);
  Buffer.from(String(reason).slice(0, 64), "utf8").copy(reasonBuf);
  const data = Buffer.concat([Buffer.from([1]), digestBytes(digest), reasonBuf, le64(ts)]);
  const ix = new web3.TransactionInstruction({
    programId: prog,
    keys: [
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: pda, isSigner: false, isWritable: true },
      { pubkey: web3.SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
  const sig = await web3.sendAndConfirmTransaction(connection, new web3.Transaction().add(ix), [payer], { commitment: "confirmed" });
  return { signature: sig, address: pda.toBase58() };
}

function le64(n) {
  const b = Buffer.alloc(8);
  b.writeBigInt64LE(BigInt(n));
  return b;
}

// Backwards-compatible with findRecord() in lib/oath.mjs: the record, or null when missing OR revoked
// (same collapsing the admission webhook already relies on for the Memo backend).
export async function findPda(opts) {
  const r = await checkPda(opts);
  return r.status === "verified" ? r.rec : null;
}

export const _internal = { digestBytes, imageHash, commitBytes, decodeRecord, decodeRevoke, RECORD_LEN, REVOKE_LEN };
