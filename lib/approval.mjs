// Offline approvals: a human (or any key holder) signs a short plain-text statement about an image digest with an ed25519 key
// (a Solana wallet key works: wallets sign arbitrary messages). Verifying needs only the public key: no RPC, no chain, no network.
//
//   oath approval v1
//   image: ghcr.io/me/app
//   digest: sha256:<64 hex>
//   commit: 0123456789ab
//   approved: 2026-10-22T10:00:00.000Z
//   expires: 2026-11-21T10:00:00.000Z
//
// The text is what a wallet shows before it signs, so the signer sees what they approve (no blind signing). Approvals expire (at most
// 366 days), which bounds how long a forgotten approval stays valid. A revocation is a second statement type; any trusted signer's
// revocation of a digest is final.
//
//   oath revocation v1
//   digest: sha256:<64 hex>
//   reason: <one line>
//   issued: 2026-10-22T10:00:00.000Z
//
// A signed statement travels as JSON: { "v": 1, "message": "<the text>", "signer": "<base58 public key>", "signature": "<base58>" }.
import { createPublicKey, createPrivateKey, sign as edSign, verify as edVerify } from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { repoName } from "./oath.mjs";

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const DAY = 86400000;
const MAX_DAYS = 366;
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;

export function b58encode(buf) {
  let n = BigInt("0x" + (Buffer.from(buf).toString("hex") || "0"));
  let out = "";
  while (n > 0n) { out = ALPHABET[Number(n % 58n)] + out; n /= 58n; }
  for (const b of buf) { if (b === 0) out = "1" + out; else break; }
  return out;
}

export function b58decode(str) {
  let n = 0n;
  for (const ch of String(str)) {
    const i = ALPHABET.indexOf(ch);
    if (i < 0) throw new Error("not base58");
    n = n * 58n + BigInt(i);
  }
  let hex = n.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  const body = n === 0n ? Buffer.alloc(0) : Buffer.from(hex, "hex");
  let zeros = 0;
  for (const ch of String(str)) { if (ch === "1") zeros++; else break; }
  return Buffer.concat([Buffer.alloc(zeros), body]);
}

const publicKeyOf = (b58) => {
  const raw = b58decode(b58);
  if (raw.length !== 32) throw new Error("a public key is 32 bytes");
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: "der", type: "spki" });
};

// ---- statements ----

export function approvalMessage({ image, digest, commit, approved = new Date(), days = 30 }) {
  if (!DIGEST_RE.test(String(digest))) throw new Error("bad digest (expected sha256:<64 hex>)");
  const name = repoName(image);
  if (!name) throw new Error("an image name is required");
  const c = String(commit || "").trim().toLowerCase();
  if (!/^[0-9a-f]{7,40}$/.test(c)) throw new Error("bad commit (7 to 40 hex characters)");
  if (!(days > 0 && days <= MAX_DAYS)) throw new Error(`days must be between 1 and ${MAX_DAYS}`);
  const expires = new Date(approved.getTime() + days * DAY);
  return ["oath approval v1", `image: ${name}`, `digest: ${digest}`, `commit: ${c.slice(0, 12)}`, `approved: ${approved.toISOString()}`, `expires: ${expires.toISOString()}`].join("\n");
}

export function revocationMessage({ digest, reason = "", issued = new Date() }) {
  if (!DIGEST_RE.test(String(digest))) throw new Error("bad digest (expected sha256:<64 hex>)");
  return ["oath revocation v1", `digest: ${digest}`, `reason: ${String(reason).replace(/[\r\n]+/g, " ").trim().slice(0, 100)}`, `issued: ${issued.toISOString()}`].join("\n");
}

// strict: exactly these lines in this order, so a wallet shows the same thing the verifier reads
export function parseMessage(text) {
  const lines = String(text).split("\n");
  const field = (line, key) => {
    if (!line || !line.startsWith(key + ": ")) throw new Error(`expected "${key}: …"`);
    return line.slice(key.length + 2);
  };
  if (lines[0] === "oath approval v1") {
    if (lines.length !== 6) throw new Error("an approval has exactly 6 lines");
    const m = { type: "approval", image: field(lines[1], "image"), digest: field(lines[2], "digest"), commit: field(lines[3], "commit"), approved: field(lines[4], "approved"), expires: field(lines[5], "expires") };
    if (!DIGEST_RE.test(m.digest)) throw new Error("bad digest in the statement");
    if (Number.isNaN(Date.parse(m.approved)) || Number.isNaN(Date.parse(m.expires))) throw new Error("bad date in the statement");
    if (Date.parse(m.expires) - Date.parse(m.approved) > MAX_DAYS * DAY) throw new Error(`an approval lasts at most ${MAX_DAYS} days`);
    return m;
  }
  if (lines[0] === "oath revocation v1") {
    if (lines.length !== 4) throw new Error("a revocation has exactly 4 lines");
    const m = { type: "revocation", digest: field(lines[1], "digest"), reason: field(lines[2], "reason"), issued: field(lines[3], "issued") };
    if (!DIGEST_RE.test(m.digest)) throw new Error("bad digest in the statement");
    return m;
  }
  throw new Error("not an oath statement");
}

// ---- signing and verifying ----

// secretKey: the Solana keypair file contents (64 numbers: 32 secret + 32 public) or a 32-byte seed
export function signMessage(message, secretKey) {
  const bytes = Buffer.from(secretKey);
  if (bytes.length !== 64 && bytes.length !== 32) throw new Error("a secret key is 64 bytes (a Solana keypair file) or a 32-byte seed");
  const key = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, bytes.subarray(0, 32)]), format: "der", type: "pkcs8" });
  const signer = bytes.length === 64 ? b58encode(bytes.subarray(32)) : null;
  const signature = b58encode(edSign(null, Buffer.from(message, "utf8"), key));
  return { v: 1, message, signer, signature };
}

export function verifyStatement(stmt) {
  try {
    if (!stmt || stmt.v !== 1 || typeof stmt.message !== "string" || typeof stmt.signer !== "string" || typeof stmt.signature !== "string") return false;
    const sig = b58decode(stmt.signature);
    if (sig.length !== 64) return false;
    return edVerify(null, Buffer.from(stmt.message, "utf8"), publicKeyOf(stmt.signer), sig);
  } catch { return false; }
}

// Reads one JSON file, or every *.json in a directory (non-recursive). Unreadable files are skipped, never trusted.
export function loadStatements(path) {
  const files = statSync(path).isDirectory() ? readdirSync(path).filter((f) => f.endsWith(".json")).map((f) => join(path, f)) : [path];
  const out = [];
  for (const f of files) {
    try {
      const j = JSON.parse(readFileSync(f, "utf8"));
      for (const s of Array.isArray(j) ? j : [j]) out.push(s);
    } catch { /* skip */ }
  }
  return out;
}

// -> { status: "verified", rec: { signers, commit, approvedAt, expiresAt, image } } | { status: "revoked", signer, reason } | { status: "missing", why }
// signers: trusted public keys (base58). A statement counts only if its signature is valid AND its signer is trusted.
export function checkApprovals({ statements, signers, digest, image, quorum = 1, now = new Date() }) {
  const trusted = new Set(signers);
  const want = image ? repoName(image) : null;
  const approvedBy = new Map();
  let expired = 0, otherImage = 0;
  for (const stmt of statements) {
    if (!trusted.has(stmt?.signer) || !verifyStatement(stmt)) continue;
    let m;
    try { m = parseMessage(stmt.message); } catch { continue; }
    if (m.digest !== digest) continue;
    if (m.type === "revocation") return { status: "revoked", signer: stmt.signer, reason: m.reason }; // final, from any trusted signer
    if (Date.parse(m.expires) <= now.getTime()) { expired++; continue; }
    if (Date.parse(m.approved) > now.getTime() + 5 * 60000) continue; // not valid yet (clock skew allowed: 5 minutes)
    if (want && repoName(m.image) !== want) { otherImage++; continue; }
    if (!approvedBy.has(stmt.signer)) approvedBy.set(stmt.signer, m);
  }
  if (approvedBy.size >= Math.max(1, quorum)) {
    const list = [...approvedBy.entries()];
    const newest = list.map(([, m]) => m).sort((a, b) => Date.parse(b.approved) - Date.parse(a.approved))[0];
    return { status: "verified", rec: { signers: list.map(([s]) => s), commit: newest.commit, image: newest.image, approvedAt: newest.approved, expiresAt: list.map(([, m]) => m.expires).sort()[0] } };
  }
  const why = approvedBy.size ? `only ${approvedBy.size} of the required ${quorum} trusted signers approved it` : expired ? "the approval has expired" : otherImage ? "it was approved for a different image name" : "no valid approval from a trusted signer";
  return { status: "missing", why };
}
