import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { b58encode, b58decode, approvalMessage, revocationMessage, parseMessage, signMessage, verifyStatement, checkApprovals } from "../lib/approval.mjs";

const D = "sha256:" + "a".repeat(64);
const D2 = "sha256:" + "b".repeat(64);
const NOW = new Date("2026-10-22T12:00:00.000Z");

// a keypair in the shape of a Solana keypair file: 32-byte seed + 32-byte public key
function keypair() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);
  const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  return { secret: Buffer.concat([seed, pub]), pub: b58encode(pub) };
}
const approve = (kp, o = {}) => signMessage(approvalMessage({ image: "ghcr.io/me/app", digest: D, commit: "0123456789ab", approved: NOW, days: 30, ...o }), kp.secret);

test("base58 round-trips, including leading zero bytes", () => {
  for (const hex of ["", "00", "0000ff", "ff", "00010203", randomBytes(32).toString("hex")]) {
    assert.equal(b58decode(b58encode(Buffer.from(hex, "hex"))).toString("hex"), hex);
  }
  assert.equal(b58encode(Buffer.from("00", "hex")), "1");
});

test("a signed approval verifies offline, and any change to the text or the signer breaks it", () => {
  const kp = keypair();
  const s = approve(kp);
  assert.equal(s.signer, kp.pub);
  assert.equal(verifyStatement(s), true);
  assert.equal(verifyStatement({ ...s, message: s.message.replace(D, D2) }), false, "another digest");
  assert.equal(verifyStatement({ ...s, signer: keypair().pub }), false, "another signer");
  assert.equal(verifyStatement({ ...s, signature: b58encode(randomBytes(64)) }), false, "a random signature");
  assert.equal(verifyStatement({ v: 2, message: s.message, signer: s.signer, signature: s.signature }), false);
});

test("the key encoding matches a real Solana keypair (the public key is the same base58 string)", async (t) => {
  let web3; try { web3 = await import("@solana/web3.js"); } catch { return t.skip("@solana/web3.js is not installed"); }
  const kp = web3.Keypair.generate();
  const s = signMessage(approvalMessage({ image: "ghcr.io/me/app", digest: D, commit: "0123456789ab", approved: NOW }), Buffer.from(kp.secretKey));
  assert.equal(s.signer, kp.publicKey.toBase58());
  assert.equal(verifyStatement(s), true);
});

test("statements are parsed strictly", () => {
  const m = approvalMessage({ image: "GHCR.io/Me/App:latest", digest: D, commit: "0123456789ABCDEF", approved: NOW, days: 10 });
  const p = parseMessage(m);
  assert.equal(p.image, "ghcr.io/me/app", "the image name is normalised, a tag is dropped");
  assert.equal(p.commit, "0123456789ab");
  assert.throws(() => parseMessage(m + "\nextra: line"), /exactly 6 lines/);
  assert.throws(() => parseMessage(m.replace("digest:", "dig:")), /digest/);
  assert.throws(() => parseMessage("hello"), /not an oath statement/);
  assert.throws(() => approvalMessage({ image: "a/b", digest: D, commit: "0123456789ab", days: 400 }), /days must be/);
  const long = m.replace(/expires: .*/, "expires: 2030-01-01T00:00:00.000Z");
  assert.throws(() => parseMessage(long), /at most 366 days/);
});

test("checkApprovals: a trusted, valid, unexpired approval for this digest and image verifies", () => {
  const kp = keypair();
  const r = checkApprovals({ statements: [approve(kp)], signers: [kp.pub], digest: D, image: "ghcr.io/me/app:1", now: NOW });
  assert.equal(r.status, "verified");
  assert.deepEqual(r.rec.signers, [kp.pub]);
  assert.equal(r.rec.commit, "0123456789ab");
});

test("checkApprovals: an untrusted signer, another digest, another image or an expired approval does not count", () => {
  const kp = keypair(), other = keypair();
  const base = { signers: [kp.pub], digest: D, image: "ghcr.io/me/app", now: NOW };
  assert.equal(checkApprovals({ ...base, statements: [approve(other)] }).status, "missing", "valid signature, but not a trusted key");
  assert.equal(checkApprovals({ ...base, statements: [approve(kp, { digest: D2 })] }).status, "missing", "approved another digest");
  const wrongImage = checkApprovals({ ...base, statements: [approve(kp, { image: "ghcr.io/me/other" })] });
  assert.equal(wrongImage.status, "missing"); assert.match(wrongImage.why, /different image/);
  assert.equal(checkApprovals({ ...base, image: undefined, statements: [approve(kp, { image: "ghcr.io/me/other" })] }).status, "verified", "no image binding when no image is given");
  const expired = checkApprovals({ ...base, statements: [approve(kp, { approved: new Date("2026-01-01T00:00:00Z"), days: 30 })] });
  assert.equal(expired.status, "missing"); assert.match(expired.why, /expired/);
  assert.equal(checkApprovals({ ...base, statements: [approve(kp, { approved: new Date(NOW.getTime() + 86400000) })] }).status, "missing", "approved in the future");
});

test("checkApprovals: a quorum needs that many DIFFERENT trusted signers", () => {
  const a = keypair(), b = keypair();
  const base = { signers: [a.pub, b.pub], digest: D, image: "ghcr.io/me/app", now: NOW, quorum: 2 };
  assert.equal(checkApprovals({ ...base, statements: [approve(a), approve(a)] }).status, "missing", "one signer twice is still one");
  const one = checkApprovals({ ...base, statements: [approve(a)] });
  assert.match(one.why, /only 1 of the required 2/);
  assert.equal(checkApprovals({ ...base, statements: [approve(a), approve(b)] }).status, "verified");
});

test("checkApprovals: a revocation by a trusted signer is final; by an untrusted one it is ignored", () => {
  const kp = keypair(), other = keypair();
  const rev = (k) => signMessage(revocationMessage({ digest: D, reason: "bad build", issued: NOW }), k.secret);
  const base = { signers: [kp.pub], digest: D, image: "ghcr.io/me/app", now: NOW };
  const revoked = checkApprovals({ ...base, statements: [rev(kp), approve(kp)] });
  assert.equal(revoked.status, "revoked"); assert.equal(revoked.reason, "bad build");
  assert.equal(checkApprovals({ ...base, statements: [approve(kp), rev(kp)] }).status, "revoked", "order does not matter");
  assert.equal(checkApprovals({ ...base, statements: [approve(kp), rev(other)] }).status, "verified", "an outsider cannot revoke");
});

test("garbage in the statement list never verifies and never throws", () => {
  const kp = keypair();
  const r = checkApprovals({ statements: [null, 5, {}, { v: 1 }, { v: 1, message: "x", signer: kp.pub, signature: "!!" }], signers: [kp.pub], digest: D, now: NOW });
  assert.equal(r.status, "missing");
});
