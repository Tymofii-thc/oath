import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { findRecord, parseMemo, repoName, resolveRpc, rpcCall } from "../lib/oath.mjs";

const D1 = "sha256:" + "a".repeat(64);
const D2 = "sha256:" + "b".repeat(64);
const memo = (image, digest) => `[${100}] pod1|${image}|0123456789ab|${digest}|2026-01-01T00:00:00.000Z`;

// Mock Solana RPC: txs[signer] = newest-first list of { signature, memo, err, blockTime }
function mockRpc(txs) {
  const calls = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const { method, params, id } = JSON.parse(body);
      res.setHeader("content-type", "application/json");
      if (method === "getTransaction") {
        // the first signer whose list holds this signature; tx.forged = the address is only mentioned, not a signer
        const owner = Object.keys(txs).find((a) => txs[a].some((t) => t.signature === params[0]));
        const t = owner && txs[owner].find((x) => x.signature === params[0]);
        res.end(JSON.stringify({ jsonrpc: "2.0", id, result: t ? { meta: { err: null }, transaction: { message: { accountKeys: [{ pubkey: owner, signer: !t.forged }, { pubkey: "ATTACKER", signer: !!t.forged }] } } } : null }));
        return;
      }
      calls.push(params);
      const [addr, opts] = params;
      let list = txs[addr] || [];
      if (opts.before) list = list.slice(list.findIndex((t) => t.signature === opts.before) + 1);
      res.end(JSON.stringify({ jsonrpc: "2.0", id, result: list.slice(0, opts.limit) }));
    });
  });
  return new Promise((r) => server.listen(0, () => r({ url: `http://127.0.0.1:${server.address().port}`, calls, close: () => server.close() })));
}
const tx = (n, m, extra = {}) => ({ signature: `sig${n}`, memo: m, err: null, blockTime: Math.floor(Date.now() / 1000) - n, ...extra });

test("repoName normalizes refs", () => {
  assert.equal(repoName("ghcr.io/Me/App:latest"), "ghcr.io/me/app");
  assert.equal(repoName(`ghcr.io/me/app@${D1}`), "ghcr.io/me/app");
  assert.equal(repoName("alpine:3.20"), "docker.io/library/alpine");
  assert.equal(repoName("me/app"), "docker.io/me/app");
  assert.equal(repoName("localhost:5055/demo/app:latest"), "localhost:5055/demo/app");
});

test("parseMemo handles joined memos and ignores foreign ones", () => {
  const r = parseMemo(`[5] hello; ${memo("x/y", D1)}`);
  assert.equal(r.length, 1);
  assert.equal(r[0].digest, D1);
});

test("resolveRpc precedence and unknown network", () => {
  assert.equal(resolveRpc({ rpc: "http://x", env: {} }), "http://x");
  assert.equal(resolveRpc({ env: { SOLANA_RPC: "http://y" } }), "http://y");
  assert.match(resolveRpc({ network: "mainnet", env: {} }), /mainnet-beta/);
  assert.match(resolveRpc({ env: {} }), /devnet/);
  assert.throws(() => resolveRpc({ network: "nope", env: {} }));
});

test("match, mismatch, failed tx ignored", async () => {
  const m = await mockRpc({ S: [tx(1, memo("ghcr.io/me/app", D1), { err: { x: 1 } }), tx(2, memo("ghcr.io/me/app", D2))] });
  try {
    assert.equal(await findRecord({ signers: ["S"], digest: D1, rpcUrl: m.url }), null, "failed tx must not count");
    const hit = await findRecord({ signers: ["S"], digest: D2, rpcUrl: m.url });
    assert.equal(hit.signature, "sig2");
    assert.equal(await findRecord({ signers: ["other"], digest: D2, rpcUrl: m.url }), null, "other signer");
  } finally { m.close(); }
});

test("image binding: same digest anchored for a different image is rejected", async () => {
  const m = await mockRpc({ S: [tx(1, memo("ghcr.io/me/other", D1))] });
  try {
    assert.equal(await findRecord({ signers: ["S"], digest: D1, rpcUrl: m.url, image: "ghcr.io/me/app" }), null);
    assert.ok(await findRecord({ signers: ["S"], digest: D1, rpcUrl: m.url, image: "ghcr.io/me/other:latest" }));
    assert.ok(await findRecord({ signers: ["S"], digest: D1, rpcUrl: m.url }), "no binding when image is omitted");
  } finally { m.close(); }
});

test("key rotation: any of several signers is accepted", async () => {
  const m = await mockRpc({ OLD: [tx(1, memo("a/b", D1))], NEW: [] });
  try {
    assert.ok(await findRecord({ signers: ["NEW", "OLD"], digest: D1, rpcUrl: m.url }));
    assert.equal(await findRecord({ signers: ["NEW"], digest: D1, rpcUrl: m.url }), null, "revoked key no longer listed");
  } finally { m.close(); }
});

test("max age", async () => {
  const m = await mockRpc({ S: [tx(10 * 86400, memo("a/b", D1))] });
  try {
    assert.equal(await findRecord({ signers: ["S"], digest: D1, rpcUrl: m.url, maxAgeSeconds: 5 * 86400 }), null);
    assert.ok(await findRecord({ signers: ["S"], digest: D1, rpcUrl: m.url, maxAgeSeconds: 30 * 86400 }));
  } finally { m.close(); }
});

test("pagination: record older than one page is still found", async () => {
  const noise = Array.from({ length: 2500 }, (_, i) => tx(i + 1, memo("a/b", D2)));
  noise.push(tx(2600, memo("a/b", D1)));
  const m = await mockRpc({ S: noise });
  try {
    const hit = await findRecord({ signers: ["S"], digest: D1, rpcUrl: m.url, limit: 5000 });
    assert.equal(hit.signature, "sig2600");
    assert.ok(m.calls.length >= 3);
    assert.equal(await findRecord({ signers: ["S"], digest: D1, rpcUrl: m.url, limit: 1000 }), null, "limit respected");
  } finally { m.close(); }
});

test("RPC failure throws (caller must treat as deny, not as verified)", async () => {
  await assert.rejects(() => findRecord({ signers: ["S"], digest: D1, rpcUrl: "http://127.0.0.1:1" }));
});

test("quorum: needs N distinct signers; one signer repeating does not count twice", async () => {
  const m = await mockRpc({ A: [tx(1, memo("a/b", D1)), tx(2, memo("a/b", D1))], B: [tx(3, memo("a/b", D1))], C: [] });
  try {
    assert.equal(await findRecord({ signers: ["A", "C"], digest: D1, rpcUrl: m.url, quorum: 2 }), null, "A alone twice is still one signer");
    const ok = await findRecord({ signers: ["A", "B", "C"], digest: D1, rpcUrl: m.url, quorum: 2 });
    assert.deepEqual([...ok.signers].sort(), ["A", "B"]);
    assert.equal(await findRecord({ signers: ["A"], digest: D1, rpcUrl: m.url, quorum: 2 }), null, "quorum above signer count can never pass");
    assert.ok(await findRecord({ signers: ["A", "A"], digest: D1, rpcUrl: m.url, quorum: 1 }));
  } finally { m.close(); }
});

// ---- revocation and RPC failover
const rev = (digest, reason = "stolen build") => `[${60}] pod1r|${digest}|${reason}|2026-01-02T00:00:00.000Z`;
const { checkRecord, parseRevocation } = await import("../lib/oath.mjs");

test("parseRevocation reads revocation memos and ignores records", () => {
  assert.deepEqual(parseRevocation(rev(D1, "why")).map((r) => [r.digest, r.reason]), [[D1, "why"]]);
  assert.deepEqual(parseRevocation(memo("a/b", D1)), []);
});

test("revocation by the same signer wins, even if the digest was (re)anchored later", async () => {
  const m = await mockRpc({ S: [tx(1, memo("a/b", D1)), tx(2, rev(D1)), tx(3, memo("a/b", D1))] }); // newest first: re-anchored after the revocation
  try {
    const r = await checkRecord({ signers: ["S"], digest: D1, rpcUrl: m.url });
    assert.equal(r.status, "revoked");
    assert.equal(r.reason, "stolen build");
    assert.equal(await findRecord({ signers: ["S"], digest: D1, rpcUrl: m.url }), null, "findRecord must not return a revoked record");
  } finally { m.close(); }
});

test("revocation by another TRUSTED signer wins; by an untrusted one is ignored", async () => {
  const m = await mockRpc({ CI: [tx(3, memo("a/b", D1))], APPROVER: [tx(1, rev(D1, "bad"))], STRANGER: [tx(2, rev(D1, "troll"))] });
  try {
    assert.equal((await checkRecord({ signers: ["CI", "APPROVER"], digest: D1, rpcUrl: m.url })).status, "revoked");
    assert.equal((await checkRecord({ signers: ["CI"], digest: D1, rpcUrl: m.url })).status, "verified", "a stranger's revocation is not trusted");
  } finally { m.close(); }
});

test("revoking one digest does not affect another", async () => {
  const m = await mockRpc({ S: [tx(1, rev(D2)), tx(2, memo("a/b", D1))] });
  try { assert.equal((await checkRecord({ signers: ["S"], digest: D1, rpcUrl: m.url })).status, "verified"); } finally { m.close(); }
});

test("RPC failover: a dead first endpoint does not stop verification", async () => {
  const m = await mockRpc({ S: [tx(1, memo("a/b", D1))] });
  try {
    const r = await findRecord({ signers: ["S"], digest: D1, rpcUrl: `http://127.0.0.1:1, ${m.url}` });
    assert.ok(r);
    await assert.rejects(() => findRecord({ signers: ["S"], digest: D1, rpcUrl: "http://127.0.0.1:1,http://127.0.0.1:2" }), "all endpoints dead still throws (fail closed)");
  } finally { m.close(); }
});

test("a record in a tx the signer did not sign (address only mentioned) is ignored", async () => {
  const m = await mockRpc({ S: [tx(1, memo("a/b", D1), { forged: true })] });
  assert.equal(await findRecord({ signers: ["S"], digest: D1, rpcUrl: m.url }), null);
  m.close();
});

test("a forged revocation (signer did not sign it) does not revoke", async () => {
  const m = await mockRpc({ S: [tx(1, rev(D1, "troll"), { forged: true }), tx(2, memo("a/b", D1))] });
  assert.ok(await findRecord({ signers: ["S"], digest: D1, rpcUrl: m.url }));
  m.close();
});

test("forged record does not count towards a quorum", async () => {
  const m = await mockRpc({ A: [tx(1, memo("a/b", D1))], B: [tx(2, memo("a/b", D1), { forged: true })] });
  assert.equal(await findRecord({ signers: ["A", "B"], digest: D1, rpcUrl: m.url, quorum: 2 }), null);
  m.close();
});

// ---- RPC retry on rate limiting (public devnet/mainnet endpoints 429 often; CI must not treat that as "not verified")
test("a 429 is retried on the same endpoint before giving up", async () => {
  let hits = 0;
  const server = http.createServer((req, res) => {
    hits++;
    if (hits < 3) { res.statusCode = 429; res.end("rate limited"); return; }
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const { id } = JSON.parse(body);
      res.end(JSON.stringify({ jsonrpc: "2.0", id, result: "ok" }));
    });
  });
  await new Promise((r) => server.listen(0, r));
  const url = `http://127.0.0.1:${server.address().port}`;
  try {
    assert.equal(await rpcCall(url, "getHealth", []), "ok");
    assert.equal(hits, 3, "two 429s then a success, all against the same endpoint");
  } finally { server.close(); }
});

test("429s that never clear eventually throw (fail closed, not silently verified)", async () => {
  const server = http.createServer((_req, res) => { res.statusCode = 429; res.end("rate limited"); });
  await new Promise((r) => server.listen(0, r));
  const url = `http://127.0.0.1:${server.address().port}`;
  const prev = process.env.OATH_RPC_RETRIES;
  process.env.OATH_RPC_RETRIES = "1"; // keep this test fast; the retry count itself is exercised above
  try {
    await assert.rejects(() => rpcCall(url, "getHealth", []), /429/);
  } finally {
    server.close();
    if (prev === undefined) delete process.env.OATH_RPC_RETRIES; else process.env.OATH_RPC_RETRIES = prev;
  }
});

test("a 429 on the first of several endpoints fails over at once, without backing off on it", async () => {
  let first = 0;
  const limited = http.createServer((_q, res) => { first++; res.statusCode = 429; res.end(); });
  const good = http.createServer((req, res) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: "ok" }))); });
  await Promise.all([limited, good].map((s) => new Promise((r) => s.listen(0, r))));
  const url = `http://127.0.0.1:${limited.address().port},http://127.0.0.1:${good.address().port}`;
  try {
    const t0 = Date.now();
    assert.equal(await rpcCall(url, "getHealth", []), "ok");
    assert.equal(first, 1, "the rate-limited endpoint was asked once");
    assert.ok(Date.now() - t0 < 250, "no backoff sleep happened");
  } finally { limited.close(); good.close(); }
});

test("when every endpoint is rate limited, a backed-off second round can succeed", async () => {
  let hits = 0;
  const a = http.createServer((_q, res) => { hits++; res.statusCode = 429; res.end(); });
  let bHits = 0;
  const b = http.createServer((req, res) => { bHits++; if (bHits < 2) { res.statusCode = 429; res.end(); return; } let x = ""; req.on("data", (c) => (x += c)); req.on("end", () => res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: "ok" }))); });
  await Promise.all([a, b].map((s) => new Promise((r) => s.listen(0, r))));
  try {
    assert.equal(await rpcCall(`http://127.0.0.1:${a.address().port},http://127.0.0.1:${b.address().port}`, "getHealth", []), "ok");
    assert.equal(hits, 2); assert.equal(bHits, 2);
  } finally { a.close(); b.close(); }
});
