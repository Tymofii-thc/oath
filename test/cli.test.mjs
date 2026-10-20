import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const D = "sha256:" + "a".repeat(64);
const SIGNER = "SignerKey1111111111111111111111111111111111";

// the CLI in a child process (the test's event loop must stay free to serve the mock RPC); PATH has no docker and no git
const cli = (args, env = {}) => new Promise((resolve) => {
  const p = spawn(process.execPath, [join(root, "bin/oath.mjs"), ...args], { env: { PATH: "/nonexistent", ...env }, cwd: tmpdir() });
  let out = "", err = "";
  p.stdout.on("data", (c) => (out += c)); p.stderr.on("data", (c) => (err += c));
  p.on("close", (code) => resolve({ code, out, err }));
});

function rpc(memoDigest) {
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const { method, params, id } = JSON.parse(body);
      res.setHeader("content-type", "application/json");
      const result = method === "getTransaction"
        ? { meta: { err: null }, transaction: { message: { accountKeys: [{ pubkey: SIGNER, signer: true }] } } }
        : params[1].before ? [] : [{ signature: "s1", err: null, blockTime: Math.floor(Date.now() / 1000), memo: `[99] pod1|ghcr.io/me/app|0123456789ab|${memoDigest}|2026-01-01T00:00:00.000Z` }];
      res.end(JSON.stringify({ jsonrpc: "2.0", id, result }));
    });
  });
  return new Promise((r) => server.listen(0, () => r({ url: `http://127.0.0.1:${server.address().port}`, close: () => server.close() })));
}

test("verify --image repo@sha256:… needs neither docker nor a registry call", async () => {
  const m = await rpc(D);
  try {
    const ok = await cli(["verify", "--signer", SIGNER, "--image", `ghcr.io/me/app@${D}`, "--rpc", m.url]);
    assert.equal(ok.code, 0, ok.err + ok.out);
    assert.match(ok.out, /VERIFIED/);
    // the record is bound to the image name: the same digest under another name is not verified
    const other = await cli(["verify", "--signer", SIGNER, "--image", `ghcr.io/me/other@${D}`, "--rpc", m.url]);
    assert.equal(other.code, 1, other.out);
  } finally { m.close(); }
});

test("verify --image repo@sha256:… of an unrecorded digest is NOT VERIFIED", async () => {
  const m = await rpc("sha256:" + "b".repeat(64));
  try {
    const r = await cli(["verify", "--signer", SIGNER, "--image", `ghcr.io/me/app@${D}`, "--rpc", m.url]);
    assert.equal(r.code, 1, r.out);
    assert.match(r.err + r.out, /NOT VERIFIED/);
  } finally { m.close(); }
});

test("anchor refuses to run without an image, a commit or a key", async () => {
  assert.match((await cli(["anchor"])).err, /Missing --image/);
  assert.match((await cli(["anchor", "--image", "ghcr.io/me/app", "--digest", D])).err, /Missing --commit/);
  const noKey = await cli(["anchor", "--image", "ghcr.io/me/app", "--digest", D, "--commit", "0123456789ab"]);
  assert.equal(noKey.code, 2);
  assert.match(noKey.err, /secret key/);
  assert.match((await cli(["anchor", "--image", "ghcr.io/me/app", "--digest", "nope", "--commit", "0123456789ab"])).err, /Bad --digest/);
});

test("anchor takes the commit from the CI environment and fails clearly when it cannot send", async () => {
  const key = join(mkdtempSync(join(tmpdir(), "oath-anchor-")), "k.json");
  writeFileSync(key, JSON.stringify(Array.from({ length: 64 }, (_, i) => i)));
  const r = await cli(["anchor", "--image", "GHCR.io/Me/App:latest", "--digest", D, "--key-file", key, "--rpc", "http://127.0.0.1:9"], { BUILD_SOURCEVERSION: "ABCDEF0123456789" });
  assert.equal(r.code, 2);
  assert.match(r.err, /could not send the record/); // got as far as sending: image, digest, commit and key were all accepted
});

test("--help lists every command, `<command> --help` lists its options, --version matches package.json", async () => {
  const main = await cli(["--help"]);
  assert.equal(main.code, 0);
  for (const c of ["init", "anchor", "verify", "audit", "revoke"]) assert.match(main.out, new RegExp(`^  ${c}\\s+\\S`, "m"), c);
  const v = await cli(["verify", "--help"]);
  assert.equal(v.code, 0);
  assert.match(v.out, /--signer/);
  assert.match(v.out, /--quorum/);
  assert.equal((await cli(["help", "anchor"])).code, 0);
  const version = (await cli(["--version"])).out.trim();
  assert.equal(version, JSON.parse((await import("node:fs")).readFileSync(join(root, "package.json"), "utf8")).version);
  const bad = await cli(["nope"]);
  assert.equal(bad.code, 2);
  assert.match(bad.err, /Unknown command/);
});

test("a broken OATH_REGISTRY_AUTH is reported as that, and its value is not printed", async () => {
  const r = await cli(["anchor", "--image", "reg.example/app:1", "--commit", "0123456789ab"], { OATH_REGISTRY_AUTH: '{"reg.example":{"username":"u","password":"s3cr3t"oops"}}' });
  assert.equal(r.code, 2);
  assert.match(r.err, /OATH_REGISTRY_AUTH is not valid JSON/);
  assert.ok(!r.err.includes("s3cr3t"), "the password must not appear in the error");
  // some Node versions put an excerpt of the bad text into the parse error: it must not reach the output either
  const r2 = await cli(["anchor", "--image", "reg.example/app:1", "--commit", "0123456789ab"], { OATH_REGISTRY_AUTH: "{bad s3cr3t" });
  assert.match(r2.err, /not valid JSON/);
  assert.ok(!r2.err.includes("s3cr3t"));
});
