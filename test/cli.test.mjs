import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, chmodSync, readFileSync, mkdirSync } from "node:fs";
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

function rpc(memoDigest, image = "ghcr.io/me/app") {
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const { method, params, id } = JSON.parse(body);
      res.setHeader("content-type", "application/json");
      const result = method === "getTransaction"
        ? { meta: { err: null }, transaction: { message: { accountKeys: [{ pubkey: SIGNER, signer: true }] } } }
        : params[1].before ? [] : [{ signature: "s1", err: null, blockTime: Math.floor(Date.now() / 1000), memo: `[99] pod1|${image}|0123456789ab|${memoDigest}|2026-01-01T00:00:00.000Z` }];
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

// a registry whose tag now points at EVIL, and a fake docker whose local copy still has GOOD
async function tagSwapSetup() {
  const GOOD = "sha256:" + "a".repeat(64), EVIL = "sha256:" + "b".repeat(64);
  let hits = 0;
  const registry = http.createServer((req, res) => { hits++; res.setHeader("docker-content-digest", EVIL); res.end(); });
  await new Promise((r) => registry.listen(0, "127.0.0.1", r));
  const host = `127.0.0.1:${registry.address().port}`;
  const dir = mkdtempSync(join(tmpdir(), "fake-docker-"));
  writeFileSync(join(dir, "docker"), `#!/bin/sh\necho "${host}/app@${GOOD}"\n`);
  chmodSync(join(dir, "docker"), 0o755);
  return { GOOD, EVIL, host, dir, hits: () => hits, close: () => registry.close() };
}

test("verify of a tag asks the registry, not the local docker copy that this agent just pushed", async () => {
  const t = await tagSwapSetup();
  const m = await rpc(t.GOOD, `${t.host}/app`);
  try {
    // the local copy (GOOD) was recorded, but the tag in the registry now points at EVIL: that must not verify
    const r = await cli(["verify", "--signer", SIGNER, "--image", `${t.host}/app:42`, "--rpc", m.url], { PATH: t.dir });
    assert.equal(r.code, 1, r.out + r.err);
    assert.match(r.err + r.out, /NOT VERIFIED/);
    assert.ok(t.hits() > 0, "the registry was asked");
  } finally { m.close(); t.close(); }
});

test("verify falls back to the local docker copy only when the registry cannot be asked, and says so", async () => {
  const t = await tagSwapSetup();
  const m = await rpc(t.GOOD, `${t.host}/app`);
  t.close(); // the registry is gone
  try {
    const r = await cli(["verify", "--signer", SIGNER, "--image", `${t.host}/app:42`, "--rpc", m.url], { PATH: t.dir });
    assert.equal(r.code, 0, r.out + r.err);
    assert.match(r.err, /could not ask the registry/);
  } finally { m.close(); }
});

test("anchor records the digest of the local copy (what this job pushed), not what the tag points to now", async () => {
  const t = await tagSwapSetup();
  try {
    const r = await cli(["anchor", "--image", `${t.host}/app:42`, "--commit", "0123456789ab", "--dry-run"], { PATH: t.dir });
    assert.equal(r.code, 0, r.err);
    assert.ok(r.out.includes(t.GOOD) && !r.out.includes(t.EVIL), r.out);
    assert.equal(t.hits(), 0, "no registry request needed");
  } finally { t.close(); }
});

test("verify --max-age together with --program is an error, not silently ignored", async () => {
  const r = await cli(["verify", "--signer", SIGNER, "--digest", D, "--max-age", "7", "--program", "Prog11111111111111111111111111111111111111", "--rpc", "http://127.0.0.1:9"]);
  assert.equal(r.code, 2, r.out + r.err);
  assert.match(r.err, /--max-age does not work with --program/);
});

test("verify --attest with a malformed requirement exits 2 before any network call", async () => {
  const r = await cli(["verify", "--signer", SIGNER, "--digest", D, "--attest", "me/app@main", "--rpc", "http://127.0.0.1:9"]);
  assert.equal(r.code, 2, r.out + r.err);
  assert.match(r.err, /full ref/);
});

// offline approvals through the real CLI: sign, verify, tamper, revoke; the "RPC" is unroutable and never used
import { generateKeyPairSync } from "node:crypto";
import { b58encode } from "../lib/approval.mjs";
function keyFile(dir, name) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32), pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const file = join(dir, name);
  writeFileSync(file, JSON.stringify([...Buffer.concat([seed, pub])]), { mode: 0o600 });
  return { file, pub: b58encode(pub) };
}

test("oath approve + verify --approvals work offline and refuse everything else", async () => {
  const dir = mkdtempSync(join(tmpdir(), "oath-appr-cli-"));
  const human = keyFile(dir, "human.json"), ci = keyFile(dir, "ci.json");
  const img = `ghcr.io/me/app@${D}`;
  const sign = (k, extra = []) => cli(["approve", "--image", "ghcr.io/me/app", "--digest", D, "--commit", "0123456789ab", "--key-file", k.file, ...extra]);
  const okSign = await sign(human, ["--out", join(dir, "approval.json")]);
  assert.equal(okSign.code, 0, okSign.err);
  assert.match(okSign.out, new RegExp(`signed by ${human.pub}`));
  const verify = (signer, path, extra = []) => cli(["verify", "--signer", signer, "--image", img, "--approvals", path, "--rpc", "http://127.0.0.1:9", ...extra]);

  const good = await verify(human.pub, join(dir, "approval.json"));
  assert.equal(good.code, 0, good.err + good.out);
  assert.match(good.out, /VERIFIED/); assert.match(good.out, /checked offline/);

  await sign(ci, ["--out", join(dir, "ci.json.approval")]);
  writeFileSync(join(dir, "ci-approval.json"), readFileSync(join(dir, "ci.json.approval")));
  const untrusted = await verify(human.pub, join(dir, "ci-approval.json"));
  assert.equal(untrusted.code, 1, "an approval signed by a key you do not trust is worthless");

  const tampered = JSON.parse(readFileSync(join(dir, "approval.json"), "utf8"));
  tampered.message = tampered.message.replace("ghcr.io/me/app", "ghcr.io/me/evil");
  writeFileSync(join(dir, "tampered.json"), JSON.stringify(tampered));
  assert.equal((await verify(human.pub, join(dir, "tampered.json"))).code, 1, "an edited statement no longer verifies");

  const rev = await cli(["approve", "--revoke", "--digest", D, "--reason", "backdoor", "--key-file", human.file, "--out", join(dir, "rev.json")]);
  assert.equal(rev.code, 0, rev.err);
  mkdirSync(join(dir, "both"));
  writeFileSync(join(dir, "both", "a.json"), readFileSync(join(dir, "approval.json")));
  writeFileSync(join(dir, "both", "r.json"), readFileSync(join(dir, "rev.json")));
  const revoked = await verify(human.pub, join(dir, "both"));
  assert.equal(revoked.code, 1);
  assert.match(revoked.err, /REVOKED/); assert.match(revoked.err, /backdoor/);
});

test("--print-message needs no key, and --approvals refuses --max-age and --program", async () => {
  const p = await cli(["approve", "--image", "ghcr.io/me/app", "--digest", D, "--commit", "0123456789ab", "--print-message"]);
  assert.equal(p.code, 0, p.err);
  assert.match(p.out, /^oath approval v1\nimage: ghcr\.io\/me\/app\ndigest: sha256:a{64}\ncommit: 0123456789ab\napproved: /);
  const both = await cli(["verify", "--signer", SIGNER, "--digest", D, "--approvals", "/nonexistent", "--max-age", "7"]);
  assert.equal(both.code, 2); assert.match(both.err, /--max-age does not work with --approvals/);
  const two = await cli(["verify", "--signer", SIGNER, "--digest", D, "--approvals", "/nonexistent", "--program", "P"]);
  assert.equal(two.code, 2); assert.match(two.err, /two different backends/);
});
