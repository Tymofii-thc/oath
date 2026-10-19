import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, chmodSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = new URL("..", import.meta.url).pathname;

test("install.sh keeps '&' and '|' in values intact (RPC URL with a query string)", () => {
  const dir = mkdtempSync(join(tmpdir(), "oath-install-"));
  const applied = join(dir, "applied.yaml");
  // stub kubectl: records what is piped into `apply`, succeeds at everything else
  writeFileSync(join(dir, "kubectl"), `#!/bin/sh\ncase "$*" in *apply*) cat >> "${applied}";; esac\nexit 0\n`);
  chmodSync(join(dir, "kubectl"), 0o755);
  const rpc = "https://rpc.example/?api-key=k&commitment=confirmed,https://b.example/x|y";
  const r = spawnSync("bash", [join(root, "deploy/install.sh")], {
    env: { ...process.env, PATH: `${dir}:${process.env.PATH}`, OATH_SIGNER: "SIGNERKEY", SOLANA_RPC: rpc, OATH_IMAGE: "img:1" },
    encoding: "utf8",
  });
  assert.equal(r.status, 0, r.stderr);
  const yaml = readFileSync(applied, "utf8");
  assert.ok(yaml.includes(`value: "${rpc}"`), "SOLANA_RPC arrives unchanged");
  assert.ok(!yaml.includes("__"), "no placeholder is left");
});

test("oath init --approver makes an approver key and does not tell you to put it into GitHub secrets", async (t) => {
  try { await import("@solana/web3.js"); } catch { return t.skip("@solana/web3.js is not installed"); }
  const dir = mkdtempSync(join(tmpdir(), "oath-init-"));
  const r = spawnSync("node", [join(root, "bin/oath.mjs"), "init", "--approver", "--no-wait", "--rpc", "http://127.0.0.1:9"], { cwd: dir, encoding: "utf8" });
  assert.ok(existsSync(join(dir, ".oath/approver-key.json")), r.stdout + r.stderr);
  assert.ok(!existsSync(join(dir, ".oath/ci-key.json")));
  assert.match(r.stdout, /approver key/);
  assert.match(r.stdout, /--quorum 2/);
  assert.doesNotMatch(r.stdout, /SOLANA_SECRET_KEY\s+=/);
  assert.doesNotMatch(r.stdout, /node bin\/oath\.mjs init/);
});

test("the CI-key init output recommends `oath init --approver`, not a repo-relative node command", () => {
  const src = readFileSync(join(root, "bin/oath.mjs"), "utf8");
  assert.ok(src.includes('"    oath init --approver"'));
});
