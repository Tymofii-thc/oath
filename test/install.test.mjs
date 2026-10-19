import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, chmodSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = new URL("..", import.meta.url).pathname;

test("install.sh puts the RPC URL (with '&', ',' and '|') into a Secret, not into the Deployment spec", () => {
  const dir = mkdtempSync(join(tmpdir(), "oath-install-"));
  const applied = join(dir, "applied.yaml");
  // stub kubectl: records what is piped into `apply`, succeeds at everything else
  const calls = join(dir, "calls.txt");
  writeFileSync(join(dir, "kubectl"), `#!/bin/sh\necho "$@" >> "${calls}"\ncase "$*" in *apply*) cat >> "${applied}";; esac\nexit 0\n`);
  chmodSync(join(dir, "kubectl"), 0o755);
  const rpc = "https://rpc.example/?api-key=k&commitment=confirmed,https://b.example/x|y";
  const r = spawnSync("bash", [join(root, "deploy/install.sh")], {
    env: { ...process.env, PATH: `${dir}:${process.env.PATH}`, OATH_SIGNER: "SIGNERKEY", SOLANA_RPC: rpc, OATH_IMAGE: "img:1" },
    encoding: "utf8",
  });
  assert.equal(r.status, 0, r.stderr);
  const yaml = readFileSync(applied, "utf8");
  assert.ok(readFileSync(calls, "utf8").includes(`--from-literal=rpc=${rpc}`), "the URL goes into the oath-rpc Secret unchanged");
  assert.ok(!yaml.includes("api-key"), "the URL (and its key) is not written into the applied manifests");
  assert.match(yaml, /secretKeyRef: \{ name: oath-rpc, key: rpc, optional: true \}/);
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

test("install.sh substitutes values that contain '&' (e.g. the image reference)", () => {
  const dir = mkdtempSync(join(tmpdir(), "oath-install2-"));
  const applied = join(dir, "applied.yaml");
  writeFileSync(join(dir, "kubectl"), `#!/bin/sh\ncase "$*" in *apply*) cat >> "${applied}";; esac\nexit 0\n`);
  chmodSync(join(dir, "kubectl"), 0o755);
  const r = spawnSync("bash", [join(root, "deploy/install.sh")], { env: { ...process.env, PATH: `${dir}:${process.env.PATH}`, OATH_SIGNER: "A&B|C", OATH_IMAGE: "img:1" }, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.ok(readFileSync(applied, "utf8").includes('value: "A&B|C"'));
});

test("install.sh audits already-running Pods by default (CronJob + one run now) and OATH_AUDIT_SCHEDULE=off skips it", () => {
  const run = (extra) => {
    const dir = mkdtempSync(join(tmpdir(), "oath-audit-"));
    const calls = join(dir, "calls.txt"), applied = join(dir, "applied.yaml");
    writeFileSync(join(dir, "kubectl"), `#!/bin/sh\necho "$@" >> "${calls}"\ncase "$*" in *apply*) cat >> "${applied}";; esac\nexit 0\n`);
    chmodSync(join(dir, "kubectl"), 0o755);
    const r = spawnSync("bash", [join(root, "deploy/install.sh")], { env: { ...process.env, PATH: `${dir}:${process.env.PATH}`, OATH_SIGNER: "S", OATH_IMAGE: "img:1", ...extra }, encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    return { yaml: readFileSync(applied, "utf8"), calls: readFileSync(calls, "utf8") };
  };
  const on = run({});
  assert.match(on.yaml, /schedule: "0 \* \* \* \*"/);
  assert.match(on.calls, /create job oath-audit-first-\d+ --from=cronjob\/oath-audit/);
  const off = run({ OATH_AUDIT_SCHEDULE: "off" });
  assert.ok(!off.yaml.includes("kind: CronJob"));
  assert.ok(!off.calls.includes("--from=cronjob"));
});
