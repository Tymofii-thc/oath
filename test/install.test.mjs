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
  writeFileSync(join(dir, "kubectl"), `#!/bin/sh\necho "$@" >> "${calls}"\ncase "$*" in *apply*) cat >> "${applied}";; *"get job/"*) printf 1;; esac\nexit 0\n`);
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
  writeFileSync(join(dir, "kubectl"), `#!/bin/sh\ncase "$*" in *apply*) cat >> "${applied}";; *"get job/"*) printf 1;; esac\nexit 0\n`);
  chmodSync(join(dir, "kubectl"), 0o755);
  const r = spawnSync("bash", [join(root, "deploy/install.sh")], { env: { ...process.env, PATH: `${dir}:${process.env.PATH}`, OATH_SIGNER: "A&B|C", OATH_IMAGE: "img:1" }, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.ok(readFileSync(applied, "utf8").includes('value: "A&B|C"'));
});

test("install.sh audits already-running Pods by default (CronJob + one run now) and OATH_AUDIT_SCHEDULE=off skips it", () => {
  const run = (extra) => {
    const dir = mkdtempSync(join(tmpdir(), "oath-audit-"));
    const calls = join(dir, "calls.txt"), applied = join(dir, "applied.yaml");
    writeFileSync(join(dir, "kubectl"), `#!/bin/sh\necho "$@" >> "${calls}"\ncase "$*" in *apply*) cat >> "${applied}";; *"get job/"*) printf 1;; esac\nexit 0\n`);
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

// install.sh checks the official webhook image before installing it, and installs it by digest
function installWith(env, cliExit = 0) {
  const dir = mkdtempSync(join(tmpdir(), "oath-imgcheck-"));
  const calls = join(dir, "calls.txt"), applied = join(dir, "applied.yaml"), cliArgs = join(dir, "cli.txt");
  writeFileSync(join(dir, "kubectl"), `#!/bin/sh\necho "$@" >> "${calls}"\ncase "$*" in *apply*) cat >> "${applied}";; *"get job/"*) printf 1;; esac\nexit 0\n`);
  // a stand-in for the oath CLI: records its arguments and answers like a successful (or failed) `oath verify`
  writeFileSync(join(dir, "fake-oath"), `#!/bin/sh\necho "$@" >> "${cliArgs}"\n[ ${cliExit} = 0 ] && echo "VERIFIED  sha256:${"f".repeat(64)}" && echo "  built from commit abc"\nexit ${cliExit}\n`);
  for (const f of ["kubectl", "fake-oath"]) chmodSync(join(dir, f), 0o755);
  const r = spawnSync("bash", [join(root, "deploy/install.sh")], { env: { ...process.env, PATH: `${dir}:${process.env.PATH}`, OATH_SIGNER: "S", OATH_CLI: join(dir, "fake-oath"), ...env }, encoding: "utf8" });
  const read = (f) => (existsSync(f) ? readFileSync(f, "utf8") : "");
  return { r, yaml: read(applied), calls: read(calls), cli: read(cliArgs) };
}

test("the official webhook image is checked first and installed by the digest that was checked", () => {
  const { r, yaml, cli } = installWith({});
  assert.equal(r.status, 0, r.stderr);
  assert.match(cli, /verify --signer 5D4W8x8UeqW3qVi9uzNzvJPWiJZQaRWVR9ru2ckFhoih --image ghcr\.io\/tymofii-thc\/oath-webhook:latest/);
  assert.match(cli, /--attest Tymofii-thc\/oath\/\.github\/workflows\/release-webhook\.yml@refs\/heads\/main/);
  assert.match(cli, /--rpc https:\/\/api\.devnet\.solana\.com/, "the project's records are on devnet whatever network the webhook itself watches");
  assert.ok(yaml.includes(`image: ghcr.io/tymofii-thc/oath-webhook@sha256:${"f".repeat(64)}`), "the Deployment runs the digest that was verified");
  assert.ok(!yaml.includes("oath-webhook:latest"), "no moving tag in what is applied");
});

test("an unverified official image stops the install before anything touches the cluster", () => {
  const { r, calls } = installWith({}, 1);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /NOT verified: refusing to install/);
  assert.equal(calls, "", "no kubectl call at all");
});

test("a user's SOLANA_RPC (for the webhook) does not redirect the check of the image", () => {
  const { cli } = installWith({ SOLANA_RPC: "https://my.mainnet.rpc/x", OATH_NETWORK: "mainnet" });
  assert.ok(!cli.includes("my.mainnet.rpc"));
  assert.match(cli, /--network devnet/);
});

test("a custom image is installed as given unless a signer is set for it", () => {
  const plain = installWith({ OATH_IMAGE: "registry.example/me/wh:1" });
  assert.equal(plain.cli, "", "not checked");
  assert.match(plain.r.stderr, /custom image/);
  assert.ok(plain.yaml.includes("image: registry.example/me/wh:1"));
  const checked = installWith({ OATH_IMAGE: "registry.example/me/wh:1", OATH_IMAGE_SIGNER: "MySigner", OATH_IMAGE_ATTEST: "me/wh/build.yml@refs/heads/main" });
  assert.match(checked.cli, /--signer MySigner --image registry\.example\/me\/wh:1/);
  assert.ok(checked.yaml.includes(`image: registry.example/me/wh@sha256:${"f".repeat(64)}`));
});

test("OATH_VERIFY_IMAGE=skip installs without the check and says so", () => {
  const { r, cli, yaml } = installWith({ OATH_VERIFY_IMAGE: "skip" });
  assert.equal(cli, "");
  assert.match(r.stderr, /WITHOUT checking/);
  assert.ok(yaml.includes("oath-webhook:latest"));
});
