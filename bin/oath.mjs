#!/usr/bin/env node
// oath — Proof of Deploy CLI
//
//   oath verify --signer <pubkey[,pubkey…]> --digest sha256:<hex>
//   oath verify --signer <pubkey> --image ghcr.io/me/app:latest      (digest read from local docker, else from the registry: OATH_REGISTRY_AUTH for private ones)
//   oath verify --signer <pubkey> --image ghcr.io/me/app@sha256:…   (a pinned ref needs no docker and no registry call)
//   oath verify --signer <pubkey> --container prod                   (digest of the RUNNING image)
//   oath anchor --image ghcr.io/me/app:latest [--digest sha256:…] [--commit <sha>] [--key-file <path>]   (record a build: SOLANA_SECRET_KEY; no docker, the digest comes from the registry)
//   oath init   [--out .oath/ci-key.json] [--approver] [--no-wait] [--set-github]      (create a CI key, fund it on devnet, print the next steps)
//   oath revoke --digest sha256:<hex> --reason "<text>"   (SOLANA_SECRET_KEY or --key-file; a revoked digest never verifies again)
//   oath audit  --signer <pubkey> [--file pods.json | --in-cluster] [--skip-namespaces a,b]   (every Pod running in the current kube context, or from inside a Pod)
//
// Options: --network devnet|mainnet | --rpc <url>   --max-age <days>   --limit <txs per signer, default 1000>
//          --quorum <N>  at least N distinct signers must have anchored the digest (a stolen CI key alone is then not enough)
//          --attest <owner/repo>  also require a Sigstore-signed SLSA build attestation from that repo's GitHub Actions
//          --no-bind  (don't require the record's image name to match the image being checked)
// Env:     OATH_SIGNER (comma separated), OATH_NETWORK, SOLANA_RPC, OATH_QUORUM, OATH_ATTEST_REPO, GITHUB_TOKEN (optional, API rate limit)
//
// Exit codes: 0 = verified, 1 = NOT verified, 2 = usage / network error.
// Put it right before your deploy step: if it exits non-zero, the deploy stops.
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, existsSync, mkdirSync, appendFileSync } from "node:fs";
import { dirname } from "node:path";
import { extractDigest, checkRecord, repoName, resolveRpc } from "../lib/oath.mjs";
import { sendMemo } from "../lib/memo.mjs";
import { resolveDigest } from "../lib/registry.mjs";
import { collectImages, listPodsInCluster } from "../lib/audit.mjs";
import { verifyAttestation } from "../lib/attest.mjs";

function arg(name) {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : undefined;
}
const flag = (name) => process.argv.includes(`--${name}`);

function fail(code, msg) {
  console.error(msg);
  process.exit(code);
}

function docker(args) {
  try {
    return execFileSync("docker", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  } catch (e) {
    fail(2, `docker failed: ${(e.stderr || e.message).toString().trim()}`);
  }
}

// All "repo@sha256:…" entries of a local image; prefer the one whose repo matches `ref`.
function pickRepoDigest(lines, ref) {
  const all = lines.split("\n").map((l) => l.trim()).filter(Boolean);
  const want = repoName(ref);
  const chosen = (want && all.find((l) => repoName(l) === want)) || all[0];
  return chosen ? { digest: extractDigest(chosen), repo: repoName(chosen) } : null;
}

const REPO_DIGESTS = "{{range .RepoDigests}}{{println .}}{{end}}";
// repo@sha256:… entries of an image in local docker, or null
function localDigest(image) {
  try { return pickRepoDigest(execFileSync("docker", ["image", "inspect", "--format", REPO_DIGESTS, image], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim(), image); }
  catch { return null; }
}

const registryAuths = () => {
  if (!process.env.OATH_REGISTRY_AUTH) return {};
  try { return JSON.parse(process.env.OATH_REGISTRY_AUTH); } // the value itself is never printed: it holds a password
  catch (e) { fail(2, `OATH_REGISTRY_AUTH is not valid JSON${/position (\d+)/.exec(e.message) ? ` (near character ${/position (\d+)/.exec(e.message)[1]})` : ""}. Expected {"<registry host>":{"username":"…","password":"…"}}; check for stray quotes, line breaks, or a " or \\ inside the password.`); }
};

async function resolveTarget() {
  const direct = arg("digest");
  if (direct) return { digest: extractDigest(direct), repo: null };

  const fmt = "{{range .RepoDigests}}{{println .}}{{end}}";
  const container = arg("container");
  if (container) {
    const imageId = docker(["inspect", "--format", "{{.Image}}", container]);
    return pickRepoDigest(docker(["inspect", "--format", fmt, imageId])) || { digest: null };
  }
  const image = arg("image");
  if (image) {
    // repo@sha256:… already says which digest it is: no docker, no registry call
    const pinned = image.match(/@(sha256:[0-9a-f]{64})$/i);
    if (pinned) return { digest: pinned[1].toLowerCase(), repo: repoName(image) };
    // A tag means "whatever the registry serves now", which is what prod will pull: ask the registry first. A local docker copy
    // proves little (in a CI job it is the image this very agent just built and pushed), so it is only a fallback, and a loud one.
    let regErr;
    try { return { digest: await resolveDigest(image, { auths: registryAuths() }), repo: repoName(image) }; } catch (e) { regErr = e; }
    const local = localDigest(image);
    if (local) {
      console.error(`warning: could not ask the registry (${regErr.message}); using the local docker copy, which does not prove what ${image} points to now`);
      return local;
    }
    fail(2, `cannot get the digest of ${image}: ${regErr.message} (private registry: set OATH_REGISTRY_AUTH; or pass repo@sha256:…)`);
  }
  return { digest: null };
}

async function verify() {
  const signers = (arg("signer") || process.env.OATH_SIGNER || process.env.POD_SIGNER || "")
    .split(",").map((s) => s.trim()).filter(Boolean);
  if (!signers.length) fail(2, "Missing --signer <public key of the CI signer> (or OATH_SIGNER). Comma-separate several to accept a rotation.");

  let rpcUrl;
  try {
    rpcUrl = resolveRpc({ rpc: arg("rpc"), network: arg("network") });
  } catch (e) {
    fail(2, e.message);
  }

  const { digest: want, repo } = await resolveTarget();
  if (!want) fail(2, "Could not determine a sha256 digest (no registry digest on the local image?). Pass --digest, or push/pull the image first.");

  const maxAgeDays = arg("max-age");
  const quorum = Number(arg("quorum") || process.env.OATH_QUORUM || 1);
  const attestRepo = arg("attest") || process.env.OATH_ATTEST_REPO;
  let check;
  try {
    check = await checkRecord({
      signers,
      digest: want,
      rpcUrl,
      limit: Number(arg("limit") || 1000),
      image: flag("no-bind") ? undefined : repo,
      maxAgeSeconds: maxAgeDays ? Number(maxAgeDays) * 86400 : undefined,
      quorum,
    });
  } catch (e) {
    fail(2, `RPC lookup failed: ${e.message}`);
  }

  if (check.status === "revoked") {
    console.error(`REVOKED  ${want}`);
    console.error(`  Revoked by ${check.signer}${check.reason ? `: ${check.reason}` : ""}`);
    console.error("  Refusing to proceed: a trusted key marked this digest as bad.");
    process.exit(1);
  }
  const rec = check.status === "verified" ? check.rec : null;

  if (rec) {
    let att = null;
    if (attestRepo) {
      try {
        att = await verifyAttestation({ digest: want, image: flag("no-bind") ? undefined : repo, repo: attestRepo });
      } catch (e) {
        fail(2, `attestation check failed: ${e.message}`);
      }
      if (!att.ok) {
        console.error(`NOT VERIFIED  ${want}`);
        console.error(`  The digest is anchored on Solana, but the build attestation check failed: ${att.reason}`);
        process.exit(1);
      }
    }
    console.log(`VERIFIED  ${want}`);
    console.log(`  built from commit ${rec.commit} (${rec.image})`);
    console.log(`  anchored at ${rec.anchoredAt} by ${rec.signers.join(" + ")}${quorum > 1 ? `  (quorum ${rec.signers.length}/${quorum} met)` : ""}`);
    console.log(`  tx ${rec.signature}`);
    if (att) console.log(`  build attestation OK: Sigstore-signed by ${att.workflow}`);
    if (quorum <= 1 && process.stderr.isTTY && !process.env.OATH_QUIET) console.error("  note: single-signer verification — whoever holds this signer's key alone can anchor a forged digest; see --quorum in README.");
    process.exit(0);
  }

  console.error(`NOT VERIFIED  ${want}`);
  console.error(`  No pipeline build with this digest${repo ? ` for ${repo}` : ""} was anchored by ${quorum > 1 ? `${quorum} of ` : ""}${signers.join(" / ")}${maxAgeDays ? ` in the last ${maxAgeDays} days` : ""}.`);
  console.error("  Refusing to proceed: the image may have been replaced outside the pipeline.");
  process.exit(1);
}

// Checks every running container of the current cluster (or of a saved `kubectl get pods -A -o json`).
async function audit() {
  const signers = (arg("signer") || process.env.OATH_SIGNER || process.env.POD_SIGNER || "").split(",").map((s) => s.trim()).filter(Boolean);
  if (!signers.length) fail(2, "Missing --signer (or OATH_SIGNER).");
  let rpcUrl;
  try { rpcUrl = resolveRpc({ rpc: arg("rpc"), network: arg("network") }); } catch (e) { fail(2, e.message); }

  let list;
  if (flag("in-cluster")) {
    try { list = await listPodsInCluster(); } catch (e) { fail(2, `cannot list pods: ${e.message}`); }
  } else {
    let raw;
    const file = arg("file");
    try {
      raw = file
        ? readFileSync(file === "-" ? 0 : file, "utf8")
        : execFileSync("kubectl", ["get", "pods", "-A", "-o", "json"], { encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });
    } catch (e) {
      fail(2, `cannot read pods: ${(e.stderr || e.message).toString().trim()}`);
    }
    try { list = JSON.parse(raw); } catch { fail(2, "pods input is not valid JSON"); }
  }

  const skip = (arg("skip-namespaces") ?? "kube-system,kube-public,kube-node-lease,oath-system").split(",").filter(Boolean);
  const images = collectImages(list, { skipNamespaces: skip });
  const maxAgeDays = arg("max-age");
  const cache = new Map();
  let bad = 0;
  for (const im of images) {
    if (!im.digest) { bad++; console.log(`UNKNOWN      ${im.where}  ${im.image}  (no digest in imageID)`); continue; }
    const key = `${im.repo}@${im.digest}`;
    if (!cache.has(key)) {
      try {
        cache.set(key, await checkRecord({ signers, digest: im.digest, rpcUrl, limit: Number(arg("limit") || 1000), image: flag("no-bind") ? undefined : im.repo, maxAgeSeconds: maxAgeDays ? Number(maxAgeDays) * 86400 : undefined, quorum: Number(arg("quorum") || process.env.OATH_QUORUM || 1) }));
      } catch (e) {
        fail(2, `RPC lookup failed: ${e.message}`);
      }
    }
    const chk = cache.get(key);
    if (chk.status === "verified") console.log(`VERIFIED     ${im.where}  ${im.image}  commit ${chk.rec.commit}`);
    else if (chk.status === "revoked") { bad++; console.log(`REVOKED      ${im.where}  ${im.image}  ${im.digest}  (${chk.reason || "no reason given"})`); }
    else { bad++; console.log(`NOT VERIFIED ${im.where}  ${im.image}  ${im.digest}`); }
  }
  console.log(`\n${images.length} containers checked, ${bad} not verified.`);
  process.exit(bad ? 1 : 0);
}

// The signing key: --key-file wins over SOLANA_SECRET_KEY (a JSON array of 64 numbers).
function readSecret() {
  let secret = process.env.SOLANA_SECRET_KEY;
  if (arg("key-file")) { try { secret = readFileSync(arg("key-file"), "utf8"); } catch (e) { fail(2, `cannot read key file: ${e.message}`); } }
  if (!secret) fail(2, "Provide the signer's secret key: SOLANA_SECRET_KEY='[…]' or --key-file <path>.");
  try { return JSON.parse(secret); } catch { fail(2, "The secret key is not valid JSON (expected a JSON array of numbers)."); }
}

// Records a build: the same memo the GitHub Action writes, but from any CI and without docker.
async function anchor() {
  const image = arg("image");
  if (!image) fail(2, "Missing --image <registry/name[:tag]> (the name that goes into the record).");
  let digest = null;
  if (arg("digest")) { digest = extractDigest(arg("digest")); if (!digest) fail(2, "Bad --digest (expected sha256:<64 hex>)."); }
  else digest = extractDigest(image.match(/@sha256:[0-9a-fA-F]{64}$/)?.[0]);
  if (!digest) {
    // what this job just built and pushed is what must be recorded: take the digest from the local copy when there is one, because a tag
    // can be moved in the registry between the push and now. Without docker the registry is asked.
    const local = localDigest(image);
    if (local) digest = local.digest;
    else {
      try { digest = await resolveDigest(image, { auths: registryAuths() }); }
      catch (e) { fail(2, `cannot get the digest of ${image}: ${e.message} (pass --digest, or OATH_REGISTRY_AUTH for a private registry)`); }
      console.error(`note: ${image} is not in local docker; the digest comes from the registry (it may have moved since your push)`);
    }
  }
  let commit = arg("commit") || process.env.GITHUB_SHA || process.env.BUILD_SOURCEVERSION || process.env.CI_COMMIT_SHA || "";
  if (!commit) { try { commit = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim(); } catch { /* not a checkout */ } }
  commit = commit.trim().toLowerCase();
  if (!/^[0-9a-f]{7,40}$/.test(commit)) fail(2, "Missing --commit <sha> (or set GITHUB_SHA / BUILD_SOURCEVERSION / CI_COMMIT_SHA, or run inside a git checkout).");
  const text = `pod1|${repoName(image)}|${commit.slice(0, 12)}|${digest}|${new Date().toISOString()}`;
  if (flag("dry-run")) { console.log(`Would record: ${text}`); return; }
  const secretKey = readSecret();
  let rpcUrl;
  try { rpcUrl = resolveRpc({ rpc: arg("rpc"), network: arg("network") }); } catch (e) { fail(2, e.message); }
  try {
    const out = await sendMemo({ text, secretKey, rpcUrl });
    console.log(`Anchored: ${text}`);
    console.log(`Digest  : ${digest}`);   // deploy this exact digest (repo@sha256:…), not the tag
    console.log(`Signer  : ${out.signer}`);
    console.log(`Tx      : ${out.signature}`);
  } catch (e) {
    fail(2, `could not send the record: ${e.message}`);
  }
}

// Marks a digest as bad. Any trusted signer can do it; it takes effect for every later check.
async function revoke() {
  const digest = extractDigest(arg("digest"));
  if (!digest) fail(2, "Missing --digest sha256:<64 hex>.");
  const reason = String(arg("reason") || "").replace(/[|\r\n]+/g, " ").trim().slice(0, 100);
  const secretKey = readSecret();
  let rpcUrl;
  try { rpcUrl = resolveRpc({ rpc: arg("rpc"), network: arg("network") }); } catch (e) { fail(2, e.message); }
  const text = `pod1r|${digest}|${reason}|${new Date().toISOString()}`;
  try {
    const out = await sendMemo({ text, secretKey, rpcUrl });
    console.log(`Revoked: ${text}`);
    console.log(`Signer : ${out.signer}`);
    console.log(`Tx     : ${out.signature}`);
  } catch (e) {
    fail(2, `could not send the revocation: ${e.message}`);
  }
}

// One-command setup: a CI key in a file (the secret is never printed), a funded devnet balance, and the exact next steps.
async function init() {
  const approver = flag("approver"); // a second, independent key for --quorum: never goes into CI secrets
  const out = arg("out") || (approver ? ".oath/approver-key.json" : ".oath/ci-key.json");
  const network = arg("network") || "devnet";
  let web3;
  try { web3 = await import("@solana/web3.js"); } catch { fail(2, "oath init needs @solana/web3.js: run `npm install` in this repository first."); }
  const { Keypair, Connection, LAMPORTS_PER_SOL } = web3;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  let kp;
  if (existsSync(out)) {
    kp = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(out, "utf8"))));
    console.log(`Using the existing key: ${out}`);
  } else {
    kp = Keypair.generate();
    mkdirSync(dirname(out), { recursive: true });
    writeFileSync(out, JSON.stringify(Array.from(kp.secretKey)), { mode: 0o600 });
    console.log(`Created ${approver ? "an approver" : "a CI"} key: ${out}   (never printed; keep it out of git and chat)`);
    try { // keep the key out of git
      const gi = ".gitignore";
      const entry = dirname(out) === "." ? out : dirname(out).split("/")[0] + "/";
      const cur = existsSync(gi) ? readFileSync(gi, "utf8") : "";
      if (!cur.split("\n").includes(entry)) appendFileSync(gi, (cur && !cur.endsWith("\n") ? "\n" : "") + entry + "\n");
    } catch { /* not fatal */ }
  }
  const pub = kp.publicKey.toBase58();
  console.log(`\nPublic key (${approver ? "the approver key, safe to share" : "OATH_SIGNER, safe to share"}):\n  ${pub}\n`);

  const rpcUrl = resolveRpc({ rpc: arg("rpc"), network });
  const conn = new Connection(rpcUrl, { commitment: "confirmed", disableRetryOnRateLimit: true }); // fail fast: the public faucet is often rate-limited
  const bal = async () => { try { return (await conn.getBalance(kp.publicKey)) / LAMPORTS_PER_SOL; } catch { return 0; } };
  let funded = (await bal()) >= 0.001;

  if (!funded && network === "devnet") {
    for (const sol of [1, 0.5, 0.1]) {
      try {
        const sig = await conn.requestAirdrop(kp.publicKey, sol * LAMPORTS_PER_SOL);
        await conn.confirmTransaction(sig, "confirmed");
        console.log(`Devnet airdrop: ${sol} SOL received.`);
        funded = true;
        break;
      } catch { /* the public faucet is often rate-limited */ }
    }
  }
  if (!funded) {
    const faucet = network === "devnet" ? "https://faucet.solana.com (choose devnet, paste the public key above)" : "any wallet or exchange (mainnet needs real SOL, about 0.01 is plenty)";
    console.log(`The key has no SOL yet. Fund it via ${faucet}.`);
    if (!flag("no-wait")) {
      console.log("Waiting for the balance (Ctrl+C to skip; run this command again later to continue)…");
      for (let i = 0; i < 120 && !funded; i++) { await sleep(5000); funded = (await bal()) >= 0.001; }
      console.log(funded ? "Funds received." : "Still no balance. Fund the key, then run `oath init` again.");
    }
  }

  const say = (...lines) => console.log(lines.join("\n"));
  if (approver) {
    say("\nNext steps. This key stays OFF GitHub: putting it in CI secrets would defeat the quorum.",
      "",
      "1  Trust both keys",
      `     oath verify --signer <ciKey>,${pub} --quorum 2 …`,
      `     webhook:  OATH_SIGNER=<ciKey>,${pub}  OATH_QUORUM=2`,
      "",
      "2  Approve each build with this key",
      `     SOLANA_SECRET_KEY="$(cat ${out})" oath anchor --image ghcr.io/me/app --digest sha256:…`,
      "   or from a browser wallet, no key file needed:",
      "     https://tymofii-thc.github.io/oath/approve.html",
      "",
      "3  Keep the key file off CI and off shared machines.");
    process.exit(funded ? 0 : 1);
  }

  let ghDone = false;
  if (flag("set-github")) {
    try {
      execFileSync("gh", ["secret", "set", "SOLANA_SECRET_KEY"], { input: readFileSync(out), stdio: ["pipe", "inherit", "inherit"] });
      execFileSync("gh", ["variable", "set", "OATH_SIGNER", "--body", pub], { stdio: "inherit" });
      ghDone = true;
    } catch { /* gh failed or is not logged in: the manual steps below still apply */ }
  }
  say("\nNext steps", "",
    ghDone ? "1  GitHub secret and variable: done (through the GitHub CLI)" : "1  Add to your GitHub repo (Settings → Secrets and variables → Actions)",
    ...(ghDone ? [] : [
      `     secret    SOLANA_SECRET_KEY   the contents of ${out}`,
      `     variable  OATH_SIGNER         ${pub}`,
      "   or in one go:",
      `     gh secret set SOLANA_SECRET_KEY < ${out} && gh variable set OATH_SIGNER --body ${pub}`]),
    "",
    "2  After the image build, record the digest",
    "     - uses: Tymofii-thc/oath@main",
    "       with:",
    "         image: ghcr.io/${{ github.repository }}",
    "         digest: ${{ steps.build.outputs.digest }}",
    "         secret-key: ${{ secrets.SOLANA_SECRET_KEY }}",
    "",
    "3  Before deploy, verify",
    "     - uses: Tymofii-thc/oath/verify@main",
    "       with:",
    "         signer: ${{ vars.OATH_SIGNER }}",
    "         image: ghcr.io/${{ github.repository }}:latest",
    "",
    "Not on GitHub? `oath anchor` and `oath verify` are plain commands: https://github.com/Tymofii-thc/oath/tree/main/examples",
    "",
    "Recommended: a second approver key, so a stolen CI key alone is not enough.",
    "     oath init --approver");
  process.exit(funded ? 0 : 1);
}

// options: [flag, description] pairs, padded to one column per command
const help = (title, usage, options, extra = []) => {
  const w = Math.max(...options.map(([f]) => f.length));
  return [title, "", `Usage: ${usage}`, "", ...options.map(([f, d]) => `  ${f.padEnd(w)}  ${d}`), ...(extra.length ? ["", ...extra] : [])];
};
const NETWORK = [
  ["--network <name>", "devnet (default) or mainnet"],
  ["--rpc <url>", "use this Solana RPC instead (comma-separate several for failover; or SOLANA_RPC)"],
];
const HELP = {
  init: help("oath init: create a CI key, fund it on devnet, print the setup steps",
    "oath init [--approver] [--out <file>] [--set-github] [--no-wait]", [
      ["--approver", "make the second key for --quorum 2 instead (it must stay out of CI secrets)"],
      ["--out <file>", "where to write the key (default .oath/ci-key.json, or .oath/approver-key.json)"],
      ["--set-github", "also set the GitHub secret and variable (needs the gh CLI, logged in)"],
      ["--no-wait", "do not wait for the key to be funded"],
      ...NETWORK]),
  anchor: help("oath anchor: record a built image on Solana. Run it in CI right after the build.",
    "oath anchor --image <ref> [--digest sha256:…] [--commit <sha>] [--key-file <file>]", [
      ["--image <ref>", "image name, e.g. ghcr.io/me/app:latest (the digest of the local docker copy, else the registry's)"],
      ["--digest sha256:…", "use this digest instead of asking the registry"],
      ["--commit <sha>", "default: GITHUB_SHA, BUILD_SOURCEVERSION, CI_COMMIT_SHA, or the current git commit"],
      ["--dry-run", "print the record that would be written and stop (no key needed)"],
      ["--key-file <file>", "the signing key; default: the SOLANA_SECRET_KEY environment variable"],
      ...NETWORK],
    ['Private registry: OATH_REGISTRY_AUTH=\'{"host":{"username":"u","password":"p"}}\'']),
  verify: help("oath verify: is this image one your pipeline built? Run it before deploy.",
    "oath verify --signer <pubkey> (--image <ref> | --digest sha256:… | --container <name>)", [
      ["--signer <key[,key]>", "public key(s) of the CI signer; several accept a key rotation (or OATH_SIGNER)"],
      ["--image <ref>", "repo@sha256:… needs nothing else; a tag is looked up in the registry, with the local docker copy only as a fallback"],
      ["--digest sha256:…", "check a digest directly (the image name is not checked)"],
      ["--container <name>", "the image a running docker container uses"],
      ["--quorum <N>", "at least N different signers must have recorded it"],
      ["--max-age <days>", "ignore records older than this"],
      ["--attest <owner/repo>", "also require the Sigstore build attestation from that repository"],
      ["--no-bind", "do not require the record's image name to match the image"],
      ...NETWORK],
    ["Exit code: 0 verified, 1 not verified (stop the deploy), 2 error"]),
  audit: help("oath audit: check every Pod that is already running in a Kubernetes cluster",
    "oath audit --signer <pubkey> [--in-cluster | --file pods.json] [--skip-namespaces a,b]", [
      ["--signer <key[,key]>", "public key(s) of the CI signer (or OATH_SIGNER)"],
      ["--in-cluster", "read Pods through the Pod's own service account (for a CronJob)"],
      ["--file <pods.json>", "a saved `kubectl get pods -A -o json` (- for stdin)"],
      ["--skip-namespaces a,b", "leave these namespaces out"],
      ["--quorum, --max-age", "as in `oath verify`"],
      ...NETWORK],
    ["Default: the current kubectl context. Exit code: 0 all verified, 1 something is not, 2 error"]),
  revoke: help("oath revoke: mark a digest as bad. It never verifies again, even if it is recorded later.",
    "oath revoke --digest sha256:… [--reason <text>] [--key-file <file>]", [
      ["--digest sha256:…", "the digest to revoke"],
      ["--reason <text>", "shown by verify and audit (up to 100 characters)"],
      ["--key-file <file>", "a trusted signer's key; default: the SOLANA_SECRET_KEY environment variable"],
      ...NETWORK]),
};
const MAIN_HELP = [
  "oath: stop deploys of images your pipeline did not build",
  "",
  "Usage: oath <command> [options]",
  "",
  "Commands",
  "  init     create a CI key, fund it on devnet, print the setup steps",
  "  anchor   record a built image on Solana (in CI, after the build)",
  "  verify   check an image against the records (before deploy; exit 1 = not verified)",
  "  audit    check every Pod already running in a Kubernetes cluster",
  "  revoke   mark a digest as bad",
  "",
  "`oath <command> --help` lists a command's options.   `oath --version` prints the version.",
  "Docs: https://github.com/Tymofii-thc/oath",
];

const cmd = process.argv[2];
const wantsHelp = process.argv.slice(3).some((a) => a === "--help" || a === "-h");
if (!cmd || cmd === "help" || cmd === "--help" || cmd === "-h") {
  const topic = cmd === "help" ? process.argv[3] : null;
  console.log((topic && HELP[topic] ? HELP[topic] : MAIN_HELP).join("\n"));
  process.exit(0);
}
if (cmd === "--version" || cmd === "-v") {
  console.log(JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version);
  process.exit(0);
}
if (HELP[cmd] && wantsHelp) {
  console.log(HELP[cmd].join("\n"));
  process.exit(0);
}
if (cmd === "verify") {
  await verify();
} else if (cmd === "audit") {
  await audit();
} else if (cmd === "init") {
  await init();
} else if (cmd === "revoke") {
  await revoke();
} else if (cmd === "anchor") {
  await anchor();
} else {
  console.error(`Unknown command "${cmd}".\n\n${MAIN_HELP.join("\n")}`);
  process.exit(2);
}
