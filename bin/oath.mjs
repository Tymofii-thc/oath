#!/usr/bin/env node
// oath — Proof of Deploy CLI
//
//   oath verify --signer <pubkey[,pubkey…]> --digest sha256:<hex>
//   oath verify --signer <pubkey> --image ghcr.io/me/app:latest      (digest read from local docker)
//   oath verify --signer <pubkey> --container prod                   (digest of the RUNNING image)
//   oath init   [--out .oath/ci-key.json] [--no-wait] [--set-github]      (create a CI key, fund it on devnet, print the next steps)
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

function resolveTarget() {
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
    return pickRepoDigest(docker(["image", "inspect", "--format", fmt, image]), image) || { digest: null };
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

  const { digest: want, repo } = resolveTarget();
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
    if (quorum <= 1) console.error("  note: single-signer verification — whoever holds this signer's key alone can anchor a forged digest; see --quorum in README.");
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

// Marks a digest as bad. Any trusted signer can do it; it takes effect for every later check.
async function revoke() {
  const digest = extractDigest(arg("digest"));
  if (!digest) fail(2, "Missing --digest sha256:<64 hex>.");
  const reason = String(arg("reason") || "").replace(/[|\r\n]+/g, " ").trim().slice(0, 100);
  let secret = process.env.SOLANA_SECRET_KEY;
  if (arg("key-file")) { try { secret = readFileSync(arg("key-file"), "utf8"); } catch (e) { fail(2, `cannot read key file: ${e.message}`); } }
  if (!secret) fail(2, "Provide the signer's secret key: SOLANA_SECRET_KEY='[…]' or --key-file <path>.");
  let rpcUrl;
  try { rpcUrl = resolveRpc({ rpc: arg("rpc"), network: arg("network") }); } catch (e) { fail(2, e.message); }
  const text = `pod1r|${digest}|${reason}|${new Date().toISOString()}`;
  try {
    const out = await sendMemo({ text, secretKey: JSON.parse(secret), rpcUrl });
    console.log(`Revoked: ${text}`);
    console.log(`Signer : ${out.signer}`);
    console.log(`Tx     : ${out.signature}`);
  } catch (e) {
    fail(2, `could not send the revocation: ${e.message}`);
  }
}

// One-command setup: a CI key in a file (the secret is never printed), a funded devnet balance, and the exact next steps.
async function init() {
  const out = arg("out") || ".oath/ci-key.json";
  const network = arg("network") || "devnet";
  let web3;
  try { web3 = await import("@solana/web3.js"); } catch { fail(2, "oath init needs @solana/web3.js: run `npm install` in this repository first."); }
  const { Keypair, Connection, LAMPORTS_PER_SOL } = web3;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  let kp;
  if (existsSync(out)) {
    kp = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(out, "utf8"))));
    console.log(`Using the existing key in ${out}`);
  } else {
    kp = Keypair.generate();
    mkdirSync(dirname(out), { recursive: true });
    writeFileSync(out, JSON.stringify(Array.from(kp.secretKey)), { mode: 0o600 });
    console.log(`Created a CI key in ${out} (permissions 600; keep it out of git and chat)`);
    try { // keep the key out of git
      const gi = ".gitignore";
      const entry = dirname(out).split("/")[0] + "/";
      const cur = existsSync(gi) ? readFileSync(gi, "utf8") : "";
      if (!cur.split("\n").includes(entry)) appendFileSync(gi, (cur && !cur.endsWith("\n") ? "\n" : "") + entry + "\n");
    } catch { /* not fatal */ }
  }
  const pub = kp.publicKey.toBase58();
  console.log(`\nPublic key (this is OATH_SIGNER, safe to share):\n  ${pub}\n`);

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

  console.log("\nNext steps");
  console.log("  1. Add two things to your GitHub repository:");
  console.log(`       secret    SOLANA_SECRET_KEY  = the contents of ${out}`);
  console.log(`       variable  OATH_SIGNER        = ${pub}`);
  let ghDone = false;
  if (flag("set-github")) {
    try {
      execFileSync("gh", ["secret", "set", "SOLANA_SECRET_KEY"], { input: readFileSync(out), stdio: ["pipe", "inherit", "inherit"] });
      execFileSync("gh", ["variable", "set", "OATH_SIGNER", "--body", pub], { stdio: "inherit" });
      ghDone = true;
      console.log("     (done through the GitHub CLI)");
    } catch { console.log("     (gh failed or is not logged in; set them by hand)"); }
  }
  if (!ghDone) {
    console.log(`       with the GitHub CLI:  gh secret set SOLANA_SECRET_KEY < ${out}   &&   gh variable set OATH_SIGNER --body ${pub}`);
    console.log("       or in the browser:    Settings → Secrets and variables → Actions");
  }
  console.log("  2. Record each build, after your image build step:");
  console.log("       - uses: Tymofii-thc/oath@main");
  console.log("         with:");
  console.log("           image: ghcr.io/${{ github.repository }}");
  console.log("           digest: ${{ steps.build.outputs.digest }}");
  console.log("           secret-key: ${{ secrets.SOLANA_SECRET_KEY }}");
  console.log("  3. Verify before deploy:");
  console.log("       - uses: Tymofii-thc/oath/verify@main");
  console.log("         with:");
  console.log("           signer: ${{ vars.OATH_SIGNER }}");
  console.log("           image: ghcr.io/${{ github.repository }}:latest");
  console.log("\nRecommended: close the single-key hole");
  console.log("  Right now, whoever has SOLANA_SECRET_KEY can anchor a forged digest. Create a second, independent");
  console.log("  approver key — kept OUTSIDE CI, e.g. on your own machine, never as a repository secret:");
  console.log(`    node bin/oath.mjs init --out .oath/approver-key.json`);
  console.log("  Then require both: --signer <ciKey>,<approverKey> --quorum 2 (or OATH_QUORUM=2 for the webhook).");
  console.log("  The approver signs each build with their own key (scripts/anchor.mjs) or from a browser wallet");
  console.log("  (verifier/approve.html) — a stolen CI key alone is then not enough. See README: Signer quorum.");
  process.exit(funded ? 0 : 1);
}

const cmd = process.argv[2];
if (cmd === "verify") {
  await verify();
} else if (cmd === "audit") {
  await audit();
} else if (cmd === "init") {
  await init();
} else if (cmd === "revoke") {
  await revoke();
} else {
  console.error("Usage: oath revoke --digest sha256:… --reason <text> [--key-file <path>] [--network …]\n       oath init [--out .oath/ci-key.json] [--no-wait] [--set-github]\n       oath audit --signer <pubkey[,pubkey]> [--file pods.json|-] [--skip-namespaces a,b] [--network …]\n       oath verify --signer <pubkey[,pubkey]> (--digest sha256:… | --image <ref> | --container <name>) [--network devnet|mainnet | --rpc <url>] [--max-age <days>] [--quorum <N>] [--attest <owner/repo>] [--no-bind]");
  process.exit(2);
}
