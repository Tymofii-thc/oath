// Verifies the SLSA build-provenance attestation that GitHub (Sigstore, keyless) issued for an image digest.
// Checks, in order: the bundle's signature chain + transparency log (sigstore), the signing identity (GitHub Actions of the
// expected repository), and that the signed statement is about exactly this digest (and image, if given).
import { repoName } from "./oath.mjs";

const ISSUER = "https://token.actions.githubusercontent.com";
const SLSA = "https://slsa.dev/provenance/";

export async function fetchBundles(repo, digest, { token = process.env.GITHUB_TOKEN, fetchImpl = fetch } = {}) {
  const r = await fetchImpl(`https://api.github.com/repos/${repo}/attestations/${digest}`, {
    headers: { accept: "application/vnd.github+json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
  });
  if (r.status === 404) return [];
  if (!r.ok) throw new Error(`GitHub attestations API: HTTP ${r.status}`);
  const j = await r.json();
  return (j.attestations || []).map((a) => a.bundle).filter(Boolean);
}

// What to require of the signing identity. The spec is `owner/repo` (any workflow of that repository, any ref: the old, loose form),
// or `owner/repo/<workflow>@<ref>` to pin the exact workflow file and the exact ref that must have built the image, e.g.
//   me/app/.github/workflows/deploy.yml@refs/heads/main     (a bare file name is taken to be under .github/workflows/)
//   me/app@refs/heads/main                                  (any workflow, but only built from main)
// Pinning matters: with the loose form, anyone who can push a branch or add a workflow to the repository gets a valid attestation.
export function parseAttestSpec(spec) {
  const m = String(spec || "").trim().match(/^([^/@\s]+\/[^/@\s]+)(?:\/([^@\s]+))?(?:@(\S+))?$/);
  if (!m) throw new Error(`bad attestation requirement "${spec}": expected owner/repo, owner/repo/workflow.yml@refs/heads/main or owner/repo@refs/heads/main`);
  let [, repo, workflow, ref] = m;
  if (workflow && !workflow.includes("/")) workflow = `.github/workflows/${workflow}`;
  if (ref && !ref.startsWith("refs/")) throw new Error(`bad attestation ref "${ref}": write the full ref, for example refs/heads/main or refs/tags/v1.0.0`);
  return { repo, workflow: workflow || null, ref: ref || null };
}

// -> { ok: true, identity, workflow, ref } | { ok: false, reason }.  `repo` is the spec described above (a plain owner/repo works as before).
export async function verifyAttestation({ digest, image, repo: spec, token, fetchImpl, verifyImpl }) {
  const { repo, workflow: wantWorkflow, ref: wantRef } = parseAttestSpec(spec);
  let verify = verifyImpl;
  if (!verify) {
    try { ({ verify } = await import("sigstore")); }
    catch { throw new Error("attestation check needs the 'sigstore' package (npm install sigstore)"); }
  }
  const bundles = await fetchBundles(repo, digest, { token, fetchImpl });
  if (!bundles.length) return { ok: false, reason: `no build attestation found for ${digest} in ${repo}` };

  const wantHex = digest.replace(/^sha256:/, "");
  const wantRepo = repoName(image);
  const prefix = `https://github.com/${repo}/.github/workflows/`.toLowerCase();
  let lastReason = "no attestation matched";
  for (const bundle of bundles) {
    let stmt;
    try { stmt = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, "base64").toString("utf8")); }
    catch { lastReason = "unreadable attestation payload"; continue; }
    if (!String(stmt.predicateType || "").startsWith(SLSA)) { lastReason = `unexpected predicate ${stmt.predicateType}`; continue; }
    const subject = (stmt.subject || []).find((s) => s.digest?.sha256 === wantHex && (!wantRepo || repoName(s.name) === wantRepo));
    if (!subject) { lastReason = "attestation is about a different digest or image"; continue; }
    let signer;
    try { signer = await verify(bundle, { certificateIssuer: ISSUER }); }
    catch (e) { lastReason = `signature/transparency-log verification failed: ${e.message}`; continue; }
    const san = signer?.identity?.subjectAlternativeName || "";
    if (!san.toLowerCase().startsWith(prefix)) { lastReason = `built by an unexpected identity: ${san || "unknown"}`; continue; }
    // https://github.com/<owner>/<repo>/<workflow path>@<ref>: the workflow path never contains "@", the ref may
    const rest = san.slice(`https://github.com/${repo}/`.length);
    const at = rest.indexOf("@");
    const gotWorkflow = at < 0 ? rest : rest.slice(0, at);
    const gotRef = at < 0 ? "" : rest.slice(at + 1);
    if (wantWorkflow && gotWorkflow !== wantWorkflow) { lastReason = `built by workflow ${gotWorkflow || "unknown"}, but ${wantWorkflow} is required`; continue; }
    if (wantRef && gotRef !== wantRef) { lastReason = `built from ${gotRef || "an unknown ref"}, but ${wantRef} is required`; continue; }
    return { ok: true, identity: san, workflow: rest, ref: gotRef };
  }
  return { ok: false, reason: lastReason };
}
