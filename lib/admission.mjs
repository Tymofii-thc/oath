// Kubernetes AdmissionReview handler: allow a Pod only if every image was anchored by the pipeline.
import { findRecord, repoName } from "./oath.mjs";
import { parseRef, resolveDigest } from "./registry.mjs";
import { verifyAttestation, parseAttestSpec } from "./attest.mjs";

// Slots are matched by path, so on UPDATE only images that are new or changed are checked (a bare Pod's image can be edited in place,
// and `kubectl debug` adds an ephemeral container).
function containerSlots(pod) {
  const spec = pod?.spec || {};
  const out = [];
  for (const key of ["initContainers", "containers", "ephemeralContainers"]) {
    (spec[key] || []).forEach((c, i) => out.push({ path: `/spec/${key}/${i}/image`, image: c.image }));
  }
  return out;
}

export function makeHandler({ signers, rpcUrl, maxAgeSeconds, quorum = 1, attestRepo, mode = "enforce", pin = true, auths = {}, cacheMs = 300000, staleMs = 0, limit = 1000, deadlineMs = 0, programId, deps = {} }) {
  if (programId && maxAgeSeconds) throw new Error("OATH_MAX_AGE_DAYS does not work with OATH_PROGRAM yet: an on-chain record has no trustworthy age, and a security setting that is silently ignored would be worse than refusing to start");
  if (attestRepo) parseAttestSpec(attestRepo); // a malformed requirement must stop the start, not deny every Pod later
  const resolve = deps.resolveDigest || resolveDigest;
  // --program (experimental, README: "On-chain records"): one account per signer+digest instead of a Memo
  // scan, closing the revocation-eviction-by-spam gap in THREAT-MODEL.md. Lazily imported: @solana/web3.js
  // is an optional dependency, and most installs never set OATH_PROGRAM.
  const find = deps.findRecord
    || (deps.findPda && (async (opts) => deps.findPda({ ...opts, programId })))
    || (programId && (async (opts) => (await import("./pda.mjs")).findPda({ ...opts, programId })))
    || findRecord;
  const attest = deps.verifyAttestation || verifyAttestation;
  const stats = { lookups: 0, cache_hits: 0, stale_admits: 0, lookup_errors: 0 };
  const cache = new Map(); // `${repo}@${digest}` -> { rec, exp }; capped, oldest entries dropped first

  // staleMs: if the RPC is unreachable, a digest that was VERIFIED within the last staleMs is still admitted (records are
  // immutable; the only thing this can miss is a revocation made during the outage). 0 disables it (strictly fail closed).
  const inflight = new Map(); // concurrent checks of the same image share one lookup (a Deployment with 50 replicas = 1 RPC scan, not 50)
  function check(image) {
    const k = image;
    if (!inflight.has(k)) inflight.set(k, checkOnce(image).finally(() => inflight.delete(k)));
    return inflight.get(k);
  }

  async function checkOnce(image) {
    const digest = await resolve(image, { auths });
    const repo = repoName(image);
    const key = `${repo}@${digest}`;
    const hit = cache.get(key);
    if (hit && hit.exp > Date.now()) { stats.cache_hits++; return { digest, rec: hit.rec, why: hit.why }; }
    stats.lookups++;
    let rec;
    let why = "";
    try {
      rec = await find({ signers, digest, rpcUrl, image, maxAgeSeconds, quorum, limit });
      if (rec && attestRepo) {
        const att = await attest({ digest, image, repo: attestRepo });
        if (!att.ok) { rec = null; why = `anchored, but build attestation failed: ${att.reason}`; }
      }
    } catch (e) {
      stats.lookup_errors++;
      if (hit && hit.rec && staleMs > 0 && Date.now() - hit.at < staleMs) {
        console.warn(`oath: lookup failed (${e.message}); admitting ${key} from a verification ${Math.round((Date.now() - hit.at) / 1000)}s old`);
        stats.stale_admits++;
        return { digest, rec: hit.rec, why: "" };
      }
      throw e;
    }
    if (cache.size >= 5000) cache.delete(cache.keys().next().value);
    cache.set(key, { rec, why, exp: Date.now() + (rec ? cacheMs : 15000), at: rec ? Date.now() : hit?.at || 0 }); // a miss is re-checked soon: the build may just have been anchored
    return { digest, rec, why };
  }

  // phase: "verdict" = only decide (ValidatingWebhook: it sees the Pod after every mutating webhook has run);
  //        "pin"     = only rewrite tags to digests and always allow (MutatingWebhook, reinvoked after other mutators);
  //        "all"     = both in one call (the old single webhook, kept so a half-upgraded install keeps working).
  const review = async function review(body, phase = "all") {
    const req = body?.request;
    const uid = req?.uid || "";
    const respond = (allowed, message, patch, warnings) => ({
      apiVersion: "admission.k8s.io/v1",
      kind: "AdmissionReview",
      response: {
        uid,
        allowed,
        ...(message ? { status: { code: allowed ? 200 : 403, message } } : {}),
        ...(warnings?.length ? { warnings } : {}),
        ...(patch?.length ? { patchType: "JSONPatch", patch: Buffer.from(JSON.stringify(patch)).toString("base64") } : {}),
      },
    });
    if (!req || req.kind?.kind !== "Pod") return respond(true);

    const patch = [];
    const failures = [];
    if (phase === "pin") {
      // pinning is not a gate: a tag that cannot be resolved is left alone and the verdict phase decides about it
      const before = req.operation === "UPDATE" ? new Map(containerSlots(req.oldObject).map((x) => [x.path, x.image])) : new Map();
      if (pin) {
        for (const slot of containerSlots(req.object)) {
          if (before.get(slot.path) === slot.image || !slot.image || parseRef(slot.image).digest) continue;
          try { patch.push({ op: "replace", path: slot.path, value: `${slot.image.replace(/:[^:/@]+$/, "")}@${await resolve(slot.image, { auths })}` }); } catch { /* the verdict phase reports it */ }
        }
      }
      return respond(true, null, patch);
    }
    const before = req.operation === "UPDATE" ? new Map(containerSlots(req.oldObject).map((x) => [x.path, x.image])) : new Map();
    for (const slot of containerSlots(req.object)) {
      if (before.get(slot.path) === slot.image) continue; // unchanged since it was admitted
      try {
        const { digest, rec, why } = await check(slot.image);
        if (!rec) {
          failures.push(`${slot.image} (${digest}): ${why || `no pipeline build anchored by ${quorum > 1 ? `${quorum} of ` : ""}the trusted signer(s)`}`);
        } else if (phase === "all" && pin && !parseRef(slot.image).digest) {
          patch.push({ op: "replace", path: slot.path, value: `${slot.image.replace(/:[^:/@]+$/, "")}@${digest}` });
        }
      } catch (e) {
        failures.push(`${slot.image}: ${e.message}`); // can't verify => don't run (fail closed)
      }
    }

    if (failures.length) {
      const msg = `oath: refusing to admit pod. ${failures.join("; ")}`;
      return mode === "audit" ? respond(true, null, null, [msg]) : respond(false, msg);
    }
    return respond(true, null, patch);
  };
  // The API server gives up on a webhook after its own timeout and then reports an opaque "failed calling webhook". Answering first,
  // with the reason, is clearer; the lookup keeps running and fills the cache, so the controller's next attempt is usually instant.
  const withDeadline = async (body, phase = "all") => {
    // pinning must never hold a Pod back for long: it gets a shorter deadline and then simply allows without a patch
    const limitMs = phase === "pin" && deadlineMs ? Math.min(deadlineMs, 5000) : deadlineMs;
    if (!limitMs) return review(body, phase);
    let timer;
    const late = new Promise((resolve) => {
      timer = setTimeout(() => {
        const uid = body?.request?.uid || "";
        if (phase === "pin") return resolve({ apiVersion: "admission.k8s.io/v1", kind: "AdmissionReview", response: { uid, allowed: true } });
        const msg = `oath: verification took longer than ${Math.round(limitMs / 1000)}s (slow or rate-limited RPC/registry); retry shortly`;
        resolve({ apiVersion: "admission.k8s.io/v1", kind: "AdmissionReview", response: mode === "audit" ? { uid, allowed: true, warnings: [msg] } : { uid, allowed: false, status: { code: 403, message: msg } } });
      }, limitMs);
    });
    try { return await Promise.race([review(body, phase), late]); } finally { clearTimeout(timer); }
  };
  withDeadline.stats = stats;
  return withDeadline;
}
