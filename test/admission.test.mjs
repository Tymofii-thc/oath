import { test } from "node:test";
import assert from "node:assert/strict";
import { makeHandler } from "../lib/admission.mjs";
import { parseRef } from "../lib/registry.mjs";

const D1 = "sha256:" + "a".repeat(64);
const D2 = "sha256:" + "b".repeat(64);
const digests = { "ghcr.io/me/app:v1": D1, "ghcr.io/me/evil:latest": D2, "localhost:5000/x/app": D1 };
const anchored = new Set([D1]);

const deps = {
  resolveDigest: async (ref) => {
    if (ref.includes("@sha256:")) return ref.split("@")[1];
    if (!digests[ref]) throw new Error(`cannot resolve ${ref}`);
    return digests[ref];
  },
  findRecord: async ({ digest }) => (anchored.has(digest) ? { signature: "s" } : null),
};
const pod = (images, kind = "Pod") => ({
  request: { uid: "u1", kind: { kind }, object: { spec: { containers: images.map((image, i) => ({ name: `c${i}`, image })) } } },
});
const mk = (o = {}) => makeHandler({ signers: ["S"], rpcUrl: "x", deps, ...o });
const patchOf = (r) => JSON.parse(Buffer.from(r.response.patch, "base64"));

test("allows anchored image and pins tag to digest", async () => {
  const r = await mk()(pod(["ghcr.io/me/app:v1"]));
  assert.equal(r.response.allowed, true);
  assert.deepEqual(patchOf(r), [{ op: "replace", path: "/spec/containers/0/image", value: `ghcr.io/me/app@${D1}` }]);
});

test("pin keeps registry port intact", async () => {
  const r = await mk()(pod(["localhost:5000/x/app"]));
  assert.equal(patchOf(r)[0].value, `localhost:5000/x/app@${D1}`);
});

test("denies un-anchored image with a reason", async () => {
  const r = await mk()(pod(["ghcr.io/me/evil:latest"]));
  assert.equal(r.response.allowed, false);
  assert.match(r.response.status.message, /no pipeline build anchored/);
});

test("one bad container among good ones denies the pod", async () => {
  const r = await mk()(pod(["ghcr.io/me/app:v1", "ghcr.io/me/evil:latest"]));
  assert.equal(r.response.allowed, false);
});

test("fails closed when the image cannot be resolved", async () => {
  const r = await mk()(pod(["ghcr.io/me/missing:1"]));
  assert.equal(r.response.allowed, false);
});

test("fails closed when the Solana lookup throws", async () => {
  const h = makeHandler({ signers: ["S"], rpcUrl: "x", deps: { ...deps, findRecord: async () => { throw new Error("rpc down"); } } });
  const r = await h(pod(["ghcr.io/me/app:v1"]));
  assert.equal(r.response.allowed, false);
  assert.match(r.response.status.message, /rpc down/);
});

test("already-pinned image is verified but not patched", async () => {
  const r = await mk()(pod([`ghcr.io/me/app@${D1}`]));
  assert.equal(r.response.allowed, true);
  assert.equal(r.response.patch, undefined);
});

test("audit mode allows but warns", async () => {
  const r = await mk({ mode: "audit" })(pod(["ghcr.io/me/evil:latest"]));
  assert.equal(r.response.allowed, true);
  assert.match(r.response.warnings[0], /refusing/);
});

test("non-Pod objects pass through", async () => {
  const r = await mk()(pod(["ghcr.io/me/evil:latest"], "ConfigMap"));
  assert.equal(r.response.allowed, true);
});

test("parseRef", () => {
  assert.deepEqual(parseRef("nginx"), { registry: "docker.io", repo: "library/nginx", tag: "latest", digest: null });
  assert.deepEqual(parseRef("ghcr.io/me/app:v1"), { registry: "ghcr.io", repo: "me/app", tag: "v1", digest: null });
  assert.equal(parseRef(`ghcr.io/me/app@${D1}`).digest, D1);
  assert.equal(parseRef("localhost:5000/x/app").registry, "localhost:5000");
});

test("attestation required: anchored but unattested image is denied, attested one passes", async () => {
  const seen = [];
  const h = makeHandler({ signers: ["S"], rpcUrl: "x", attestRepo: "me/app", deps: { ...deps,
    verifyAttestation: async ({ digest, repo }) => { seen.push(repo); return digest === D1 ? { ok: true } : { ok: false, reason: "no build attestation" }; } } });
  anchored.add(D2);
  try {
    const bad = await h(pod(["ghcr.io/me/evil:latest"]));
    assert.equal(bad.response.allowed, false);
    assert.match(bad.response.status.message, /build attestation failed: no build attestation/);
    const good = await h(pod(["ghcr.io/me/app:v1"]));
    assert.equal(good.response.allowed, true);
  } finally { anchored.delete(D2); }
  assert.deepEqual(seen, ["me/app", "me/app"]);
});

test("quorum is passed to the lookup", async () => {
  let got;
  const h = makeHandler({ signers: ["A", "B"], rpcUrl: "x", quorum: 2, deps: { ...deps, findRecord: async (o) => { got = o.quorum; return null; } } });
  const r = await h(pod(["ghcr.io/me/app:v1"]));
  assert.equal(got, 2);
  assert.match(r.response.status.message, /2 of the trusted signer/);
});

test("RPC outage: a digest verified recently is still admitted (stale cache); an unknown one is denied", async () => {
  let down = false;
  const h = makeHandler({ signers: ["S"], rpcUrl: "x", cacheMs: 1, staleMs: 60000,
    deps: { ...deps, findRecord: async (o) => { if (down) throw new Error("rpc down"); return anchored.has(o.digest) ? { signature: "s" } : null; } } });
  assert.equal((await h(pod(["ghcr.io/me/app:v1"]))).response.allowed, true, "verified while the RPC is up");
  await new Promise((r) => setTimeout(r, 5)); // cache entry expires
  down = true;
  assert.equal((await h(pod(["ghcr.io/me/app:v1"]))).response.allowed, true, "served from the recent verification");
  const unknown = await h(pod(["ghcr.io/me/evil:latest"]));
  assert.equal(unknown.response.allowed, false, "never seen before: fail closed");
  assert.match(unknown.response.status.message, /rpc down/);
});

test("RPC outage with stale cache disabled (staleMs 0) is strictly fail closed", async () => {
  let down = false;
  const h = makeHandler({ signers: ["S"], rpcUrl: "x", cacheMs: 1, staleMs: 0,
    deps: { ...deps, findRecord: async (o) => { if (down) throw new Error("rpc down"); return { signature: "s" }; } } });
  assert.equal((await h(pod(["ghcr.io/me/app:v1"]))).response.allowed, true);
  await new Promise((r) => setTimeout(r, 5)); down = true;
  assert.equal((await h(pod(["ghcr.io/me/app:v1"]))).response.allowed, false);
});

test("a stale verification expires: after staleMs the pod is denied again", async () => {
  let down = false;
  const h = makeHandler({ signers: ["S"], rpcUrl: "x", cacheMs: 1, staleMs: 20,
    deps: { ...deps, findRecord: async () => { if (down) throw new Error("rpc down"); return { signature: "s" }; } } });
  await h(pod(["ghcr.io/me/app:v1"]));
  await new Promise((r) => setTimeout(r, 40)); down = true;
  assert.equal((await h(pod(["ghcr.io/me/app:v1"]))).response.allowed, false);
});

test("UPDATE: swapping the image of a running Pod is checked; unchanged images are not", async () => {
  const mkpod = (image, extra = {}) => ({ spec: { containers: [{ name: "c0", image }] }, ...extra });
  const h = mk();
  // image edited to an un-anchored one: denied
  const bad = await h({ request: { uid: "u", kind: { kind: "Pod" }, operation: "UPDATE", oldObject: mkpod(`ghcr.io/me/app@${D1}`), object: mkpod("ghcr.io/me/evil:latest") } });
  assert.equal(bad.response.allowed, false);
  // metadata-only update: images are the same, nothing is looked up, admitted
  const same = await h({ request: { uid: "u", kind: { kind: "Pod" }, operation: "UPDATE", oldObject: mkpod("ghcr.io/me/evil:latest"), object: mkpod("ghcr.io/me/evil:latest") } });
  assert.equal(same.response.allowed, true);
  // image edited to an anchored one: admitted
  const good = await h({ request: { uid: "u", kind: { kind: "Pod" }, operation: "UPDATE", oldObject: mkpod(`ghcr.io/me/app@${D1}`), object: mkpod("ghcr.io/me/app:v1") } });
  assert.equal(good.response.allowed, true);
});

test("UPDATE: a new ephemeral container (kubectl debug) is checked", async () => {
  const base = { spec: { containers: [{ name: "c0", image: `ghcr.io/me/app@${D1}` }] } };
  const withDebug = { spec: { ...base.spec, ephemeralContainers: [{ name: "dbg", image: "ghcr.io/me/evil:latest" }] } };
  const r = await mk()({ request: { uid: "u", kind: { kind: "Pod" }, operation: "UPDATE", oldObject: base, object: withDebug } });
  assert.equal(r.response.allowed, false);
});

test("concurrent pods with the same image share one lookup", async () => {
  let lookups = 0;
  const h = makeHandler({ signers: ["S"], rpcUrl: "x", deps: { ...deps, findRecord: async ({ digest }) => { lookups++; await new Promise((r) => setTimeout(r, 30)); return anchored.has(digest) ? { signature: "s" } : null; } } });
  const rs = await Promise.all(Array.from({ length: 50 }, () => h(pod(["ghcr.io/me/app:v1"]))));
  assert.ok(rs.every((r) => r.response.allowed));
  assert.equal(lookups, 1);
});

test("a slow lookup is answered with a clear denial before the API server's timeout, and still fills the cache", async () => {
  let done = 0;
  const slow = { ...deps, findRecord: async ({ digest }) => { await new Promise((r) => setTimeout(r, 120)); done++; return anchored.has(digest) ? { signature: "s" } : null; } };
  const h = makeHandler({ signers: ["S"], rpcUrl: "x", deadlineMs: 40, deps: slow });
  const r1 = await h(pod(["ghcr.io/me/app:v1"]));
  assert.equal(r1.response.allowed, false);
  assert.match(r1.response.status.message, /took longer than/);
  await new Promise((r) => setTimeout(r, 150)); // the lookup finished in the background
  const r2 = await h(pod(["ghcr.io/me/app:v1"]));
  assert.equal(r2.response.allowed, true);
  assert.equal(done, 1, "the second request was served from the cache");
  const audit = await makeHandler({ signers: ["S"], rpcUrl: "x", deadlineMs: 40, mode: "audit", deps: slow })(pod(["ghcr.io/me/evil:latest"]));
  assert.equal(audit.response.allowed, true);
  assert.ok(audit.response.warnings[0].includes("took longer"));
});

// --- OATH_PROGRAM / --program: the experimental account-based backend (lib/pda.mjs), stubbed via deps.findPda
// so this stays an offline unit test; test/pda-local-validator.mjs and test/e2e-pda.sh exercise the real thing.
test("programId routes lookups through deps.findPda instead of the Memo backend", async () => {
  let calls = 0;
  const findPda = async ({ digest, programId }) => { calls++; assert.equal(programId, "Prog1111"); return digest === D1 ? { signature: "onchain" } : null; };
  const h = makeHandler({ signers: ["S"], rpcUrl: "x", programId: "Prog1111", deps: { resolveDigest: deps.resolveDigest, findPda } });
  const ok = await h(pod(["ghcr.io/me/app:v1"]));
  assert.equal(ok.response.allowed, true);
  assert.equal(calls, 1);
  const bad = await h(pod(["ghcr.io/me/evil:latest"]));
  assert.equal(bad.response.allowed, false);
});

test("without programId, the Memo backend is used even if deps.findPda is given (it should never be called)", async () => {
  const findPda = async () => { throw new Error("must not be called"); };
  const h = makeHandler({ signers: ["S"], rpcUrl: "x", deps: { resolveDigest: deps.resolveDigest, findRecord: deps.findRecord, findPda } });
  const r = await h(pod(["ghcr.io/me/app:v1"]));
  assert.equal(r.response.allowed, true);
});

test("OATH_MAX_AGE_DAYS together with OATH_PROGRAM refuses to start instead of being silently ignored", () => {
  assert.throws(() => makeHandler({ signers: ["S"], rpcUrl: "http://x", maxAgeSeconds: 86400, programId: "Prog11111111111111111111111111111111111111" }), /OATH_MAX_AGE_DAYS does not work with OATH_PROGRAM/);
  assert.doesNotThrow(() => makeHandler({ signers: ["S"], rpcUrl: "http://x", programId: "Prog11111111111111111111111111111111111111" }));
});

// The verdict and the pinning are two webhooks: the ValidatingWebhook decides on the final Pod, the MutatingWebhook only pins.
test("verdict phase: denies an un-anchored image and never patches", async () => {
  const h = mk();
  const bad = await h(pod(["ghcr.io/me/evil:latest"]), "verdict");
  assert.equal(bad.response.allowed, false);
  const ok = await h(pod(["ghcr.io/me/app:v1"]), "verdict");
  assert.equal(ok.response.allowed, true);
  assert.equal(ok.response.patch, undefined, "a validating webhook cannot and must not mutate");
});

test("verdict phase checks the image as another mutating webhook left it, not as it was submitted", async () => {
  // the Pod the verdict phase sees already carries the digest that a sidecar injector or a pin put there
  const swapped = pod([`ghcr.io/me/evil@${D2}`]);
  assert.equal((await mk()(swapped, "verdict")).response.allowed, false);
  assert.equal((await mk()(pod([`ghcr.io/me/app@${D1}`]), "verdict")).response.allowed, true);
});

test("pin phase: pins a tag, never denies, and leaves digests and unresolvable tags alone", async () => {
  const h = mk();
  const tagged = await h(pod(["ghcr.io/me/app:v1"]), "pin");
  assert.equal(tagged.response.allowed, true);
  assert.deepEqual(patchOf(tagged), [{ op: "replace", path: "/spec/containers/0/image", value: `ghcr.io/me/app@${D1}` }]);
  const evil = await h(pod(["ghcr.io/me/evil:latest"]), "pin");
  assert.equal(evil.response.allowed, true, "pinning is not a gate: the verdict phase refuses this one");
  assert.equal(patchOf(evil)[0].value, `ghcr.io/me/evil@${D2}`);
  const pinned = await h(pod([`ghcr.io/me/app@${D1}`]), "pin");
  assert.equal(pinned.response.allowed, true);
  assert.equal(pinned.response.patch, undefined);
  const unknown = await h(pod(["ghcr.io/me/nope:1"]), "pin");
  assert.equal(unknown.response.allowed, true);
  assert.equal(unknown.response.patch, undefined);
});

test("pin phase with pinning switched off patches nothing", async () => {
  const r = await mk({ pin: false })(pod(["ghcr.io/me/app:v1"]), "pin");
  assert.equal(r.response.allowed, true);
  assert.equal(r.response.patch, undefined);
});

test("pin phase never holds a Pod back: a slow registry means allow without a patch", async () => {
  const slow = makeHandler({ signers: ["S"], rpcUrl: "x", deadlineMs: 50, deps: { ...deps, resolveDigest: () => new Promise(() => {}) } });
  const t0 = Date.now();
  const r = await slow(pod(["ghcr.io/me/app:v1"]), "pin");
  assert.equal(r.response.allowed, true);
  assert.ok(Date.now() - t0 < 1000);
  const v = await slow(pod(["ghcr.io/me/app:v1"]), "verdict");
  assert.equal(v.response.allowed, false, "the verdict phase still fails closed on a timeout");
});

test("a malformed attestation requirement stops the handler from being built", () => {
  assert.throws(() => makeHandler({ signers: ["S"], rpcUrl: "x", attestRepo: "me/app@main", deps }), /full ref/);
  assert.doesNotThrow(() => makeHandler({ signers: ["S"], rpcUrl: "x", attestRepo: "me/app/deploy.yml@refs/heads/main", deps }));
});

// Kubernetes ImageVolume: an OCI image mounted as a volume is an image to check as well
const podWithVolume = (reference, extra = {}) => ({
  request: { uid: "u1", kind: { kind: "Pod" }, object: { spec: { containers: [{ name: "c", image: "ghcr.io/me/app:v1" }], volumes: [{ name: "data", image: { reference } }] } }, ...extra },
});

test("an image volume with an un-anchored image is denied", async () => {
  const r = await mk()(podWithVolume("ghcr.io/me/evil:latest"), "verdict");
  assert.equal(r.response.allowed, false);
  assert.match(r.response.status.message, /ghcr\.io\/me\/evil/);
});

test("an anchored image volume is allowed and its tag is pinned like a container's", async () => {
  const r = await mk()(podWithVolume("ghcr.io/me/app:v1"));
  assert.equal(r.response.allowed, true);
  assert.ok(patchOf(r).some((p) => p.path === "/spec/volumes/0/image/reference" && p.value === `ghcr.io/me/app@${D1}`));
});

test("a volume swapped in place on UPDATE is checked, an unchanged one is not", async () => {
  const old = { spec: { containers: [{ name: "c", image: "ghcr.io/me/app:v1" }], volumes: [{ name: "data", image: { reference: "ghcr.io/me/app:v1" } }] } };
  const swapped = podWithVolume("ghcr.io/me/evil:latest", { operation: "UPDATE", oldObject: old });
  assert.equal((await mk()(swapped, "verdict")).response.allowed, false);
  const same = podWithVolume("ghcr.io/me/app:v1", { operation: "UPDATE", oldObject: old });
  assert.equal((await mk()(same, "verdict")).response.allowed, true);
});
