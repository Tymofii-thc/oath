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
