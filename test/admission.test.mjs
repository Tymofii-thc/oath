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

// signed approvals in a folder (a mounted ConfigMap): the webhook decides offline, it never asks the chain
import { mkdtempSync as mkd, writeFileSync as wf } from "node:fs";
import { tmpdir as td } from "node:os";
import { join as jn } from "node:path";
import { generateKeyPairSync } from "node:crypto";
import { b58encode, approvalMessage, revocationMessage, signMessage } from "../lib/approval.mjs";

function human() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32), pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  return { secret: Buffer.concat([seed, pub]), pub: b58encode(pub) };
}
const approvalsDeps = { ...deps, findRecord: async () => { throw new Error("the chain must not be asked in approvals mode"); } };

test("approvals mode: a digest approved by the trusted key is admitted, anything else is denied, with no chain lookup", async () => {
  const h = human(), other = human(), dir = mkd(jn(td(), "oath-appr-"));
  const sign = (k, o = {}) => signMessage(approvalMessage({ image: "ghcr.io/me/app", digest: D1, commit: "0123456789ab", ...o }), k.secret);
  wf(jn(dir, "a.json"), JSON.stringify(sign(h)));
  wf(jn(dir, "b.json"), JSON.stringify(signMessage(approvalMessage({ image: "ghcr.io/me/evil", digest: D2, commit: "0123456789ab" }), other.secret))); // valid signature, key not trusted
  const handler = makeHandler({ signers: [h.pub], rpcUrl: "x", approvalsDir: dir, deps: approvalsDeps });
  assert.equal((await handler(pod(["ghcr.io/me/app:v1"]), "verdict")).response.allowed, true);
  const bad = await handler(pod(["ghcr.io/me/evil:latest"]), "verdict");
  assert.equal(bad.response.allowed, false);
  assert.match(bad.response.status.message, /no valid approval/);
});

test("approvals mode: expired approvals and revocations are honoured, and new files are picked up", async () => {
  const h = human(), dir = mkd(jn(td(), "oath-appr-"));
  wf(jn(dir, "old.json"), JSON.stringify(signMessage(approvalMessage({ image: "ghcr.io/me/app", digest: D1, commit: "0123456789ab", approved: new Date("2020-01-01T00:00:00Z"), days: 30 }), h.secret)));
  const handler = makeHandler({ signers: [h.pub], rpcUrl: "x", cacheMs: 0, approvalsDir: dir, deps: approvalsDeps });
  const expired = await handler(pod(["ghcr.io/me/app:v1"]), "verdict");
  assert.equal(expired.response.allowed, false);
  assert.match(expired.response.status.message, /expired/);
});

test("approvals mode cannot be combined with --max-age", () => {
  assert.throws(() => makeHandler({ signers: ["S"], rpcUrl: "x", approvalsDir: "/tmp", maxAgeSeconds: 5, deps }), /expiry/);
});

test("approvals mode has no result cache: a new approval and a revocation count at once", async () => {
  const h = human(), dir = mkd(jn(td(), "oath-appr-"));
  const handler = makeHandler({ signers: [h.pub], rpcUrl: "x", approvalsDir: dir, deps: approvalsDeps });
  const req = () => handler(pod(["ghcr.io/me/app:v1"]), "verdict");
  assert.equal((await req()).response.allowed, false, "nothing approved yet");
  wf(jn(dir, "a.json"), JSON.stringify(signMessage(approvalMessage({ image: "ghcr.io/me/app", digest: D1, commit: "0123456789ab" }), h.secret)));
  await new Promise((r) => setTimeout(r, 5200)); // the folder listing is re-read every 5 s
  assert.equal((await req()).response.allowed, true, "the miss was not remembered");
  wf(jn(dir, "r.json"), JSON.stringify(signMessage(revocationMessage({ digest: D1, reason: "bad" }), h.secret)));
  await new Promise((r) => setTimeout(r, 5200));
  const after = await req();
  assert.equal(after.response.allowed, false);
  assert.match(after.response.status.message, /revoked by/);
});
