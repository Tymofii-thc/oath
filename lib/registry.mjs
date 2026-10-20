// Minimal OCI registry client: resolve "repo:tag" to its manifest digest (what the kubelet will pull).
const ACCEPT = [
  "application/vnd.oci.image.index.v1+json",
  "application/vnd.docker.distribution.manifest.list.v2+json",
  "application/vnd.oci.image.manifest.v1+json",
  "application/vnd.docker.distribution.manifest.v2+json",
].join(", ");

export function parseRef(ref) {
  let rest = ref;
  let digest = null;
  const at = rest.indexOf("@");
  if (at > -1) { digest = rest.slice(at + 1); rest = rest.slice(0, at); }
  let tag = null;
  const slash = rest.lastIndexOf("/");
  const colon = rest.lastIndexOf(":");
  if (colon > slash) { tag = rest.slice(colon + 1); rest = rest.slice(0, colon); }
  const parts = rest.split("/");
  let registry = "docker.io";
  if (parts.length > 1 && (/[.:]/.test(parts[0]) || parts[0] === "localhost")) registry = parts.shift();
  let repo = parts.join("/");
  if (registry === "docker.io" && !repo.includes("/")) repo = `library/${repo}`;
  return { registry, repo, tag: tag || (digest ? null : "latest"), digest };
}

function apiHost(registry) {
  return registry === "docker.io" ? "registry-1.docker.io" : registry;
}

function scheme(registry) {
  return /^(localhost|127(\.\d{1,3}){3}|\[::1\])(:\d+)?$/.test(registry) || process.env.OATH_INSECURE_REGISTRIES?.split(",").includes(registry) ? "http" : "https";
}

async function bearer(challenge, auth, registry, timeoutMs) {
  const p = Object.fromEntries([...challenge.matchAll(/(\w+)="([^"]*)"/g)].map((m) => [m[1], m[2]]));
  if (!p.realm) throw new Error("registry sent an unusable auth challenge");
  const u = new URL(p.realm);
  if (u.protocol !== "https:" && !(u.protocol === "http:" && scheme(registry) === "http")) throw new Error("registry sent an unusable auth challenge");
  if (p.service) u.searchParams.set("service", p.service);
  if (p.scope) u.searchParams.set("scope", p.scope);
  // credentials only go to the registry's own host (or its token service on the same domain), never to whatever host a challenge names
  const sameSite = u.hostname === apiHost(registry).split(":")[0] || u.hostname.endsWith("." + registry.split(":")[0]) || (registry === "docker.io" && u.hostname === "auth.docker.io");
  const headers = auth && sameSite ? { authorization: "Basic " + Buffer.from(`${auth.username}:${auth.password}`).toString("base64") } : {};
  const r = await fetch(u, { headers, signal: AbortSignal.timeout(timeoutMs) });
  if (!r.ok) throw new Error(`registry token request failed: HTTP ${r.status}`);
  const j = await r.json();
  return j.token || j.access_token;
}

// auths: { "ghcr.io": { username, password } } (optional, for private registries)
export async function resolveDigest(ref, { auths = {}, timeoutMs = 10000 } = {}) {
  const { registry, repo, tag, digest } = parseRef(ref);
  if (digest) return digest.toLowerCase();
  const allowed = (process.env.OATH_ALLOWED_REGISTRIES || "").split(",").map((x) => x.trim()).filter(Boolean);
  if (allowed.length && !allowed.includes(registry)) throw new Error(`registry ${registry} is not in OATH_ALLOWED_REGISTRIES`);
  const url = `${scheme(registry)}://${apiHost(registry)}/v2/${repo}/manifests/${tag}`;
  const auth = auths[registry];
  const attempt = (headers) =>
    fetch(url, { method: "HEAD", headers: { accept: ACCEPT, ...headers }, signal: AbortSignal.timeout(timeoutMs) });

  let r = await attempt(auth ? { authorization: "Basic " + Buffer.from(`${auth.username}:${auth.password}`).toString("base64") } : {});
  if (r.status === 401) {
    const ch = r.headers.get("www-authenticate") || "";
    if (/^bearer/i.test(ch)) r = await attempt({ authorization: `Bearer ${await bearer(ch, auth, registry, timeoutMs)}` });
  }
  if (!r.ok) throw new Error(`cannot resolve ${ref}: registry answered HTTP ${r.status}`);
  const d = r.headers.get("docker-content-digest");
  if (!d || !/^sha256:[0-9a-f]{64}$/.test(d)) throw new Error(`cannot resolve ${ref}: registry returned no digest`);
  return d;
}
