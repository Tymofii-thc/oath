// Core verification logic shared by the CLI (bin/oath.mjs) and the admission webhook (bin/oath-webhook.mjs).
export const NETWORKS = {
  devnet: "https://api.devnet.solana.com",
  mainnet: "https://api.mainnet-beta.solana.com",
};

export function resolveRpc({ rpc, network, env = process.env } = {}) {
  if (rpc) return rpc;
  if (env.SOLANA_RPC) return env.SOLANA_RPC;
  const n = network || env.OATH_NETWORK || "devnet";
  if (!NETWORKS[n]) throw new Error(`Unknown network "${n}" (use devnet, mainnet, or --rpc <url>)`);
  return NETWORKS[n];
}

export function extractDigest(s) {
  const m = (s || "").match(/sha256:[0-9a-fA-F]{64}/);
  return m ? m[0].toLowerCase() : null;
}

// RPC returns memo as "[<len>] <text>"; several memos in one tx are joined by "; ".
export function parseMemo(memo) {
  if (!memo) return [];
  return memo
    .split("; ")
    .map((m) => m.replace(/^\[\d+\]\s*/, ""))
    .filter((m) => m.startsWith("pod1|"))
    .map((m) => {
      const [, image, commit, digest, ts] = m.split("|");
      return { image, commit, digest, ts };
    });
}

// "ghcr.io/Me/App:latest" and "ghcr.io/me/app@sha256:..." -> "ghcr.io/me/app"
export function repoName(ref) {
  if (!ref) return null;
  let r = ref.replace(/@sha256:[0-9a-f]{64}$/i, "");
  const slash = r.lastIndexOf("/");
  const colon = r.lastIndexOf(":");
  if (colon > slash) r = r.slice(0, colon);
  const parts = r.split("/");
  if (parts.length === 1) r = `docker.io/library/${r}`;
  else if (!/[.:]/.test(parts[0]) && parts[0] !== "localhost") r = `docker.io/${r}`;
  return r.toLowerCase();
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function rpcAttempt(u, method, params, timeout) {
  const r = await fetch(u, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal: AbortSignal.timeout(timeout),
  });
  if (!r.ok) {
    const err = new Error(`RPC HTTP ${r.status}`);
    err.status = r.status;
    throw err;
  }
  const j = await r.json();
  if (j.error) throw new Error(j.error.message);
  return j.result;
}

// `url` may be a comma-separated list: endpoints are tried in order, so one dead or rate-limited RPC does not stop verification.
// A 429 (the public endpoints' most common failure) moves on to the next endpoint at once; only when a whole round of endpoints
// has failed and one of them was rate limited do we back off and go round again (OATH_RPC_RETRIES rounds, default 3). With a single
// endpoint that is simply "retry with backoff". Any other error just moves on to the next endpoint.
export async function rpcCall(url, method, params) {
  const urls = String(url).split(",").map((u) => u.trim()).filter(Boolean);
  const timeout = Number(process.env.OATH_RPC_TIMEOUT_MS || 15000);
  const retries = Number(process.env.OATH_RPC_RETRIES ?? 3);
  let lastErr = new Error("no RPC url given");
  for (let round = 0; round <= retries; round++) {
    let limited = false;
    for (const u of urls) {
      try {
        return await rpcAttempt(u, method, params, timeout);
      } catch (e) {
        lastErr = e;
        if (e.status === 429) limited = true;
      }
    }
    if (!limited) break;
    if (round < retries) await sleep(300 * 2 ** round);
  }
  throw lastErr;
}

// Revocation record: "pod1r|<digest>|<reason>|<ISO time>", signed by a trusted key. Final: a revoked digest never verifies again.
export function parseRevocation(memo) {
  if (!memo) return [];
  return memo
    .split("; ")
    .map((m) => m.replace(/^\[\d+\]\s*/, ""))
    .filter((m) => m.startsWith("pod1r|"))
    .map((m) => {
      const [, digest, reason, ts] = m.split("|");
      return { digest: (digest || "").toLowerCase(), reason: reason || "", ts };
    });
}

// Looks for a successful anchor of `digest` by the trusted `signers`, newest first, paging back up to `limit` txs per signer.
// opts.image: if set, the record's image name must equal repoName(image).
// opts.maxAgeSeconds: if set, the anchoring tx must be newer than that.
// opts.quorum: number of DISTINCT signers that must each have anchored the digest (default 1). With quorum 2 a stolen CI key alone is not enough.
// Returns { status: "verified", rec } | { status: "revoked", reason, signer } | { status: "missing" }.
// A revocation by ANY trusted signer wins, even if the digest was anchored (or re-anchored) later. Throws on RPC errors.
export async function checkRecord({ signers, digest, rpcUrl, limit = 1000, image, maxAgeSeconds, now = Date.now(), quorum = 1 }) {
  const want = repoName(image);
  const need = Math.max(1, Number(quorum) || 1);
  const unique = [...new Set(signers)];
  if (need > unique.length) return { status: "missing" }; // can never be satisfied

  // getSignaturesForAddress lists every tx that merely MENTIONS the address (anyone can add it as a read-only account, together
  // with a Memo they signed themselves). A record only counts if the signer really signed the transaction.
  async function signedBy(signer, signature) {
    const t = await rpcCall(rpcUrl, "getTransaction", [signature, { encoding: "jsonParsed", maxSupportedTransactionVersion: 0, commitment: "confirmed" }]);
    return !!t && !t.meta?.err && (t.transaction?.message?.accountKeys || []).some((k) => k.pubkey === signer && k.signer === true);
  }

  // Scans the signer's whole window: the first (newest) matching record and any revocation of the digest.
  async function scan(signer) {
    let before;
    let seen = 0;
    let rec = null;
    while (seen < limit) {
      const page = Math.min(1000, limit - seen);
      const sigs = await rpcCall(rpcUrl, "getSignaturesForAddress", [signer, { limit: page, ...(before ? { before } : {}) }]);
      if (!sigs.length) break;
      for (const s of sigs) {
        if (s.err) continue;
        for (const rv of parseRevocation(s.memo)) {
          if (rv.digest === digest && (await signedBy(signer, s.signature))) return { revoked: { signer, reason: rv.reason } };
        }
        if (rec) continue;
        for (const r of parseMemo(s.memo)) {
          if (r.digest !== digest) continue;
          if (want && repoName(r.image) !== want) continue;
          const t = s.blockTime ? s.blockTime * 1000 : Date.parse(r.ts);
          if (maxAgeSeconds && now - t > maxAgeSeconds * 1000) continue;
          if (!(await signedBy(signer, s.signature))) continue; // someone else's tx that only mentions the signer's address
          rec = { ...r, signer, signature: s.signature, anchoredAt: new Date(t).toISOString() };
          break;
        }
      }
      seen += sigs.length;
      before = sigs[sigs.length - 1].signature;
      if (sigs.length < page) break;
    }
    return { rec };
  }

  const hits = [];
  for (const signer of unique) {
    const res = await scan(signer);
    if (res.revoked) return { status: "revoked", ...res.revoked };
    if (res.rec) hits.push(res.rec);
  }
  if (hits.length < need) return { status: "missing" };
  hits.sort((a, b) => Date.parse(b.anchoredAt) - Date.parse(a.anchoredAt));
  return { status: "verified", rec: { ...hits[0], signers: hits.map((h) => h.signer) } };
}

// Backwards-compatible: the record, or null when missing OR revoked.
export async function findRecord(opts) {
  const r = await checkRecord(opts);
  return r.status === "verified" ? r.rec : null;
}
