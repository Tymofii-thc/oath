#!/usr/bin/env node
// oath admission webhook: blocks Pods whose images were not anchored on Solana by the trusted CI signer(s),
// and pins tags to the verified digest so what was checked is exactly what the kubelet pulls.
//
// Env: OATH_SIGNER (comma separated, required)   OATH_NETWORK | SOLANA_RPC   OATH_MAX_AGE_DAYS
//      OATH_QUORUM=<N> (distinct signers required)   OATH_ATTEST_REPO=<owner/repo> (also require a Sigstore build attestation)
//      OATH_STALE_OK_HOURS=<h> (default 1; while the RPC is down, admit digests verified within the last h hours; 0 = strict)
//      OATH_LIMIT=<txs scanned per signer, default 1000>   OATH_DEADLINE_MS=<answer within, default 12000; 0 = off>
//      OATH_PROGRAM=<id> (experimental: account-based backend instead of Memo scanning; see README, "On-chain records")
//      OATH_MODE=enforce|audit (default enforce)  OATH_PIN=true|false (default true)
//      OATH_REGISTRY_AUTH='{"ghcr.io":{"username":"u","password":"token"}}' (private registries)
//      TLS_CERT, TLS_KEY (default /tls/tls.crt, /tls/tls.key)   PORT (default 8443)   OATH_PLAIN_HTTP=1 (tests only)
import http from "node:http";
import https from "node:https";
import fs from "node:fs";
import { resolveRpc } from "../lib/oath.mjs";
import { makeHandler } from "../lib/admission.mjs";

const signers = (process.env.OATH_SIGNER || "").split(",").map((s) => s.trim()).filter(Boolean);
if (!signers.length) { console.error("OATH_SIGNER is required"); process.exit(2); }

const quorumEnv = Number(process.env.OATH_QUORUM || 1);
if (quorumEnv <= 1) {
  console.warn("oath: OATH_QUORUM is 1 — a single stolen CI key is enough to admit a forged image. Consider OATH_QUORUM=2 with an independent approver key kept outside CI (see README: Signer quorum).");
}
if (!process.env.OATH_ALLOWED_REGISTRIES) {
  console.warn("oath: OATH_ALLOWED_REGISTRIES is not set — anyone who can create a Pod can make this webhook send a HEAD/GET to any host named in the image field (SSRF). Set it to the registries you actually use (see README: Availability, and THREAT-MODEL.md).");
}

const handler = makeHandler({
  signers,
  rpcUrl: resolveRpc({}),
  maxAgeSeconds: process.env.OATH_MAX_AGE_DAYS ? Number(process.env.OATH_MAX_AGE_DAYS) * 86400 : undefined,
  quorum: Number(process.env.OATH_QUORUM || 1),
  limit: Number(process.env.OATH_LIMIT || 1000),
  deadlineMs: Number(process.env.OATH_DEADLINE_MS ?? 12000), // answer before the API server's 15s webhook timeout
  programId: process.env.OATH_PROGRAM || undefined,
  attestRepo: process.env.OATH_ATTEST_REPO || undefined,
  staleMs: Number(process.env.OATH_STALE_OK_HOURS ?? 1) * 3600000,
  mode: process.env.OATH_MODE || "enforce",
  pin: process.env.OATH_PIN !== "false",
  auths: process.env.OATH_REGISTRY_AUTH ? JSON.parse(process.env.OATH_REGISTRY_AUTH) : {},
});

const counts = { admitted: 0, denied: 0, warned: 0, bad_requests: 0 };
const metrics = () => {
  const lines = [];
  const add = (name, help, value, labels = "") => lines.push(`# HELP oath_${name} ${help}`, `# TYPE oath_${name} counter`, `oath_${name}${labels} ${value}`);
  add("admission_total", "Admission decisions", counts.admitted, '{result="admitted"}');
  lines.push(`oath_admission_total{result="denied"} ${counts.denied}`, `oath_admission_total{result="warned"} ${counts.warned}`);
  add("bad_requests_total", "Unparseable admission requests", counts.bad_requests);
  for (const [k, v] of Object.entries(handler.stats)) add(`${k}_total`, `Webhook lookup statistic: ${k}`, v);
  return lines.join("\n") + "\n";
};

const app = async (req, res) => {
  const path = new URL(req.url, "http://x").pathname; // the API server appends ?timeout=…
  if (req.method === "GET" && (path === "/healthz" || path === "/readyz")) { res.end("ok"); return; }
  if (req.method === "GET" && path === "/metrics") { res.setHeader("content-type", "text/plain; version=0.0.4"); res.end(metrics()); return; }
  if (req.method !== "POST" || path !== "/validate") { res.statusCode = 404; res.end(); return; }
  let body = "";
  for await (const c of req) { body += c; if (body.length > 4_000_000) { res.statusCode = 413; res.end(); return; } }
  try {
    const out = await handler(JSON.parse(body));
    const r = out.response;
    if (!r.allowed) counts.denied++; else if (r.warnings?.length) counts.warned++; else counts.admitted++;
    console.log(JSON.stringify({ uid: r.uid, allowed: r.allowed, msg: r.status?.message, warn: r.warnings }));
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify(out));
  } catch (e) {
    counts.bad_requests++;
    console.error("bad request:", e.message);
    res.statusCode = 400; res.end();
  }
};

const port = Number(process.env.PORT || 8443);
const server = process.env.OATH_PLAIN_HTTP
  ? http.createServer(app)
  : https.createServer({ cert: fs.readFileSync(process.env.TLS_CERT || "/tls/tls.crt"), key: fs.readFileSync(process.env.TLS_KEY || "/tls/tls.key") }, app);
server.listen(port, () => console.log(`oath webhook on :${port} signers=${signers.join(",")} mode=${process.env.OATH_MODE || "enforce"}`));
