// Startup warnings the webhook prints once, before serving anything (OATH_PLAIN_HTTP skips TLS so no cert files are needed).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";

function startWebhook(env) {
  const p = spawn(process.execPath, [new URL("../bin/oath-webhook.mjs", import.meta.url).pathname], {
    env: { PATH: process.env.PATH, OATH_SIGNER: "SignerKey1111111111111111111111111111111111", OATH_PLAIN_HTTP: "1", PORT: "0", ...env },
  });
  let err = "";
  p.stderr.on("data", (c) => (err += c));
  const ready = new Promise((resolve) => p.stdout.once("data", resolve)); // "oath webhook on :..." means it's up
  return { proc: p, stop: () => p.kill(), errSoFar: () => err, ready };
}

test("warns when OATH_ALLOWED_REGISTRIES is not set (SSRF via any image host)", async () => {
  const w = startWebhook({});
  try {
    await w.ready;
    assert.match(w.errSoFar(), /OATH_ALLOWED_REGISTRIES is not set/);
  } finally {
    w.stop();
  }
});

test("no warning once OATH_ALLOWED_REGISTRIES is set", async () => {
  const w = startWebhook({ OATH_ALLOWED_REGISTRIES: "ghcr.io" });
  try {
    await w.ready;
    assert.doesNotMatch(w.errSoFar(), /OATH_ALLOWED_REGISTRIES is not set/);
  } finally {
    w.stop();
  }
});
