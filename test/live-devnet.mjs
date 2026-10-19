// Regression test against the REAL devnet (not part of `npm test`, which is offline).
// 1. The forged-record attack: a transaction that only mentions the CI address next to a Memo signed by someone else
//    (tx ECD4Terw…, digest abab…) must NOT verify.
// 2. A genuine record by the CI key must still verify.
import { checkRecord } from "../lib/oath.mjs";

const CI = "5D4W8x8UeqW3qVi9uzNzvJPWiJZQaRWVR9ru2ckFhoih";
const rpcUrl = process.env.SOLANA_RPC || "https://api.devnet.solana.com";
const FORGED = "sha256:" + "ab".repeat(32);
const REAL = "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc";
let fails = 0;
const check = (name, ok) => { console.log(`${ok ? "PASS" : "FAIL"}  ${name}`); if (!ok) fails++; };

const forged = await checkRecord({ signers: [CI], digest: FORGED, rpcUrl });
check("forged record (address only mentioned) is not accepted", forged.status === "missing");
const real = await checkRecord({ signers: [CI], digest: REAL, rpcUrl });
check("genuine record by the CI key verifies", real.status === "verified");
process.exit(fails ? 1 : 0);
