// Regression test against the REAL devnet deployment of program/oath_records (not part of `npm test`,
// which is offline), same reasoning as test/live-devnet.mjs for the Memo path.
// Fixtures anchored/revoked live on devnet under the program deployed on 2026-10-21 (the first deployment was replaced: see program/oath_records/DEPLOY.md):
//   VERIFIED_DIGEST  anchored by the project's CI key, never revoked -> must still verify
//   REVOKED_DIGEST   anchored, then revoked by the same key          -> must report revoked, permanently
//   UNRECORDED_DIGEST never anchored under this program              -> must be missing
import { checkPda } from "../lib/pda.mjs";

const PROGRAM_ID = "EWse8WXE3BYTeLvyDHufhp1Z73Pjqiq7nohAPE4cLSEc";
const CI = "5D4W8x8UeqW3qVi9uzNzvJPWiJZQaRWVR9ru2ckFhoih"; // the project's CI key, which anchored/revoked the fixtures below
const rpcUrl = process.env.SOLANA_RPC || "https://api.devnet.solana.com";
const VERIFIED_DIGEST = "sha256:" + "d".repeat(64);
const REVOKED_DIGEST = "sha256:" + "e".repeat(64);
const UNRECORDED_DIGEST = "sha256:" + "f".repeat(64);
let fails = 0;
const check = (name, ok) => { console.log(`${ok ? "PASS" : "FAIL"}  ${name}`); if (!ok) fails++; };

const verified = await checkPda({ rpcUrl, programId: PROGRAM_ID, signers: [CI], digest: VERIFIED_DIGEST });
check("a genuine, never-revoked on-chain record verifies", verified.status === "verified");

const revoked = await checkPda({ rpcUrl, programId: PROGRAM_ID, signers: [CI], digest: REVOKED_DIGEST });
check("a revoked digest reports revoked, not verified", revoked.status === "revoked");
check("the revocation reason round-trips", revoked.reason === "devnet live test");

const missing = await checkPda({ rpcUrl, programId: PROGRAM_ID, signers: [CI], digest: UNRECORDED_DIGEST });
check("a digest never anchored under this program is missing", missing.status === "missing");

process.exit(fails ? 1 : 0);
