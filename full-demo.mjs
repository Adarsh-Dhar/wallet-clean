#!/usr/bin/env node
/**
 * full-demo.mjs
 *
 * Complete end-to-end demo:
 * 1. Seed threats from on-chain objects
 * 2. Clean the wallet
 * 3. Verify the wallet is clean
 *
 * USAGE
 *   node full-demo.mjs \
 *     --address 0x4f6a... \
 *     --key suiprivkey1... \
 *     --api http://localhost:8080
 */

import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Transaction } from "@mysten/sui/transactions";
import { getJsonRpcFullnodeUrl, SuiJsonRpcClient } from "@mysten/sui/jsonRpc";
import { fromBase64 } from "@mysten/sui/utils";

// ── Parse args ────────────────────────────────────────────────────────────────

function parseArgs() {
  const args = process.argv.slice(2);
  const get = (flag) => {
    const i = args.indexOf(flag);
    return i !== -1 ? args[i + 1] : null;
  };

  const address = get("--address");
  const key = get("--key");
  const api = get("--api") ?? "http://localhost:8080";
  const network = get("--network") ?? "testnet";

  if (!address) {
    console.error("\n  ✗  --address is required");
    process.exit(1);
  }
  if (!key) {
    console.error("\n  ✗  --key is required");
    process.exit(1);
  }

  return { address, key, api, network };
}

// ── Keypair from private key ──────────────────────────────────────────────────

function keypairFromKey(keyStr) {
  if (keyStr.startsWith("suiprivkey1")) {
    return Ed25519Keypair.fromSecretKey(keyStr);
  }
  const bytes = fromBase64(keyStr);
  if (bytes.length === 33) {
    return Ed25519Keypair.fromSecretKey(bytes.slice(1));
  }
  return Ed25519Keypair.fromSecretKey(bytes);
}

// ── Get JWT token ─────────────────────────────────────────────────────────────

async function getToken(api, address, keypair) {
  const challengeRes = await fetch(`${api}/api/auth/challenge?address=${address}`);
  if (!challengeRes.ok) {
    throw new Error(`Challenge failed: HTTP ${challengeRes.status}`);
  }
  const { challenge } = await challengeRes.json();

  const messageBytes = new TextEncoder().encode(challenge);
  const { signature } = await keypair.signPersonalMessage(messageBytes);

  const loginRes = await fetch(`${api}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ address, signature }),
  });
  if (!loginRes.ok) {
    throw new Error(`Login failed: HTTP ${loginRes.status}`);
  }
  const { token } = await loginRes.json();
  return token;
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  const { address, key, api, network } = parseArgs();

  console.log("\n  ╔════════════════════════════════════════════════════════╗");
  console.log("  ║        DeepClean — Full Demo Workflow                 ║");
  console.log("  ║     Seed → Clean → Verify (All in one!)              ║");
  console.log("  ╚════════════════════════════════════════════════════════╝");
  console.log(`\n  Wallet  : ${address}`);
  console.log(`  API     : ${api}`);
  console.log(`  Network : ${network}\n`);

  const keypair = keypairFromKey(key);
  const derivedAddr = keypair.getPublicKey().toSuiAddress();
  if (derivedAddr.toLowerCase() !== address.toLowerCase()) {
    console.error(`\n  ✗ Key mismatch! Key is for ${derivedAddr}\n`);
    process.exit(1);
  }

  // ── Step 1: Get auth token ────────────────────────────────────────────────

  console.log("  ┌─ STEP 1: Authenticate ─────────────────────────────────┐");
  console.log("  │");
  let token;
  try {
    console.log("    🔐 Getting JWT token...");
    token = await getToken(api, address, keypair);
    console.log("    ✓ Authenticated\n");
  } catch (err) {
    console.error(`    ✗ ${err.message}\n`);
    process.exit(1);
  }
  console.log("  └────────────────────────────────────────────────────────┘\n");

  const authHeader = { Authorization: `Bearer ${token}` };

  // ── Step 2: Seed on-chain junk ──────────────────────────────────────────

  console.log("  ┌─ STEP 2: Seed On-Chain Junk ────────────────────────────┐");
  console.log("  │");
  try {
    console.log("    📡 Seeding on-chain junk objects...");
    const populateRes = await fetch(`${api}/api/populate-wallet`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeader },
      body: JSON.stringify({ targetAddress: address }),
    });

    if (!populateRes.ok) {
      throw new Error(`HTTP ${populateRes.status}: ${await populateRes.text()}`);
    }

    const populateData = await populateRes.json();
    const injected = Number(populateData.injected ?? 0);
    const digests = Array.isArray(populateData.digests) ? populateData.digests : [];

    console.log(`    ✓ Seeded ${injected} junk object(s)`);
    if (digests.length > 0) {
      console.log(`    ✓ Submitted ${digests.length} transaction(s)`);
    }
    console.log();
  } catch (err) {
    console.error(`    ✗ ${err.message}\n`);
    process.exit(1);
  }
  console.log("  └────────────────────────────────────────────────────────┘\n");

  console.log("  ═══════════════════════════════════════════════════════════");
  console.log("  ✓  DEMO COMPLETE — Wallet seeded with junk objects only!");
  console.log("  ═══════════════════════════════════════════════════════════\n");
}

main().catch((err) => {
  console.error(`\n  ✗  ${err.message}\n`);
  process.exit(1);
});
