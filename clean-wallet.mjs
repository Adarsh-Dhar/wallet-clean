#!/usr/bin/env node
/**
 * clean-wallet.mjs
 *
 * Cleans all quarantined threats from the demo wallet without needing a browser.
 * Mirrors exactly what the frontend does:
 *   1. GET /api/threats?status=quarantined&walletAddress=...  → get objectIds
 *   2. Build PTB → transferObjects([...objectIds], 0x0)
 *   3. Sign + execute with the wallet's private key
 *   4. POST /api/clean-wallet { threatIds, burnTxDigest }     → mark burned in DB
 *
 * USAGE
 *   node clean-wallet.mjs \
 *     --address  0xdf91e28e5ce7bddfa06f7f924db73003501d1d65192c489bb84056e1a7d628a5 \
 *     --key      <base64-or-bech32-private-key> \
 *     --api      http://localhost:8080
 *
 * PRIVATE KEY FORMAT
 *   Export from the sui CLI:
 *     sui keytool export --key-identity <address>
 *   The `exportedPrivateKey` field is the value to pass as --key.
 *   Accepts both bech32 (suiprivkey1...) and raw base64 formats.
 *
 * BYPASSING AUTH
 *   The script bypasses the wallet-signature auth challenge by setting
 *   NODE_ENV=test (the API disables auth in test mode) OR by doing the
 *   full challenge → sign → JWT flow if --key is provided.
 *   Pass --skip-auth to talk directly to the API without a JWT
 *   (only works if the server has NODE_ENV=test).
 */

import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Transaction } from "@mysten/sui/transactions";
import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from "@mysten/sui/jsonRpc";
import { fromBase64 } from "@mysten/sui/utils";

// ── Parse args ────────────────────────────────────────────────────────────────

function parseArgs() {
  const args = process.argv.slice(2);
  const get = (flag) => {
    const i = args.indexOf(flag);
    return i !== -1 ? args[i + 1] : null;
  };
  const has = (flag) => args.includes(flag);

  const address   = get("--address");
  const key       = get("--key");
  const api       = get("--api") ?? "http://localhost:8080";
  const network   = get("--network") ?? "testnet";
  const skipAuth  = has("--skip-auth");

  if (!address) {
    console.error("\n  ✗  --address is required");
    console.error("     Example: node clean-wallet.mjs --address 0xdf91... --key suiprivkey1...\n");
    process.exit(1);
  }
  if (!key && !skipAuth) {
    console.error("\n  ✗  --key is required (or pass --skip-auth if server runs in NODE_ENV=test)");
    process.exit(1);
  }

  return { address, key, api, network, skipAuth };
}

// ── Keypair from private key string ──────────────────────────────────────────

function keypairFromKey(keyStr) {
  // bech32 format: suiprivkey1...
  if (keyStr.startsWith("suiprivkey1")) {
    return Ed25519Keypair.fromSecretKey(keyStr);
  }
  // Raw base64 — 32 bytes secret key
  const bytes = fromBase64(keyStr);
  // sui keytool export prepends a scheme flag byte (0x00 for Ed25519)
  if (bytes.length === 33) {
    return Ed25519Keypair.fromSecretKey(bytes.slice(1));
  }
  return Ed25519Keypair.fromSecretKey(bytes);
}

// ── Auth: get JWT via challenge → sign ───────────────────────────────────────

async function getJwt(api, address, keypair) {
  console.log("  🔐 Authenticating with API...");

  // 1. Get challenge
  const challengeRes = await fetch(`${api}/api/auth/challenge?address=${address}`);
  if (!challengeRes.ok) {
    throw new Error(`Challenge failed: HTTP ${challengeRes.status} — ${await challengeRes.text()}`);
  }
  const { challenge } = await challengeRes.json();

  // 2. Sign the challenge message with the keypair
  const messageBytes = new TextEncoder().encode(challenge);
  const { signature } = await keypair.signPersonalMessage(messageBytes);

  // 3. Exchange for JWT
  const loginRes = await fetch(`${api}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ address, signature }),
  });
  if (!loginRes.ok) {
    throw new Error(`Login failed: HTTP ${loginRes.status} — ${await loginRes.text()}`);
  }
  const { token } = await loginRes.json();
  console.log("  ✓  Authenticated");
  return token;
}

// ── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  const { address, key, api, network, skipAuth } = parseArgs();

  console.log("\n  ╔══════════════════════════════════════════════════════╗");
  console.log("  ║           DeepClean — Wallet Cleaner                ║");
  console.log("  ╚══════════════════════════════════════════════════════╝");
  console.log(`\n  Wallet  : ${address}`);
  console.log(`  API     : ${api}`);
  console.log(`  Network : ${network}\n`);

  // ── 1. Auth ────────────────────────────────────────────────────────────────

  let keypair = null;
  let authHeader = {};

  if (!skipAuth) {
    keypair = keypairFromKey(key);
    const derivedAddress = keypair.getPublicKey().toSuiAddress();
    console.log(`  Keypair address: ${derivedAddress}`);
    if (derivedAddress.toLowerCase() !== address.toLowerCase()) {
      console.error(`\n  ✗ Key mismatch! Key derives to ${derivedAddress} but --address is ${address}`);
      process.exit(1);
    }
    const token = await getJwt(api, address, keypair);
    authHeader = { Authorization: `Bearer ${token}` };
  } else {
    console.log("  ⚠  Skipping auth (--skip-auth). Server must be in NODE_ENV=test.");
    keypair = keypairFromKey(key);
  }

  // ── 2. Fetch quarantined threats ───────────────────────────────────────────

  console.log("\n  Fetching quarantined threats...");
  const threatsRes = await fetch(
    `${api}/api/threats?status=quarantined&walletAddress=${encodeURIComponent(address)}&limit=200`,
    { headers: authHeader }
  );
  if (!threatsRes.ok) {
    throw new Error(`Failed to fetch threats: HTTP ${threatsRes.status} — ${await threatsRes.text()}`);
  }
  const threats = await threatsRes.json();

  if (!Array.isArray(threats) || threats.length === 0) {
    console.log("\n  ✓  No quarantined threats found — wallet is already clean!\n");
    process.exit(0);
  }

  console.log(`  Found ${threats.length} quarantined threat(s):\n`);
  threats.forEach((t, i) => {
    console.log(`    [${i + 1}] #${t.id}  ${t.objectId.slice(0, 20)}…  (${t.objectType.split("::").pop()})`);
  });

  // ── 3. Build PTB ───────────────────────────────────────────────────────────

  console.log("\n  Building PTB — transfer all spam objects to dead address...");
  
  // Validate that all threats have objectIds
  const validThreats = threats.filter((t) => {
    if (!t.objectId) {
      console.warn(`    ⚠ Skipping threat without objectId: ${JSON.stringify(t)}`);
      return false;
    }
    return true;
  });

  if (validThreats.length === 0) {
    console.error("    ✗ No valid objects to burn");
    process.exit(1);
  }

  if (validThreats.length !== threats.length) {
    console.log(`    ⚠ Warning: ${threats.length - validThreats.length} threat(s) skipped due to missing objectId`);
  }

  const tx = new Transaction();
  const deadAddress = "0x0"; // Use properly formatted dead address
  tx.transferObjects(
    validThreats.map((t) => tx.object(t.objectId)),
    deadAddress
  );

  // ── 4. Sign and execute on-chain ───────────────────────────────────────────

  console.log("  Signing and executing transaction...");
  const client = new SuiJsonRpcClient({
    url: getJsonRpcFullnodeUrl(network),
    network,
  });

  let digest;
  try {
    const result = await client.signAndExecuteTransaction({
      transaction: tx,
      signer: keypair,
      options: {
        showEffects: true,
        showEvents: true,
      },
    });

    if (result.effects?.status?.status !== "success") {
      throw new Error(`Transaction failed: ${JSON.stringify(result.effects?.status)}`);
    }

    digest = result.digest;
    console.log(`  ✓  On-chain transaction confirmed`);
    console.log(`     Digest  : ${digest}`);
    console.log(`     Suiscan : https://suiscan.xyz/testnet/tx/${digest}`);
  } catch (err) {
    console.error(`\n  ✗  Transaction failed: ${err.message}`);
    process.exit(1);
  }

  // ── 5. Mark burned in DB ───────────────────────────────────────────────────

  console.log("\n  Updating DB — marking threats as burned...");
  const cleanRes = await fetch(`${api}/api/clean-wallet`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeader },
    body: JSON.stringify({
      threatIds: validThreats.map((t) => t.id),
      burnTxDigest: digest,
    }),
  });

  if (!cleanRes.ok) {
    throw new Error(`DB update failed: HTTP ${cleanRes.status} — ${await cleanRes.text()}`);
  }

  const result = await cleanRes.json();

  // ── 6. Summary ─────────────────────────────────────────────────────────────

  console.log("\n  ═══════════════════════════════════════════════════════");
  console.log(`  ✓  Deep clean complete — ${result.cleaned} threat(s) burned`);
  console.log("");
  result.threats?.forEach((t, i) => {
    console.log(`    [${i + 1}] Threat #${t.id}  ${t.objectId.slice(0, 20)}…  → burned`);
  });
  console.log("");
  console.log(`  Burn TX : ${digest}`);
  console.log(`  Verify  : https://suiscan.xyz/testnet/tx/${digest}`);
  console.log("  ═══════════════════════════════════════════════════════\n");
}

main().catch((err) => {
  console.error(`\n  ✗  ${err.message}\n`);
  process.exit(1);
});
