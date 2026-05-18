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

  // ── Step 2: Seed threats from on-chain ──────────────────────────────────

  console.log("  ┌─ STEP 2: Seed Threats ─────────────────────────────────┐");
  console.log("  │");
  let populatedThreats = [];
  try {
    console.log("    📡 Detecting on-chain objects...");
    const populateRes = await fetch(`${api}/api/populate-wallet`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeader },
      body: JSON.stringify({ targetAddress: address }),
    });

    if (!populateRes.ok) {
      throw new Error(`HTTP ${populateRes.status}: ${await populateRes.text()}`);
    }

    const populateData = await populateRes.json();
    populatedThreats = Array.isArray(populateData.threats) ? populateData.threats : [];
    const threatsCount = populatedThreats.filter((threat) => threat?.threatId !== null).length;
    console.log(`    ✓ Detected ${threatsCount} threat(s)\n`);
  } catch (err) {
    console.error(`    ✗ ${err.message}\n`);
    process.exit(1);
  }
  console.log("  └────────────────────────────────────────────────────────┘\n");

  // ── Step 3: Fetch and clean threats ────────────────────────────────────

  console.log("  ┌─ STEP 3: Clean Wallet ─────────────────────────────────┐");
  console.log("  │");

  const threats = populatedThreats.filter((threat) => threat?.threatId !== null);
  try {
    console.log("    📋 Using quarantined threats returned by populate-wallet...");
    console.log(`    ✓ Found ${threats.length} threat(s)\n`);
  } catch (err) {
    console.error(`    ✗ Failed to fetch threats: ${err.message}\n`);
    process.exit(1);
  }

  if (threats.length === 0) {
    console.log("    ✗ No quarantined threats were returned, so nothing was cleaned.\n");
    console.log("  └────────────────────────────────────────────────────────┘\n");
  } else {
    // Build and execute burn transaction
    let digest;
    try {
      console.log("    🔥 Building burn transaction...");
      
      // Validate that all threats have objectIds
      const validThreats = threats.filter((t) => {
        if (!t.objectId) {
          console.warn(`    ⚠ Skipping threat without objectId: ${JSON.stringify(t)}`);
          return false;
        }
        return true;
      });

      if (validThreats.length === 0) {
        throw new Error("No valid objects to burn");
      }

      if (validThreats.length !== threats.length) {
        console.log(`    ⚠ Warning: ${threats.length - validThreats.length} threat(s) skipped due to missing objectId`);
      }

      const tx = new Transaction();
      const objectsToTransfer = validThreats.map((t) => tx.object(t.objectId));
      const deadAddress = "0x0000000000000000000000000000000000000000000000000000000000000000";

      tx.transferObjects(objectsToTransfer, tx.pure.address(deadAddress));

      console.log("    ⛓️  Signing and executing on-chain...");
      const client = new SuiJsonRpcClient({ url: getJsonRpcFullnodeUrl(network), network });
      const result = await client.signAndExecuteTransaction({
        transaction: tx,
        signer: keypair,
        options: { showEffects: true },
      });

      if (result.effects?.status?.status !== "success") {
        throw new Error(`TX failed: ${JSON.stringify(result.effects?.status)}`);
      }

      digest = result.digest;
      console.log(`    ✓ Burned ${validThreats.length} object(s)\n`);
    } catch (err) {
      console.error(`    ✗ Transaction failed: ${err.message}\n`);
      process.exit(1);
    }

    // Mark as burned in DB
    try {
      console.log("    💾 Updating database...");
      const cleanRes = await fetch(`${api}/api/clean-wallet`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeader },
        body: JSON.stringify({
          threatIds: threats.map((t) => t.id),
          burnTxDigest: digest,
        }),
      });

      if (!cleanRes.ok) {
        throw new Error(`HTTP ${cleanRes.status}`);
      }
      console.log(`    ✓ Marked as burned in DB\n`);
      console.log(`    Burn TX: ${digest}`);
      console.log(`    Verify : https://suiscan.xyz/testnet/tx/${digest}\n`);
    } catch (err) {
      console.error(`    ✗ DB update failed: ${err.message}\n`);
      process.exit(1);
    }
  }

  console.log("  └────────────────────────────────────────────────────────┘\n");

  // ── Step 4: Verify ──────────────────────────────────────────────────────

  console.log("  ┌─ STEP 4: Verify Clean ─────────────────────────────────┐");
  console.log("  │");

  try {
    console.log("    🔍 Checking on-chain objects...");
    const client = new SuiJsonRpcClient({ url: getJsonRpcFullnodeUrl(network), network });
    const ownedObjects = await client.getOwnedObjects({
      owner: address,
      options: { showType: true },
    });

    const spamPackage = "0xe933d9d3e69b29d0183ffbcecaacf7ec8dbc3832f99815760f0d34913c2c1ca4";
    const spamObjects = (ownedObjects.data ?? []).filter((o) =>
      o.data?.type?.includes(spamPackage)
    );

    if (spamObjects.length === 0) {
      console.log("    ✓ No spam objects found on-chain\n");
    } else {
      console.log(`    ✗ ${spamObjects.length} spam object(s) still in wallet\n`);
      spamObjects.forEach((o) => {
        console.log(`      - ${o.data?.type?.split("::").pop()}`);
      });
      console.log("");
    }

    console.log("    📊 Checking database...");
    const dbCheckRes = await fetch(
      `${api}/api/threats?walletAddress=${encodeURIComponent(address)}&limit=200`,
      { headers: authHeader }
    );

    if (!dbCheckRes.ok) {
      throw new Error(`HTTP ${dbCheckRes.status}`);
    }

    const allThreats = await dbCheckRes.json();
    const quarantined = allThreats.filter((t) => t.status === "quarantined");
    const burned = allThreats.filter((t) => t.status === "burned");

    if (quarantined.length === 0) {
      console.log(`    ✓ No quarantined threats in DB`);
      console.log(`    ✓ ${burned.length} threat(s) marked as burned\n`);
    } else {
      console.log(`    ✗ ${quarantined.length} threat(s) still quarantined\n`);
    }

    if (spamObjects.length > 0 || quarantined.length > 0) {
      throw new Error("Verification failed: residual spam or quarantined threats remain");
    }
  } catch (err) {
    console.error(`    ⚠  Verification check failed: ${err.message}\n`);
    process.exit(1);
  }

  console.log("  └────────────────────────────────────────────────────────┘\n");

  // ── Summary ────────────────────────────────────────────────────────────

  console.log("  ═══════════════════════════════════════════════════════════");
  console.log("  ✓  DEMO COMPLETE — Wallet cleaned and verified!");
  console.log("  ═══════════════════════════════════════════════════════════\n");
}

main().catch((err) => {
  console.error(`\n  ✗  ${err.message}\n`);
  process.exit(1);
});
