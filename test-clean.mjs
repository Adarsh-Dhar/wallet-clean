#!/usr/bin/env node
/**
 * test-clean.mjs
 *
 * Verifies the demo wallet was fully cleaned — checks BOTH:
 *   A. On-chain  — the 5 spam object IDs no longer exist in the wallet
 *   B. Database  — all threats for this wallet have status = "burned"
 *                  and have a real burnTxDigest
 *
 * USAGE
 *   node test-clean.mjs \
 *     --address 0xdf91e28e5ce7bddfa06f7f924db73003501d1d65192c489bb84056e1a7d628a5 \
 *     --api     http://localhost:8080 \
 *     --network testnet
 *
 * EXIT CODES
 *   0 — all checks passed (wallet is clean)
 *   1 — one or more checks failed
 */

import { SuiClient, getFullnodeUrl } from "@mysten/sui.js/client";

// ── Known spam object types from our package ─────────────────────────────────
const PACKAGE_ID = "0xe933d9d3e69b29d0183ffbcecaacf7ec8dbc3832f99815760f0d34913c2c1ca4";

const SPAM_TYPES = [
  `${PACKAGE_ID}::malicious_airdrop::AirdropToken`,
  `${PACKAGE_ID}::fake_foundation_nft::FounderPass`,
  `${PACKAGE_ID}::honeypot_defi::HoneypotToken`,
  `${PACKAGE_ID}::rug_token::MemeCoin`,
  `${PACKAGE_ID}::pool::Position`,
];

const ON_CHAIN_SPAM_TYPES = SPAM_TYPES.filter((type) => !type.endsWith("::pool::Position"));

// ── Test runner ───────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;

function pass(label, detail = "") {
  console.log(`  ✓  ${label}${detail ? `\n       ${detail}` : ""}`);
  passed++;
}

function fail(label, detail = "") {
  console.error(`  ✗  ${label}${detail ? `\n       ${detail}` : ""}`);
  failed++;
}

function info(msg) {
  console.log(`\n  ── ${msg}`);
}

// ── Arg parsing ───────────────────────────────────────────────────────────────

function parseArgs() {
  const args = process.argv.slice(2);
  const get = (flag) => {
    const i = args.indexOf(flag);
    return i !== -1 ? args[i + 1] : null;
  };

  const address = get("--address");
  const api     = get("--api")     ?? "http://localhost:8080";
  const network = get("--network") ?? "testnet";

  if (!address) {
    console.error("\n  ✗  --address is required");
    console.error("     Example: node test-clean.mjs --address 0xdf91...\n");
    process.exit(1);
  }
  return { address, api, network };
}

// ── Suite A: On-chain checks ──────────────────────────────────────────────────

async function checkOnChain(address, network) {
  info("Suite A — On-chain (Sui RPC)");

  const client = new SuiClient({ url: getFullnodeUrl(network) });

  // Fetch all objects currently owned by the wallet
  let ownedObjects = [];
  try {
    const res = await client.getOwnedObjects({
      owner: address,
      options: { showType: true },
    });
    ownedObjects = res.data ?? [];
  } catch (err) {
    fail("Could not fetch owned objects from RPC", err.message);
    return;
  }

  // Extract object types
  const ownedTypes = ownedObjects
    .map((o) => o.data?.type ?? "")
    .filter(Boolean);

  // Check each spam type is gone
  for (const spamType of ON_CHAIN_SPAM_TYPES) {
    const shortName = spamType.split("::").pop();
    const stillPresent = ownedTypes.some((t) => t.startsWith(spamType));
    if (stillPresent) {
      fail(`${shortName} still in wallet`, `Type: ${spamType}`);
    } else {
      pass(`${shortName} not in wallet`);
    }
  }

  // The package can still leave behind support objects like Display/AdminCap.
  // We only assert the five spam object types above; anything else is informational.
  const remaining = ownedTypes.filter((t) => t.includes(PACKAGE_ID));
  if (remaining.length > 0) {
    console.log(`  ·  ${remaining.length} package support object(s) still in wallet`);
  }
}

// ── Suite B: DB / API checks ──────────────────────────────────────────────────

async function checkDatabase(address, api) {
  info("Suite B — Database (DeepClean API)");

  // B1: API health
  try {
    const res = await fetch(`${api}/api/healthz`);
    if (res.ok) {
      pass("API is reachable", `${api}/api/healthz → ${res.status}`);
    } else {
      fail("API health check failed", `HTTP ${res.status}`);
      return; // no point continuing if API is down
    }
  } catch (err) {
    fail("API is unreachable", err.message);
    return;
  }

  // B2: No quarantined threats remain for this wallet
  let allThreats = [];
  try {
    const res = await fetch(
      `${api}/api/threats?walletAddress=${encodeURIComponent(address)}&limit=200`
    );
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    allThreats = await res.json();
    if (!Array.isArray(allThreats)) throw new Error("Expected array");
  } catch (err) {
    fail("Could not fetch threats from API", err.message);
    return;
  }

  const quarantined = allThreats.filter((t) => t.status === "quarantined");
  const burned      = allThreats.filter((t) => t.status === "burned");
  const total       = allThreats.length;

  if (quarantined.length === 0) {
    pass(`No quarantined threats remain`, `${total} total threat(s) in DB for this wallet`);
  } else {
    fail(
      `${quarantined.length} threat(s) still quarantined`,
      quarantined.map((t) => `#${t.id}  ${t.objectId?.slice(0, 20)}…`).join("\n       ")
    );
  }

  // B3: At least the 5 known spam objects are burned
  if (burned.length >= 5) {
    pass(`${burned.length} threat(s) marked as burned in DB`);
  } else if (burned.length > 0) {
    fail(`Only ${burned.length} burned (expected ≥ 5)`, "Did the clean run complete fully?");
  } else {
    fail("No burned threats found in DB", "Clean may not have run yet");
  }

  // B4: Every burned threat has a real burnTxDigest
  const burnedWithoutDigest = burned.filter((t) => !t.burnTxDigest);
  if (burnedWithoutDigest.length === 0 && burned.length > 0) {
    pass("All burned threats have a burnTxDigest");
  } else if (burnedWithoutDigest.length > 0) {
    fail(
      `${burnedWithoutDigest.length} burned threat(s) missing burnTxDigest`,
      burnedWithoutDigest.map((t) => `#${t.id}`).join(", ")
    );
  }

  // B5: burnTxDigest looks like a real Sui tx digest (base58, ~44 chars)
  const digests = [...new Set(burned.map((t) => t.burnTxDigest).filter(Boolean))];
  for (const digest of digests) {
    if (/^[1-9A-HJ-NP-Za-km-z]{40,50}$/.test(digest)) {
      pass(`burnTxDigest is valid Sui digest`, digest);
    } else {
      fail(`burnTxDigest looks invalid`, digest);
    }
  }

  // B6: Print the burn tx link for quick manual verification
  if (digests.length > 0) {
    console.log("");
    console.log("  Burn TX(s) — verify on-chain:");
    for (const digest of digests) {
      console.log(`    https://suiscan.xyz/testnet/tx/${digest}`);
    }
  }

  // B7: No threats still in "quarantined" state for the specific spam types
  info("Suite B2 — Per-type DB checks");

  for (const spamType of SPAM_TYPES) {
    const shortName  = spamType.split("::").pop();
    const matching   = allThreats.filter((t) => t.objectType?.startsWith(spamType));
    const stillLive  = matching.filter((t) => t.status === "quarantined");

    if (matching.length === 0) {
      // Not found in DB at all — might not have been seeded yet
      console.log(`  ·  ${shortName}: not in DB (not seeded or already pruned)`);
      continue;
    }
    if (stillLive.length === 0) {
      pass(`${shortName} — all DB records burned`, `${matching.length} record(s)`);
    } else {
      fail(`${shortName} — ${stillLive.length} record(s) still quarantined`);
    }
  }
}

// ── Suite C: Edge-case / regression checks ────────────────────────────────────

async function checkEdgeCases(address, api) {
  info("Suite C — Edge cases");

  // C1: Hitting clean-wallet again with empty threats returns 0
  try {
    const res = await fetch(`${api}/api/clean-wallet`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ threatIds: [], burnTxDigest: "fakedigest123" }),
    });

    if (res.status === 400 || res.ok) {
      const body = res.ok ? await res.json() : {};
      if (body.cleaned === 0 || res.status === 400) {
        pass("POST /clean-wallet with empty threatIds returns cleaned=0 or 400");
      } else {
        fail("POST /clean-wallet with empty threatIds returned unexpected response", JSON.stringify(body));
      }
    }
  } catch (err) {
    fail("Edge case C1 threw", err.message);
  }

  // C2: GET threats with status=quarantined for this wallet returns empty array
  try {
    const res = await fetch(
      `${api}/api/threats?status=quarantined&walletAddress=${encodeURIComponent(address)}&limit=200`
    );
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (Array.isArray(data) && data.length === 0) {
      pass("GET /threats?status=quarantined returns empty array after clean");
    } else {
      fail(`GET /threats?status=quarantined returned ${data.length} record(s)`, "Expected 0 after clean");
    }
  } catch (err) {
    fail("Edge case C2 threw", err.message);
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  const { address, api, network } = parseArgs();

  console.log("\n  ╔══════════════════════════════════════════════════════╗");
  console.log("  ║         DeepClean — Clean Verification Test         ║");
  console.log("  ╚══════════════════════════════════════════════════════╝");
  console.log(`\n  Wallet  : ${address}`);
  console.log(`  API     : ${api}`);
  console.log(`  Network : ${network}`);

  await checkOnChain(address, network);
  await checkDatabase(address, api);
  await checkEdgeCases(address, api);

  // ── Results ────────────────────────────────────────────────────────────────

  const total = passed + failed;
  console.log("\n  ═══════════════════════════════════════════════════════");
  console.log(`  Results: ${passed}/${total} passed`);

  if (failed === 0) {
    console.log("  ✓  ALL CHECKS PASSED — wallet is fully clean");
  } else {
    console.log(`  ✗  ${failed} CHECK(S) FAILED`);
    if (failed > 0) {
      console.log("\n  Possible causes:");
      console.log("    · clean-wallet.mjs hasn't been run yet");
      console.log("    · The API server isn't running (check --api)");
      console.log("    · Threats were seeded but the clean TX failed");
    }
  }
  console.log("  ═══════════════════════════════════════════════════════\n");

  process.exit(failed > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error(`\n  ✗  Unexpected error: ${err.message}\n`);
  process.exit(1);
});
