#!/usr/bin/env tsx
/**
 * populate-wallet — DeepClean demo population script
 *
 * Sends 5 synthetic spam/phishing objects through the DeepClean analysis
 * pipeline and optionally fires a real Sui Devnet PTB to prove on-chain
 * connectivity.
 *
 * Usage:
 *   pnpm --filter @workspace/scripts run populate --address 0x<your_wallet>
 *   pnpm --filter @workspace/scripts run populate --address 0x<wallet> --devnet
 *
 * Flags:
 *   --address <addr>   Target wallet address (required)
 *   --devnet           Also submit a real coin-split PTB on Sui Devnet (optional)
 *   --api <url>        Override API base URL (default: http://localhost:80/api)
 */

import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
// @ts-ignore: package exposes runtime `SuiClient` but types may differ by version
import { SuiClient } from "@mysten/sui/client";
import { Transaction } from "@mysten/sui/transactions";

// ─── Config ───────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
function getArg(flag: string): string | undefined {
  const idx = args.indexOf(flag);
  return idx !== -1 ? args[idx + 1] : undefined;
}
const hasFlag = (f: string) => args.includes(f);

const TARGET_ADDRESS = getArg("--address");
const USE_DEVNET    = hasFlag("--devnet");
const API_BASE      = getArg("--api") ?? "http://localhost:80/api";

const DEVNET_RPC     = "https://fullnode.devnet.sui.io";
const DEVNET_FAUCET  = "https://faucet.devnet.sui.io/v1/gas";
const TIMEOUT_MS     = 90_000;

// ─── Colour helpers ────────────────────────────────────────────────────────────

const C = {
  reset:  "\x1b[0m",
  cyan:   "\x1b[96m",
  green:  "\x1b[92m",
  red:    "\x1b[91m",
  yellow: "\x1b[93m",
  dim:    "\x1b[2m",
  bold:   "\x1b[1m",
};
const ok  = (s: string) => `${C.green}✅  ${s}${C.reset}`;
const err = (s: string) => `${C.red}❌  ${s}${C.reset}`;
const dim = (s: string) => `${C.dim}${s}${C.reset}`;
const hdr = (s: string) => `\n${C.bold}${C.cyan}${s}${C.reset}`;

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function apiFetch<T>(path: string, opts?: RequestInit): Promise<T> {
  const controller = new AbortController();
  const tid = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(`${API_BASE}${path}`, {
      ...opts,
      signal: controller.signal,
      headers: { "Content-Type": "application/json", ...opts?.headers },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} — ${await res.text()}`);
    return res.json() as Promise<T>;
  } finally {
    clearTimeout(tid);
  }
}

function shortId(id: string): string {
  return `${id.slice(0, 10)}…${id.slice(-6)}`;
}

// ─── Layer 1: Real Devnet PTB (optional) ─────────────────────────────────────

async function submitDevnetPtb(targetAddress: string): Promise<string | null> {
  console.log(hdr("Layer 1 — Real Sui Devnet PTB"));
  try {
    const keypair = new Ed25519Keypair();
    const spammerAddress = keypair.getPublicKey().toSuiAddress();
    console.log(`  Spammer address : ${dim(spammerAddress)}`);

    // Fund from Devnet faucet
    process.stdout.write("  Requesting faucet funds…");
    const faucetRes = await fetch(DEVNET_FAUCET, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ FixedAmountRequest: { recipient: spammerAddress } }),
      signal: AbortSignal.timeout(20_000),
    });
    if (!faucetRes.ok) throw new Error(`Faucet HTTP ${faucetRes.status}`);
    console.log(" funded");

    // Wait for coin to land
    const client = new SuiClient({ url: DEVNET_RPC });
    let coins: { data: Array<{ coinObjectId: string; balance: string }> } = { data: [] };
    for (let i = 0; i < 10; i++) {
      await new Promise((r) => setTimeout(r, 2000));
      coins = await client.getCoins({ owner: spammerAddress, coinType: "0x2::sui::SUI" });
      if (coins.data.length > 0) break;
    }
    if (coins.data.length === 0) throw new Error("No coins after faucet — Devnet may be slow");
    const coin = coins.data[0]!;
    console.log(`  Gas coin        : ${dim(shortId(coin.coinObjectId))} (${coin.balance} MIST)`);

    // Build PTB: split coin into 5 equal pieces and transfer each to target
    const tx = new Transaction();
    tx.setSender(spammerAddress);
    tx.setGasBudget(10_000_000);

    const AMOUNT = BigInt(1_000); // 1000 MIST each — symbolic, not real value
    const coins5 = tx.splitCoins(tx.gas, [AMOUNT, AMOUNT, AMOUNT, AMOUNT, AMOUNT]);
    for (let i = 0; i < 5; i++) {
      tx.transferObjects([coins5[i]!], targetAddress);
    }

    const txBytes = await tx.build({ client });
    const sig = await keypair.signTransaction(txBytes);
    const result = await client.executeTransactionBlock({
      transactionBlock: txBytes,
      signature: sig.signature,
      options: { showEffects: true },
    });

    const digest = result.digest;
    const status = result.effects?.status?.status;
    if (status !== "success") throw new Error(`TX failed: ${result.effects?.status?.error}`);

    console.log(ok(`PTB executed — digest: ${C.cyan}${digest}${C.reset}`));
    console.log(`  Explorer: ${dim(`https://suiscan.xyz/devnet/tx/${digest}`)}`);
    return digest;
  } catch (e) {
    console.log(err(`Devnet PTB skipped: ${(e as Error).message}`));
    console.log(`  ${dim("(This is non-fatal — API-level population will still run)")}`);
    return null;
  }
}

// ─── Layer 2: API population ──────────────────────────────────────────────────

interface PopulateResult {
  injected: number;
  quarantined: number;
  txDigest: string | null;
  threats: Array<{
    objectId: string;
    objectType: string;
    verdict: string;
    riskScore: number;
    threatId: number | null;
  }>;
}

async function runPopulateApi(targetAddress: string, txDigest: string | null): Promise<PopulateResult> {
  console.log(hdr("Layer 2 — API population (AI analysis pipeline)"));
  console.log(`  ${dim("Running 5 spam objects through Gemini / mock analysis…")}`);
  console.log(`  ${dim("(Each goes through the chain rate limiter — ~9s each)")}`);

  const start = Date.now();
  const result = await apiFetch<PopulateResult>("/populate-wallet", {
    method: "POST",
    body: JSON.stringify({ targetAddress, txDigest }),
  });
  const elapsed = Date.now() - start;

  for (const t of result.threats) {
    const badge = t.verdict === "MALICIOUS" ? `${C.red}MALICIOUS${C.reset}` :
                  t.verdict === "SUSPICIOUS" ? `${C.yellow}SUSPICIOUS${C.reset}` :
                  `${C.green}SAFE${C.reset}`;
    const stored = t.threatId ? ok(`threat #${t.threatId}`) : dim("not stored (low risk)");
    console.log(`  [${badge}] score=${t.riskScore} ${dim(shortId(t.objectId))}  → ${stored}`);
  }

  console.log(`\n  ${dim(`Elapsed: ${elapsed}ms`)}`);
  console.log(ok(`Injected: ${result.injected}  Quarantined: ${result.quarantined}`));
  return result;
}

// ─── Layer 3: Verification ────────────────────────────────────────────────────

interface Threat {
  id: number;
  objectId: string;
  verdict: string;
  riskScore: number;
  status: string;
}

async function verifyLayer3(result: PopulateResult): Promise<boolean> {
  console.log(hdr("Layer 3 — Verification (API round-trip)"));

  let passed = 0;
  let failed = 0;

  for (const t of result.threats) {
    if (!t.threatId) continue;
    try {
      const fetched = await apiFetch<Threat>(`/threats/${t.threatId}`);
      if (fetched.status === "quarantined" && fetched.verdict === t.verdict) {
        console.log(ok(`Threat #${t.threatId}: status=quarantined, verdict=${t.verdict}`));
        passed++;
      } else {
        console.log(err(`Threat #${t.threatId}: unexpected status=${fetched.status}`));
        failed++;
      }
    } catch (e) {
      console.log(err(`Threat #${t.threatId}: fetch failed — ${(e as Error).message}`));
      failed++;
    }
  }

  if (passed === 0 && failed === 0) {
    console.log(dim("  (No quarantined threats to verify — all may have scored < 65)"));
  }

  return failed === 0;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log(`\n${C.bold}${C.cyan}╔════════════════════════════════════════════╗${C.reset}`);
  console.log(`${C.bold}${C.cyan}║  DeepClean — Wallet Population Script      ║${C.reset}`);
  console.log(`${C.bold}${C.cyan}╚════════════════════════════════════════════╝${C.reset}`);

  if (!TARGET_ADDRESS) {
    console.error(err("--address <sui_wallet_address> is required"));
    console.error(dim("  Example: pnpm run populate --address 0x1234..."));
    process.exit(1);
  }

  console.log(`\n  Target address : ${C.cyan}${TARGET_ADDRESS}${C.reset}`);
  console.log(`  API base       : ${dim(API_BASE)}`);
  console.log(`  Devnet PTB     : ${USE_DEVNET ? C.green + "enabled" : dim("disabled (use --devnet to enable)")}${C.reset}`);

  // Layer 1 — optional real PTB
  let txDigest: string | null = null;
  if (USE_DEVNET) {
    txDigest = await submitDevnetPtb(TARGET_ADDRESS);
  }

  // Layer 2 — API population
  const result = await runPopulateApi(TARGET_ADDRESS, txDigest);

  // Layer 3 — verification
  const layer3ok = await verifyLayer3(result);

  // ── Summary ──────────────────────────────────────────────────────────────────
  console.log(`\n${C.bold}${"─".repeat(50)}${C.reset}`);
  console.log(`  Objects analyzed  : ${result.injected}`);
  console.log(`  Objects quarantined: ${result.quarantined}`);
  if (result.txDigest) {
    console.log(`  Devnet TX digest  : ${C.cyan}${result.txDigest}${C.reset}`);
    console.log(`  Explorer          : ${dim(`https://suiscan.xyz/devnet/tx/${result.txDigest}`)}`);
  }
  console.log(`${C.bold}${"─".repeat(50)}${C.reset}`);

  const allOk = result.quarantined > 0 && layer3ok;
  if (allOk) {
    console.log(`\n${C.green}${C.bold}✅  Population complete — dashboard should now show new threats.${C.reset}\n`);
    process.exit(0);
  } else {
    console.log(`\n${C.red}${C.bold}❌  Population had issues — check output above.${C.reset}\n`);
    process.exit(1);
  }
}

main().catch((e: unknown) => {
  console.error(err(String(e)));
  process.exit(1);
});
