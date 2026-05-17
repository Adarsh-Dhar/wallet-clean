#!/usr/bin/env tsx

import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from "@mysten/sui/jsonRpc";

const args = process.argv.slice(2);
function getArg(flag: string): string | undefined {
  const idx = args.indexOf(flag);
  return idx !== -1 ? args[idx + 1] : undefined;
}
function hasFlag(flag: string): boolean { return args.includes(flag); }

import "dotenv/config";

const API_BASE = getArg("--api") ?? process.env["API_BASE"] ?? "http://localhost:8000/api";
const TARGET_ADDRESS = getArg("--address") ?? process.env["TARGET_ADDRESS"];
const SUI_NETWORK = (process.env["SUI_NETWORK"] ?? "devnet") as "devnet" | "testnet" | "testnet" | "mainnet";
const TIMEOUT_MS = 60_000;

if (!TARGET_ADDRESS) {
  console.error("--address or TARGET_ADDRESS env required");
  process.exit(2);
}

async function postPopulate(target: string) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(`${API_BASE}/populate-wallet`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ targetAddress: target }),
      signal: controller.signal,
    });
    const text = await res.text();
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${text}`);
    }
    return JSON.parse(text);
  } finally {
    clearTimeout(timeout);
  }
}

async function getTxStatus(digest: string) {
  const client = new SuiJsonRpcClient({ url: getJsonRpcFullnodeUrl(SUI_NETWORK), network: SUI_NETWORK });
  try {
    // Attempt to fetch the transaction block/effects
    // Different versions expose different helpers — try getTransactionBlock first
    // and fall back to getTransaction if not available.
    // We only need to check for success status.
    // @ts-ignore
    const block = await client.getTransactionBlock({ digest, options: { showEffects: true } });
    // effects path may differ; try to read status
    const status = block?.effects?.status?.status ?? block?.effects?.status ?? block?.status?.status;
    return { ok: status === "success", raw: block };
  } catch (err) {
    return { ok: false, raw: err };
  }
}

async function main() {
  console.log(`Populating target ${TARGET_ADDRESS} via ${API_BASE} (SUI network ${SUI_NETWORK})`);
  const result = await postPopulate(TARGET_ADDRESS);
  console.log("API result:", JSON.stringify(result, null, 2));

  const digest = result?.onChainDigest ?? null;
  if (!digest) {
    console.error("No onChainDigest returned by API. REAL_ONCHAIN may be disabled or transaction failed.");
    process.exit(1);
  }

  console.log(`Found onChainDigest: ${digest}. Checking status on ${SUI_NETWORK}...`);
  const status = await getTxStatus(digest);
  if (status.ok) {
    console.log("Transaction confirmed successful on-chain.");
    process.exit(0);
  }

  console.error("Transaction not confirmed or query failed:", status.raw);
  process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });
