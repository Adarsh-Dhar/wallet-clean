#!/usr/bin/env tsx
/**
 * seed-onchain-junk.ts
 *
 * Mints real on-chain spam objects from the deployed deepclean_spam package
 * directly into a target wallet using Programmable Transaction Blocks (PTBs).
 *
 * Each junk type is minted in its own PTB so a single failure doesn't block
 * the others. Objects that mint to ctx.sender() are immediately transferred
 * to the target in the same PTB.
 *
 * Usage:
 *   tsx seed-onchain-junk.ts \
 *     --address 0xTARGET_WALLET \
 *     --key suiprivkeyAGENT_PRIVATE_KEY \
 *     --package 0xSPAM_PACKAGE_ID \
 *     [--network testnet|devnet|mainnet] \
 *     [--types airdrop,rug,nft,pool,honeypot]  (default: all)
 *
 * Or set env vars and omit flags:
 *   TARGET_ADDRESS   AGENT_PRIVATE_KEY   SPAM_PACKAGE_ID   SUI_NETWORK
 *
 * The package ID is the deepclean_spam package (deepclean_spam = "0x...").
 * If you published with `sui client publish`, find it in Published.toml.
 */

import "dotenv/config";
import {
  SuiJsonRpcClient,
  getJsonRpcFullnodeUrl,
} from "@mysten/sui/jsonRpc";
import { Transaction } from "@mysten/sui/transactions";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { decodeSuiPrivateKey } from "@mysten/sui/cryptography";

// ─── CLI arg parsing ──────────────────────────────────────────────────────────

const args = process.argv.slice(2);
function getArg(flag: string): string | undefined {
  const idx = args.indexOf(flag);
  return idx !== -1 ? args[idx + 1] : undefined;
}

const TARGET_ADDRESS =
  getArg("--address") ?? process.env["TARGET_ADDRESS"];
const RAW_KEY =
  getArg("--key") ?? process.env["AGENT_PRIVATE_KEY"];
const PACKAGE_ID =
  getArg("--package") ?? process.env["SPAM_PACKAGE_ID"];
const NETWORK = (
  getArg("--network") ?? process.env["SUI_NETWORK"] ?? "testnet"
) as "testnet" | "devnet" | "mainnet" | "localnet";

const TYPES_ARG = getArg("--types");
const REQUESTED_TYPES = TYPES_ARG
  ? new Set(TYPES_ARG.split(",").map((s) => s.trim()))
  : new Set(["airdrop", "rug", "nft", "pool", "honeypot"]);

// ─── Colours ─────────────────────────────────────────────────────────────────

const C = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  cyan: "\x1b[96m",
  green: "\x1b[92m",
  red: "\x1b[91m",
  yellow: "\x1b[93m",
};

// ─── Validation ───────────────────────────────────────────────────────────────

function fatal(msg: string): never {
  console.error(`${C.red}${C.bold}ERROR:${C.reset} ${msg}`);
  console.error(
    `\nUsage:\n  tsx seed-onchain-junk.ts \\\n    --address 0xTARGET \\\n    --key suiprivkey... \\\n    --package 0xSPAM_PKG \\\n    [--network testnet] \\\n    [--types airdrop,rug,nft,pool,honeypot]`
  );
  process.exit(1);
}

if (!TARGET_ADDRESS) fatal("--address (or TARGET_ADDRESS env) is required");
if (!RAW_KEY)         fatal("--key (or AGENT_PRIVATE_KEY env) is required");
if (!PACKAGE_ID)      fatal("--package (or SPAM_PACKAGE_ID env) is required");

// ─── Keypair ──────────────────────────────────────────────────────────────────

function loadKeypair(raw: string): Ed25519Keypair {
  try {
    // Supports both "suiprivkey..." bech32 format and raw base64
    const decoded = decodeSuiPrivateKey(raw);
    return Ed25519Keypair.fromSecretKey(decoded.secretKey);
  } catch {
    // Fall back to raw 32-byte base64
    const bytes = Uint8Array.from(Buffer.from(raw, "base64"));
    return Ed25519Keypair.fromSecretKey(bytes.slice(0, 32));
  }
}

const keypair = loadKeypair(RAW_KEY!);
const agentAddress = keypair.toSuiAddress();

// ─── Sui client ───────────────────────────────────────────────────────────────

const client = new SuiJsonRpcClient({
  url: getJsonRpcFullnodeUrl(NETWORK),
  network: NETWORK,
});

// ─── PTB helpers ─────────────────────────────────────────────────────────────

/**
 * Sign, execute, and wait for a PTB.
 * Returns the transaction digest on success.
 */
async function executeAndWait(tx: Transaction): Promise<string> {
  const result = await client.signAndExecuteTransaction({
    signer: keypair,
    transaction: tx,
    options: { showEffects: true, showObjectChanges: true },
  });

  const status = result.effects?.status?.status;
  if (status !== "success") {
    const err = result.effects?.status?.error ?? "unknown error";
    throw new Error(`Transaction failed: ${err}`);
  }

  // Wait for finality
  await client.waitForTransaction({ digest: result.digest });
  return result.digest;
}

// ─── Junk minters ────────────────────────────────────────────────────────────

/**
 * malicious_airdrop::mint(ctx) → AirdropToken → transfer to target
 *
 * Move signature: public fun mint(ctx: &mut TxContext)
 * Mints to ctx.sender(), so we transfer in the same PTB.
 */
async function mintAirdropToken(target: string): Promise<string> {
  const tx = new Transaction();

  // Call mint — result is the AirdropToken owned by the tx sender
  const [token] = tx.moveCall({
    target: `${PACKAGE_ID}::malicious_airdrop::mint`,
    arguments: [],
  });

  // Transfer immediately to target wallet
  tx.transferObjects([token], tx.pure.address(target));

  return executeAndWait(tx);
}

/**
 * rug_token::airdrop_to(recipient, ctx) → MemeCoin sent directly to target
 *
 * Move signature: public fun airdrop_to(recipient: address, ctx: &mut TxContext)
 * This one already accepts a recipient — no extra transfer needed.
 */
async function mintRugToken(target: string): Promise<string> {
  const tx = new Transaction();

  tx.moveCall({
    target: `${PACKAGE_ID}::rug_token::airdrop_to`,
    arguments: [tx.pure.address(target)],
  });

  return executeAndWait(tx);
}

/**
 * fake_foundation_nft::mint(ctx) → FounderPass → transfer to target
 *
 * Move signature: public fun mint(ctx: &mut TxContext)
 */
async function mintFakeFoundationNft(target: string): Promise<string> {
  const tx = new Transaction();

  const [nft] = tx.moveCall({
    target: `${PACKAGE_ID}::fake_foundation_nft::mint`,
    arguments: [],
  });

  tx.transferObjects([nft], tx.pure.address(target));

  return executeAndWait(tx);
}

/**
 * pool::fake_mint(ctx) → Position → transfer to target
 *
 * Move signature: public fun fake_mint(ctx: &mut TxContext)
 */
async function mintSpoofedPool(target: string): Promise<string> {
  const tx = new Transaction();

  const [position] = tx.moveCall({
    target: `${PACKAGE_ID}::pool::fake_mint`,
    arguments: [],
  });

  tx.transferObjects([position], tx.pure.address(target));

  return executeAndWait(tx);
}

/**
 * honeypot_defi::stake_and_receive(ctx) → HoneypotToken → transfer to target
 *
 * Move signature: public fun stake_and_receive(ctx: &mut TxContext)
 */
async function mintHoneypotToken(target: string): Promise<string> {
  const tx = new Transaction();

  const [token] = tx.moveCall({
    target: `${PACKAGE_ID}::honeypot_defi::stake_and_receive`,
    arguments: [],
  });

  tx.transferObjects([token], tx.pure.address(target));

  return executeAndWait(tx);
}

// ─── Job table ────────────────────────────────────────────────────────────────

interface JunkJob {
  key:   string;
  label: string;
  fn:    (target: string) => Promise<string>;
}

const ALL_JOBS: JunkJob[] = [
  {
    key:   "airdrop",
    label: "Fake SUI Airdrop Token    (malicious_airdrop::AirdropToken)",
    fn:    mintAirdropToken,
  },
  {
    key:   "rug",
    label: "Rug Meme Coin             (rug_token::MemeCoin)",
    fn:    mintRugToken,
  },
  {
    key:   "nft",
    label: "Fake Foundation NFT       (fake_foundation_nft::FounderPass)",
    fn:    mintFakeFoundationNft,
  },
  {
    key:   "pool",
    label: "Spoofed Cetus LP Position (pool::Position)",
    fn:    mintSpoofedPool,
  },
  {
    key:   "honeypot",
    label: "Honeypot DeFi Token       (honeypot_defi::HoneypotToken)",
    fn:    mintHoneypotToken,
  },
];

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  console.log(
    `\n${C.bold}${C.cyan}╔══════════════════════════════════════════════════════════╗${C.reset}`
  );
  console.log(
    `${C.bold}${C.cyan}║   DeepClean — On-Chain Junk Seeder                      ║${C.reset}`
  );
  console.log(
    `${C.bold}${C.cyan}╚══════════════════════════════════════════════════════════╝${C.reset}\n`
  );

  console.log(`  Network       : ${C.cyan}${NETWORK}${C.reset}`);
  console.log(`  Spam package  : ${C.dim}${PACKAGE_ID}${C.reset}`);
  console.log(`  Agent address : ${C.dim}${agentAddress}${C.reset}`);
  console.log(`  Target wallet : ${C.cyan}${TARGET_ADDRESS}${C.reset}`);
  console.log(`  Types         : ${C.dim}${[...REQUESTED_TYPES].join(", ")}${C.reset}\n`);

  const jobs = ALL_JOBS.filter((j) => REQUESTED_TYPES.has(j.key));
  if (jobs.length === 0) {
    fatal(`No valid types in --types. Valid: airdrop, rug, nft, pool, honeypot`);
  }

  // Check agent has gas before starting
  try {
    const coins = await client.getCoins({ owner: agentAddress, coinType: "0x2::sui::SUI" });
    const total = coins.data.reduce((sum, c) => sum + BigInt(c.balance), 0n);
    if (total === 0n) {
      console.warn(
        `${C.yellow}⚠  Agent wallet has 0 SUI. Transactions will fail.${C.reset}`
      );
      console.warn(
        `   Run: sui client faucet  (on testnet/devnet)\n`
      );
    } else {
      const sui = Number(total) / 1e9;
      console.log(
        `  Agent gas     : ${C.green}${sui.toFixed(4)} SUI${C.reset}\n`
      );
    }
  } catch {
    console.warn(`${C.yellow}⚠  Could not check agent gas balance${C.reset}\n`);
  }

  let succeeded = 0;
  let failed = 0;
  const results: { label: string; digest?: string; error?: string }[] = [];

  for (let i = 0; i < jobs.length; i++) {
    const job = jobs[i]!;
    const prefix = `  [${i + 1}/${jobs.length}] ${job.label}`;
    process.stdout.write(`${prefix}  …`);

    try {
      const digest = await job.fn(TARGET_ADDRESS!);
      process.stdout.write(`\r${prefix}  ${C.green}✅ OK${C.reset}\n`);
      console.log(`         digest: ${C.dim}${digest}${C.reset}`);
      results.push({ label: job.label, digest });
      succeeded++;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      process.stdout.write(`\r${prefix}  ${C.red}❌ FAIL${C.reset}\n`);
      console.log(`         error : ${C.red}${msg}${C.reset}`);
      results.push({ label: job.label, error: msg });
      failed++;
    }
  }

  // ── Summary ──────────────────────────────────────────────────────────────

  console.log(
    `\n${C.bold}── Summary ──────────────────────────────────────────────${C.reset}`
  );
  console.log(`  Seeded : ${C.green}${succeeded}${C.reset} object(s)`);
  if (failed > 0)
    console.log(`  Failed : ${C.red}${failed}${C.reset} object(s)`);

  console.log(
    `\n  The following objects are now in target wallet ${C.cyan}${TARGET_ADDRESS}${C.reset}:`
  );
  for (const r of results) {
    if (r.digest) {
      const explorer = `https://suiscan.xyz/${NETWORK}/tx/${r.digest}`;
      console.log(`  ${C.green}✅${C.reset}  ${r.label}`);
      console.log(`       🔗 ${C.dim}${explorer}${C.reset}`);
    } else {
      console.log(`  ${C.red}❌${C.reset}  ${r.label}`);
    }
  }

  if (succeeded > 0) {
    console.log(
      `\n${C.green}${C.bold}Done! Now click Populate in the DeepClean dashboard — it will fetch these real objects, run AI analysis on them, and quarantine the threats.${C.reset}\n`
    );
  } else {
    console.log(
      `\n${C.red}${C.bold}All mints failed. Check your AGENT_PRIVATE_KEY, SPAM_PACKAGE_ID, and gas balance.${C.reset}\n`
    );
    process.exit(1);
  }
}

main().catch((e) => {
  console.error(`${C.red}${e instanceof Error ? e.message : String(e)}${C.reset}`);
  process.exit(1);
});