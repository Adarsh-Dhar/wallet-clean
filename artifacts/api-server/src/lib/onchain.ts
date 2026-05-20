/**
 * onchain.ts — On-chain quarantine recorder
 *
 * After the AI engine flags a threat and it is stored in the DB, this module
 * submits a Programmable Transaction Block (PTB) that calls
 * `quarantine_vault::quarantine(...)` on the deployed Move contract, creating
 * an immutable on-chain record of every quarantine action.
 *
 * Required env vars (all optional — if unset, on-chain recording is silently skipped):
 *   QUARANTINE_PACKAGE_ID   — 0x... package ID from `sui client publish`
 *   QUARANTINE_ADMIN_CAP_ID — 0x... object ID of the AdminCap minted at publish time
 *   AGENT_PRIVATE_KEY       — base64 secret key of the deployer keypair (from `sui keytool export`)
 *   SUI_NETWORK             — devnet | testnet | mainnet (default: testnet)
 */

import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Transaction } from "@mysten/sui/transactions";
import { bcs } from "@mysten/sui/bcs";
// In @mysten/sui v2.x, SuiClient is SuiJsonRpcClient and lives in @mysten/sui/jsonRpc
import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from "@mysten/sui/jsonRpc";
import { decodeSuiPrivateKey } from "@mysten/sui/cryptography";
import { logger } from "./logger";

// Re-export the resolved RPC URL so other modules can share the same network lookup.
export function getSuiRpcUrl(): string {
  const network = process.env["SUI_NETWORK"] ?? "testnet";
  const urls: Record<string, string> = {
    mainnet: "https://fullnode.mainnet.sui.io:443",
    testnet: "https://fullnode.testnet.sui.io:443",
    devnet: "https://fullnode.devnet.sui.io:443",
    localnet: "http://127.0.0.1:9000",
  };
  return urls[network] ?? urls["testnet"]!;
}

// NOTE: Do NOT read env vars here — they may not be loaded yet!
// Read them lazily when needed, inside functions.
// Lazily created so the module loads even when env vars are absent
let _client: SuiJsonRpcClient | null = null;
// Narrow string union used by the Sui client API
type NetworkName = "testnet" | "mainnet" | "devnet" | "localnet";

function getClient(): SuiJsonRpcClient {
  if (!_client) {
    const SUI_NETWORK = process.env["SUI_NETWORK"] ?? "testnet";
    const networkName = SUI_NETWORK as NetworkName;
    _client = new SuiJsonRpcClient({
      url: getJsonRpcFullnodeUrl(networkName),
      network: networkName,
    });
  }
  return _client;
}

/**
 * Fetch the Move abilities of a struct from its package.
 * Returns the abilities array (e.g. ["Key", "Store"]) or [] on failure.
 * Used to gate send_to_dead - objects without "Store" cannot be transferred.
 */
export async function fetchObjectAbilities(objectType: string): Promise<string[]> {
  try {
    const parts = objectType.split("::");
    const pkgAddress = parts[0];
    const moduleName = parts[1];
    const structName = parts[2]?.split("<")[0]; // strip generics e.g. Coin<T> -> Coin
    if (!pkgAddress || !moduleName || !structName) return [];

    const client = getClient();
    const modules = await (client as any).getNormalizedMoveModulesByPackage({
      package: pkgAddress,
    });

    const abilities: string[] =
      modules?.[moduleName]?.structs?.[structName]?.abilities?.abilities ?? [];
    return abilities;
  } catch (err) {
    logger.warn({ err, objectType }, "fetchObjectAbilities failed - assuming no store");
    return [];
  }
}

/**
 * Fetch all coin objects of a given coinType owned by walletAddress.
 * Returns the largest coin as primary (to merge into) and the rest as dust.
 * Returns null if fewer than 2 coins exist (nothing to merge).
 */
export async function fetchCoinObjectsForWallet(
  walletAddress: string,
  coinType: string
): Promise<{ primaryCoinId: string; dustCoinIds: string[] } | null> {
  try {
    const client = getClient();
    const response = await client.getCoins({
      owner: walletAddress,
      coinType,
      limit: 50,
    });

    const coins = response.data ?? [];
    if (coins.length < 2) return null; // nothing to merge

    // Sort descending by balance - use the largest as primary
    coins.sort((a, b) => (BigInt(b.balance) > BigInt(a.balance) ? 1 : -1));

    return {
      primaryCoinId: coins[0].coinObjectId,
      dustCoinIds: coins.slice(1).map((c) => c.coinObjectId),
    };
  } catch (err) {
    logger.warn({ err, walletAddress, coinType }, "fetchCoinObjectsForWallet failed");
    return null;
  }
}


/**
 * Extract the inner coin type T from a full Coin<T> object type string.
 * e.g. "0x2::coin::Coin<0xspam::rug_token::MemeCoin>" -> "0xspam::rug_token::MemeCoin"
 * Returns null if the input is not a Coin<T> type.
 */
export function extractCoinType(objectType: string): string | null {
  const match = objectType.match(/::coin::Coin<(.+)>$/);
  return match?.[1] ?? null;
}

export interface OnChainConfigStatus {
  onChainEnabled: boolean;
  missingVars: string[];
  privateKeyParseable: boolean;
}

/**
 * Returns detailed on-chain env validation so callers can surface actionable errors.
 */
export function getOnChainConfigStatus(): OnChainConfigStatus {
  const PACKAGE_ID = process.env["QUARANTINE_PACKAGE_ID"]?.trim();
  const ADMIN_CAP_ID = process.env["QUARANTINE_ADMIN_CAP_ID"]?.trim();
  const AGENT_PRIV_KEY = process.env["AGENT_PRIVATE_KEY"]?.trim();

  const missingVars: string[] = [];
  if (!PACKAGE_ID) missingVars.push("QUARANTINE_PACKAGE_ID");
  if (!ADMIN_CAP_ID) missingVars.push("QUARANTINE_ADMIN_CAP_ID");
  if (!AGENT_PRIV_KEY) missingVars.push("AGENT_PRIVATE_KEY");

  let privateKeyParseable = false;
  if (AGENT_PRIV_KEY) {
    privateKeyParseable = parseAgentPrivateKey(AGENT_PRIV_KEY) !== null;
  }

  const onChainEnabled = missingVars.length === 0 && privateKeyParseable;

  return {
    onChainEnabled,
    missingVars,
    privateKeyParseable,
  };
}

/** True when all three env vars are present and the agent key is parseable. */
export function isOnChainEnabled(): boolean {
  return getOnChainConfigStatus().onChainEnabled;
}

export interface QuarantineOnChainParams {
  objectId: string;       // synthetic or real Sui object ID string
  objectType: string;     // full Move type, e.g. "0xabc::fake_nft::FakeNFT"
  senderAddress: string;  // address that sent the spam
  riskScore: number;      // 0-100
  verdict: string;        // "SAFE" | "SUSPICIOUS" | "MALICIOUS"
  reasonCode: number;     // 1-5
  confidence: number;     // 0.0-1.0
  walrusBlobId: string;   // Walrus blob ID linking to the AI analysis log (empty string if none)
}

function verdictToU8(verdict: string): number {
  if (verdict === "MALICIOUS")  return 2;
  if (verdict === "SUSPICIOUS") return 1;
  return 0;
}

/** Convert a string to a UTF-8 byte array for Move vector<u8> arguments */
function toBytes(s: string): number[] {
  return Array.from(new TextEncoder().encode(s));
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error("Invalid hex string length");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    out[i / 2] = parseInt(clean.slice(i, i + 2), 16);
  }
  return out;
}

function tryBase64Decode(s: string): Uint8Array | null {
  try {
    const buf = Buffer.from(s, "base64");
    return new Uint8Array(buf);
  } catch {
    return null;
  }
}

/**
 * Parse AGENT_PRIVATE_KEY using official @mysten/sui decodeSuiPrivateKey for suiprivkey1... format,
 * with fallbacks for hex/base64.
 */
function parseAgentPrivateKey(raw: string): Uint8Array | null {
  if (!raw) return null;
  const s = raw.trim();

  // suiprivkey1... (official Sui format) — use official SDK decoder
  if (s.startsWith("suiprivkey1")) {
    try {
      const { secretKey } = decodeSuiPrivateKey(s);
      logger.debug("Successfully parsed AGENT_PRIVATE_KEY as suiprivkey1 format");
      return secretKey;
    } catch (e) {
      logger.warn({ err: e }, "Failed to decode suiprivkey1 format");
      return null;
    }
  }

  // Hex (0x or bare)
  if (/^0x[0-9a-fA-F]+$/.test(s) || /^[0-9a-fA-F]+$/.test(s)) {
    try {
      return hexToBytes(s);
    } catch (e) {
      logger.warn({ err: e }, "Failed to parse AGENT_PRIVATE_KEY as hex");
    }
  }

  // Try JSON
  if (s.startsWith("{") || s.startsWith("[")) {
    try {
      const parsed = JSON.parse(s);
      // secretKey as array of numbers
      if (Array.isArray(parsed?.secretKey) && parsed.secretKey.every((n: any) => typeof n === "number")) {
        return new Uint8Array(parsed.secretKey as number[]);
      }
      // some tools export `privateKey` or `secret_key` as base64/hex
      const candidate = parsed?.privateKey ?? parsed?.secret_key ?? parsed?.secretKeyBase64 ?? parsed?.private_key_base64;
      if (typeof candidate === "string") {
        // try base64 then hex
        const b = tryBase64Decode(candidate);
        if (b && (b.length === 32 || b.length === 64)) return b;
        try { return hexToBytes(candidate); } catch {}
      }
      // raw array
      if (Array.isArray(parsed) && parsed.every((n: any) => typeof n === "number")) {
        return new Uint8Array(parsed as number[]);
      }
    } catch (e) {
      logger.debug({ err: e }, "AGENT_PRIVATE_KEY JSON parse failed — not JSON");
    }
  }

  // Comma-separated decimal bytes
  if (/^[0-9]+(,[0-9]+)+$/.test(s)) {
    try {
      const parts = s.split(",").map((p) => Number(p.trim()));
      if (parts.every((n) => Number.isInteger(n) && n >= 0 && n <= 255)) {
        return new Uint8Array(parts);
      }
    } catch (e) {
      logger.debug({ err: e }, "AGENT_PRIVATE_KEY comma list parse failed");
    }
  }

  // Base64 raw
  const base64 = tryBase64Decode(s);
  if (base64 && (base64.length === 32 || base64.length === 64)) return base64;

  // If it's a short hex-like string without 0x but odd length, try to decode and warn
  if (/^[0-9a-fA-F]+$/.test(s)) {
    try { return hexToBytes(s); } catch {}
  }

  logger.warn({ keyStart: s.substring(0, 30) }, "Could not parse AGENT_PRIVATE_KEY in any format");
  return null;
}

/**
 * Submit a PTB to record a quarantine action on-chain.
 *
 * Returns the transaction digest on success, or null if skipped / failed.
 * Never throws — failure is logged but treated as non-fatal so it doesn't
 * block the API response.
 */
export async function quarantineOnChain(
  params: QuarantineOnChainParams
): Promise<string | null> {
  if (!isOnChainEnabled()) {
    logger.debug(
      "On-chain quarantine skipped — QUARANTINE_PACKAGE_ID / QUARANTINE_ADMIN_CAP_ID / AGENT_PRIVATE_KEY not configured"
    );
    return null;
  }

  try {
    // Read env vars lazily
    const AGENT_PRIV_KEY = process.env["AGENT_PRIVATE_KEY"]!;
    const PACKAGE_ID     = process.env["QUARANTINE_PACKAGE_ID"]!;
    const ADMIN_CAP_ID   = process.env["QUARANTINE_ADMIN_CAP_ID"]!;
    const SUI_NETWORK    = process.env["SUI_NETWORK"] ?? "testnet";

    const keyBytes = parseAgentPrivateKey(AGENT_PRIV_KEY);
    if (!keyBytes) {
      logger.error(
        { hint: "AGENT_PRIVATE_KEY accepted formats: 0xhex, hex, base64, JSON{secretKey:[..]}" },
        "AGENT_PRIVATE_KEY is set but could not be parsed"
      );
      return null;
    }

    const keypair = Ed25519Keypair.fromSecretKey(keyBytes);
    const agentAddress = keypair.getPublicKey().toSuiAddress();
    const client      = getClient();

    // Explicitly fetch and select a gas coin
    logger.debug({ address: agentAddress }, "Fetching available gas coins...");
    const coinsResponse = await client.getCoins({
      owner: agentAddress,
      coinType: "0x2::sui::SUI",
      limit: 10,
    });

    if (!coinsResponse.data || coinsResponse.data.length === 0) {
      logger.error(
        { address: agentAddress },
        "No SUI coins available for gas — account may be out of funds"
      );
      return null;
    }

    // Use the first coin with balance > 0
    const gasCoin = coinsResponse.data[0];
    if (!gasCoin.balance || BigInt(gasCoin.balance) < 1_000_000n) {
      logger.warn(
        { coin: gasCoin.coinObjectId, balance: gasCoin.balance },
        "Selected gas coin has very low balance"
      );
    }

    const tx = new Transaction();
    tx.setSender(agentAddress);
    tx.setGasBudget(10_000_000);
    // Explicitly set the gas coin to avoid auto-selection issues
    tx.setGasPayment([{ objectId: gasCoin.coinObjectId, version: gasCoin.version, digest: gasCoin.digest }]);

    // Normalize sender address — must be a full 32-byte 0x-prefixed hex
    const senderAddr = params.senderAddress.startsWith("0x")
      ? params.senderAddress
      : `0x${params.senderAddress}`;

    tx.moveCall({
      target: `${PACKAGE_ID}::quarantine_vault::quarantine`,
      arguments: [
        // _cap: &mut AdminCap — pass the object by mutable reference
        tx.object(ADMIN_CAP_ID!),
        // object_id: vector<u8> — explicitly construct vector<u8>
        tx.pure.vector("u8", toBytes(params.objectId)),
        // object_type: vector<u8> — explicitly construct vector<u8>
        tx.pure.vector("u8", toBytes(params.objectType)),
        // sender_address: address
        tx.pure.address(senderAddr),
        // risk_score: u8
        tx.pure.u8(Math.min(255, Math.max(0, Math.round(params.riskScore)))),
        // verdict: u8  (0=SAFE 1=SUSPICIOUS 2=MALICIOUS)
        tx.pure.u8(verdictToU8(params.verdict)),
        // reason_code: u8
        tx.pure.u8(Math.min(255, Math.max(0, params.reasonCode))),
        // confidence_pct: u8  (0.0-1.0 → 0-100)
        tx.pure.u8(Math.min(100, Math.max(0, Math.round(params.confidence * 100)))),
        // walrus_blob_id: vector<u8> — explicitly construct vector<u8>
        tx.pure.vector("u8", toBytes(params.walrusBlobId)),
      ],
    });

    logger.info({ objectId: params.objectId, network: SUI_NETWORK }, "Recording on-chain quarantine…");

    // Diagnostic logging: dump params and the built transaction to help
    // diagnose ArgumentWithoutValue / missing-argument errors.
    try {
      logger.debug({ params }, "quarantineOnChain input params");
      // Transaction.toJSON() is async in some SDK versions — call defensively
      const txJson = typeof (tx as any).toJSON === "function" ? await (tx as any).toJSON() : (tx as any).serialize?.() ?? null;
      logger.debug({ tx: txJson }, "quarantineOnChain built PTB (serialized)");
    } catch (e) {
      logger.debug({ err: e }, "Failed to serialize PTB for debug output");
    }

    // Sign and submit — this is the real on-chain call
    const result = await client.signAndExecuteTransaction({
      signer:      keypair,
      transaction: tx,
      options: {
        showEffects: true,
      },
    });

    // Log full result for diagnostics (may include CommandArgumentError)
    try {
      logger.debug({ result }, "quarantineOnChain signAndExecuteTransaction result (raw)");
    } catch (e) {
      logger.debug({ err: e }, "Failed to log transaction result");
    }

    const digest = result.digest;

    // Confirm the transaction succeeded on-chain
    const status = result.effects?.status?.status;
    if (status !== "success") {
      const errMsg = result.effects?.status?.error ?? "unknown error";
      logger.warn(
        { digest, objectId: params.objectId, status, errMsg },
        "On-chain quarantine transaction failed"
      );
      return null;
    }

    logger.info(
      { digest, objectId: params.objectId, verdict: params.verdict, network: SUI_NETWORK },
      `On-chain quarantine recorded → digest: ${digest}`
    );

    return digest;
  } catch (err) {
    // Non-fatal — log and continue. The DB record is the source of truth.
    logger.warn({ err, objectId: params.objectId }, "On-chain quarantine failed (non-fatal)");
    return null;
  }
}

export interface SendToDeadParams {
  objectId: string;       // the real on-chain Sui object ID to dispose of
  objectType: string;     // full Move type, e.g. "0xabc::fake_nft::FakeNFT"
}

/**
 * Build and execute a PTB that calls quarantine_vault::send_to_dead<T>
 * on the real spam object, transferring it to 0x0 so it leaves the user's wallet.
 *
 * Works for any object with `key + store` (NFTs, fake tokens, spoofed positions).
 * Does NOT work for objects that lack the `store` ability — those are truly
 * indestructible by a third party and should only have their metadata burned.
 *
 * Returns the tx digest on success, null on failure.
 */
export async function sendToDeadOnChain(
  params: SendToDeadParams
): Promise<string | null> {
  if (!isOnChainEnabled()) return null;

  try {
    // Gate: object must have "Store" ability for public_transfer to work
    const abilities = await fetchObjectAbilities(params.objectType);
    if (!abilities.map((a) => a.toLowerCase()).includes("store")) {
      logger.warn(
        { objectType: params.objectType, abilities },
        "send_to_dead skipped - object lacks 'store' ability and cannot be transferred"
      );
      return null;
    }

    const AGENT_PRIV_KEY = process.env["AGENT_PRIVATE_KEY"]!;
    const PACKAGE_ID     = process.env["QUARANTINE_PACKAGE_ID"]!;
    const ADMIN_CAP_ID   = process.env["QUARANTINE_ADMIN_CAP_ID"]!;

    const keyBytes = parseAgentPrivateKey(AGENT_PRIV_KEY);
    if (!keyBytes) return null;

    const keypair      = Ed25519Keypair.fromSecretKey(keyBytes);
    const agentAddress = keypair.getPublicKey().toSuiAddress();
    const client       = getClient();

    const tx = new Transaction();
    tx.setSender(agentAddress);
    tx.setGasBudget(10_000_000);

    // The spam object must be passed as an owned object input.
    // If the agent wallet does not own it, this tx will fail — that is correct
    // behaviour (you can only dispose of objects you own or that are shared).
    tx.moveCall({
      target: `${PACKAGE_ID}::quarantine_vault::send_to_dead`,
      typeArguments: [params.objectType],
      arguments: [
        tx.object(ADMIN_CAP_ID),
        tx.object(params.objectId),
      ],
    });

    const result = await client.signAndExecuteTransaction({
      signer:      keypair,
      transaction: tx,
      options: { showEffects: true },
    });

    if (result.effects?.status?.status !== "success") {
      logger.warn(
        { objectId: params.objectId, err: result.effects?.status?.error },
        "send_to_dead PTB failed"
      );
      return null;
    }

    logger.info({ digest: result.digest, objectId: params.objectId }, "Object sent to dead address");
    return result.digest;
  } catch (err) {
    logger.warn({ err, objectId: params.objectId }, "sendToDeadOnChain failed (non-fatal)");
    return null;
  }
}


export interface MergeDustParams {
  coinType: string;         // e.g. "0x2::sui::SUI" or the full coin type
  primaryCoinId: string;    // object ID of the primary coin to merge into
  dustCoinIds: string[];    // object IDs of all dust coins to merge and dispose
}

/**
 * Build and execute a PTB that merges all dust coins into a primary coin
 * then sends the combined coin to 0x0, cleaning dust in one transaction.
 *
 * The agent wallet must own all the coins listed. In practice this means
 * you first need a TransferObjects PTB to pull them from the user's wallet
 * to the agent — or the user signs the merge tx themselves via the frontend.
 */
export async function mergeDustOnChain(
  params: MergeDustParams
): Promise<string | null> {
  if (!isOnChainEnabled()) return null;
  if (params.dustCoinIds.length === 0) return null;

  try {
    const AGENT_PRIV_KEY = process.env["AGENT_PRIVATE_KEY"]!;
    const PACKAGE_ID     = process.env["QUARANTINE_PACKAGE_ID"]!;
    const ADMIN_CAP_ID   = process.env["QUARANTINE_ADMIN_CAP_ID"]!;

    const keyBytes = parseAgentPrivateKey(AGENT_PRIV_KEY);
    if (!keyBytes) return null;

    const keypair      = Ed25519Keypair.fromSecretKey(keyBytes);
    const agentAddress = keypair.getPublicKey().toSuiAddress();
    const client       = getClient();

    const tx = new Transaction();
    tx.setSender(agentAddress);
    tx.setGasBudget(15_000_000);

    tx.moveCall({
      target: `${PACKAGE_ID}::quarantine_vault::merge_and_send_dust`,
      typeArguments: [params.coinType],
      arguments: [
        tx.object(ADMIN_CAP_ID),
        tx.object(params.primaryCoinId),
        tx.makeMoveVec({
          type: `0x2::coin::Coin<${params.coinType}>`,
          elements: params.dustCoinIds.map((id) => tx.object(id)),
        }),
      ],
    });

    const result = await client.signAndExecuteTransaction({
      signer:      keypair,
      transaction: tx,
      options: { showEffects: true },
    });

    if (result.effects?.status?.status !== "success") {
      logger.warn({ err: result.effects?.status?.error }, "merge_and_send_dust PTB failed");
      return null;
    }

    logger.info({ digest: result.digest, coinType: params.coinType }, "Dust coins merged and sent to dead address");
    return result.digest;
  } catch (err) {
    logger.warn({ err }, "mergeDustOnChain failed (non-fatal)");
    return null;
  }
}

/**
 * Extract the QuarantinedAsset event ID from a quarantine transaction.
 *
 * After quarantineOnChain succeeds and returns a tx digest, this function
 * queries the blockchain to find the emitted event and extract its ID for
 * better traceability and on-chain linkage.
 *
 * Returns the event ID on success, null on failure or if event not found.
 */
export async function extractQuarantineEventId(
  txDigest: string
): Promise<string | null> {
  if (!isOnChainEnabled()) return null;

  try {
    const client = getClient();
    const tx = await client.getTransactionBlock({
      digest: txDigest,
      options: { showEvents: true },
    });

    const events = tx.events ?? [];
    const quarantineEvent = events.find((event: any) => {
      const type = String(event?.type ?? event?.parsedJson?.type ?? "");
      return type.includes("QuarantinedAsset") || type.includes("quarantine_vault::QuarantinedAsset");
    });

    if (!quarantineEvent) {
      return null;
    }

    const parsed = (quarantineEvent as any).parsedJson ?? quarantineEvent;
    const eventId = parsed?.event_id ?? parsed?.id ?? parsed?.eventId ?? parsed?.object_id ?? null;
    return typeof eventId === "string" ? eventId : null;
  } catch (err) {
    logger.warn({ err, txDigest }, "extractQuarantineEventId failed");
    return null;
  }
}

export interface WalletOwnedObject {
  objectId: string;
  objectType: string;
  displayName: string | null;
  displayUrl: string | null;
  moveAbi: string | null;
}

export interface WalletActivityObject extends WalletOwnedObject {
  stillOwned: boolean;
}

/**
 * Fetch all owned objects for a wallet across every RPC page.
 */
export async function fetchAllWalletObjects(walletAddress: string): Promise<WalletOwnedObject[]> {
  const client = getClient();
  const objects: WalletOwnedObject[] = [];
  let cursor: string | null = null;
  let hasNextPage = true;

  while (hasNextPage) {
    const page = await client.getOwnedObjects({
      owner: walletAddress,
      cursor,
      limit: 50,
      options: {
        showType: true,
        showDisplay: true,
        showContent: false,
      },
    });

    for (const item of page.data ?? []) {
      const obj = item.data as any;
      const objectId = obj?.objectId ?? obj?.object_id;
      const objectType = obj?.type ?? obj?.objectType;
      if (!objectId || !objectType) continue;

      const displayData = obj?.display?.data ?? obj?.display ?? null;
      objects.push({
        objectId,
        objectType,
        displayName: displayData?.name ?? null,
        displayUrl: displayData?.link ?? displayData?.url ?? null,
        moveAbi: null,
      });
    }

    cursor = page.nextCursor ?? null;
    hasNextPage = Boolean(page.hasNextPage && cursor);
  }

  return objects;
}

/**
 * Fetch every object a wallet has received in its transaction history and mark
 * whether each object is still currently owned.
 */
export async function fetchWalletActivityObjects(walletAddress: string): Promise<WalletActivityObject[]> {
  const client = getClient();
  const receivedObjects = new Map<string, string>();
  let cursor: string | null = null;
  let hasNextPage = true;

  while (hasNextPage) {
    const page: any = await (client as any).queryTransactionBlocks({
      filter: { ToAddress: walletAddress },
      options: { showObjectChanges: true, showInput: false, showEffects: false },
      cursor,
      limit: 50,
      order: "descending",
    });

    for (const tx of page.data ?? []) {
      for (const change of tx.objectChanges ?? []) {
        const isReceived =
          change?.type === "created" ||
          (change?.type === "transferred" && change?.recipient === walletAddress);

        if (!isReceived) continue;

        const objectId = change?.objectId;
        const objectType = change?.objectType;
        if (typeof objectId === "string" && typeof objectType === "string" && objectId && objectType) {
          receivedObjects.set(objectId, objectType);
        }
      }
    }

    cursor = page.nextCursor ?? null;
    hasNextPage = Boolean(page.hasNextPage && cursor);
  }

  const ownedNow = await fetchAllWalletObjects(walletAddress);
  const ownedNowIds = new Set(ownedNow.map((object) => object.objectId));

  const activityObjects: WalletActivityObject[] = ownedNow.map((object) => ({
    ...object,
    stillOwned: true,
  }));

  for (const [objectId, objectType] of receivedObjects.entries()) {
    if (ownedNowIds.has(objectId)) continue;

    activityObjects.push({
      objectId,
      objectType,
      displayName: null,
      displayUrl: null,
      moveAbi: null,
      stillOwned: false,
    });
  }

  return activityObjects;
}