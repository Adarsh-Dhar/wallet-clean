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
// In @mysten/sui v2.x, SuiClient is SuiJsonRpcClient and lives in @mysten/sui/jsonRpc
import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from "@mysten/sui/jsonRpc";
import { logger } from "./logger";

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

/** True when all three env vars are present — used to gate calls at the call site */
export function isOnChainEnabled(): boolean {
  // Read env vars lazily (after dotenv.config() has run)
  const PACKAGE_ID     = process.env["QUARANTINE_PACKAGE_ID"];
  const ADMIN_CAP_ID   = process.env["QUARANTINE_ADMIN_CAP_ID"];
  const AGENT_PRIV_KEY = process.env["AGENT_PRIVATE_KEY"];

  // Ensure required env vars are present and the agent key is parseable
  if (!PACKAGE_ID || !ADMIN_CAP_ID || !AGENT_PRIV_KEY) return false;
  try {
    const parsed = parseAgentPrivateKey(AGENT_PRIV_KEY);
    return parsed !== null;
  } catch (e) {
    return false;
  }
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

/** Decode Bech32 format (used by suiprivkey1...) */
function decodeBech32(encoded: string): Uint8Array | null {
  if (!encoded.match(/^[a-z0-9]{6,}1[ac-hj-np-z02-9]{58,}$/i)) {
    return null;
  }
  
  const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  const decoded = encoded.toLowerCase();
  const lastOne = decoded.lastIndexOf("1");
  
  if (lastOne < 1 || lastOne + 7 > decoded.length || decoded.length > 90) {
    return null;
  }
  
  const hrp = decoded.substring(0, lastOne);
  const data = decoded.substring(lastOne + 1);
  
  // Decode data part
  const decodedData: number[] = [];
  for (const char of data) {
    const d = CHARSET.indexOf(char);
    if (d < 0) return null;
    decodedData.push(d);
  }
  
  // Extract the key bytes (skip checksum: last 6 characters = 30 bits)
  const keyLengthInBits = (decodedData.length - 6) * 5;
  const keyLengthInBytes = Math.floor(keyLengthInBits / 8);
  
  const result: number[] = [];
  let accumulator = 0;
  let bits = 0;
  
  for (let i = 0; i < decodedData.length - 6; i++) {
    accumulator = (accumulator << 5) | decodedData[i];
    bits += 5;
    
    if (bits >= 8) {
      bits -= 8;
      result.push((accumulator >> bits) & 0xff);
    }
  }
  
  return result.length >= 32 ? new Uint8Array(result.slice(0, 32)) : null;
}

/**
 * Parse various AGENT_PRIVATE_KEY formats into a Uint8Array secret key.
 * Supported formats:
 *  - suiprivkey1... (Bech32 encoded Sui private key)
 *  - 0x-prefixed hex string
 *  - raw hex string
 *  - base64 encoded bytes
 *  - JSON blob exported by some key tools (object with `secretKey` array or string)
 *  - comma-separated decimal byte list
 */
function parseAgentPrivateKey(raw: string): Uint8Array | null {
  if (!raw) return null;
  const s = raw.trim();

  // suiprivkey1... (Bech32 format)
  if (s.startsWith("suiprivkey1")) {
    const decoded = decodeBech32(s);
    if (decoded && decoded.length >= 32) {
      logger.debug("Successfully parsed AGENT_PRIVATE_KEY as suiprivkey1 format");
      return decoded;
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

    const tx = new Transaction();
    tx.setSender(agentAddress);
    tx.setGasBudget(10_000_000);

    // Normalize sender address — must be a full 32-byte 0x-prefixed hex
    const senderAddr = params.senderAddress.startsWith("0x")
      ? params.senderAddress
      : `0x${params.senderAddress}`;

    tx.moveCall({
      target: `${PACKAGE_ID}::quarantine_vault::quarantine`,
      arguments: [
        // _cap: &AdminCap — pass the object by reference
        tx.object(ADMIN_CAP_ID!),
        // object_id: vector<u8>
        tx.pure.vector("u8", toBytes(params.objectId)),
        // object_type: vector<u8>
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
        // walrus_blob_id: vector<u8>
        tx.pure.vector("u8", toBytes(params.walrusBlobId)),
      ],
    });

    logger.info({ objectId: params.objectId, network: SUI_NETWORK }, "Recording on-chain quarantine…");

    // Sign and submit — this is the real on-chain call
    const result = await client.signAndExecuteTransaction({
      signer:      keypair,
      transaction: tx,
      options: {
        showEffects: true,
      },
    });

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