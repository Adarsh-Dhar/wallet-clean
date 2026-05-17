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

const PACKAGE_ID     = process.env["QUARANTINE_PACKAGE_ID"];
const ADMIN_CAP_ID   = process.env["QUARANTINE_ADMIN_CAP_ID"];
const AGENT_PRIV_KEY = process.env["AGENT_PRIVATE_KEY"];
const SUI_NETWORK    = process.env["SUI_NETWORK"] ?? "testnet";
// Narrow string union used by the Sui client API
type NetworkName = "testnet" | "mainnet" | "devnet" | "localnet";

// Lazily created so the module loads even when env vars are absent
let _client: SuiJsonRpcClient | null = null;
function getClient(): SuiJsonRpcClient {
  if (!_client) {
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
  return Boolean(PACKAGE_ID && ADMIN_CAP_ID && AGENT_PRIV_KEY);
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
    const keypair     = Ed25519Keypair.fromSecretKey(AGENT_PRIV_KEY!);
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
      "On-chain quarantine recorded successfully"
    );

    return digest;
  } catch (err) {
    // Non-fatal — log and continue. The DB record is the source of truth.
    logger.warn({ err, objectId: params.objectId }, "On-chain quarantine failed (non-fatal)");
    return null;
  }
}