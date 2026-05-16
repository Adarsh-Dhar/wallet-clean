import { logger } from "./logger";

// Walrus testnet endpoints
const WALRUS_PUBLISHER = "https://publisher.walrus-testnet.walrus.space";
const WALRUS_AGGREGATOR = "https://aggregator.walrus-testnet.walrus.space";

export interface WalrusBlob {
  blobId: string;
  endEpoch: number;
  suiObjectId?: string;
}

export interface ThreatAnalysisLog {
  schemaVersion: 1;
  timestamp: string;
  objectId: string;
  objectType: string;
  senderAddress: string;
  displayName: string | null;
  displayUrl: string | null;
  verdict: string;
  riskScore: number;
  reasonCode: number;
  confidence: number;
  flags: string[];
  reasoning: string;
  agentVersion: string;
}

/**
 * Store a threat analysis log as a Walrus blob.
 * Returns the blobId for on-chain verification.
 * Does not throw — failure is logged but non-fatal.
 */
export async function storeThreatLog(log: ThreatAnalysisLog): Promise<string | null> {
  try {
    const payload = JSON.stringify(log);
    const url = `${WALRUS_PUBLISHER}/v1/blobs?epochs=5`;

    const response = await fetch(url, {
      method: "PUT",
      headers: { "Content-Type": "application/octet-stream" },
      body: payload,
      signal: AbortSignal.timeout(10_000),
    });

    if (!response.ok) {
      const text = await response.text().catch(() => "(unreadable)");
      logger.warn({ status: response.status, body: text }, "Walrus publish failed");
      return null;
    }

    const data = (await response.json()) as {
      newlyCreated?: { blobObject?: { blobId?: string } };
      alreadyCertified?: { blobId?: string };
    };

    const blobId =
      data.newlyCreated?.blobObject?.blobId ??
      data.alreadyCertified?.blobId ??
      null;

    if (blobId) {
      logger.info({ blobId }, "Threat log stored on Walrus");
    }

    return blobId;
  } catch (err) {
    logger.warn({ err }, "Walrus storage skipped (network or timeout)");
    return null;
  }
}

/**
 * Retrieve and verify a blob from Walrus by ID.
 * Returns parsed JSON or null on failure.
 */
export async function retrieveThreatLog(blobId: string): Promise<ThreatAnalysisLog | null> {
  try {
    const url = `${WALRUS_AGGREGATOR}/v1/blobs/${blobId}`;
    const response = await fetch(url, {
      signal: AbortSignal.timeout(10_000),
    });

    if (!response.ok) {
      logger.warn({ blobId, status: response.status }, "Walrus retrieve failed");
      return null;
    }

    const text = await response.text();
    return JSON.parse(text) as ThreatAnalysisLog;
  } catch (err) {
    logger.warn({ err, blobId }, "Walrus retrieve failed");
    return null;
  }
}

export function buildThreatLog(params: {
  objectId: string;
  objectType: string;
  senderAddress: string;
  displayName: string | null | undefined;
  displayUrl: string | null | undefined;
  verdict: string;
  riskScore: number;
  reasonCode: number;
  confidence: number;
  flags: string[];
  reasoning: string;
}): ThreatAnalysisLog {
  return {
    schemaVersion: 1,
    timestamp: new Date().toISOString(),
    objectId: params.objectId,
    objectType: params.objectType,
    senderAddress: params.senderAddress,
    displayName: params.displayName ?? null,
    displayUrl: params.displayUrl ?? null,
    verdict: params.verdict,
    riskScore: params.riskScore,
    reasonCode: params.reasonCode,
    confidence: params.confidence,
    flags: params.flags,
    reasoning: params.reasoning,
    agentVersion: "1.0.0",
  };
}
